// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/alerts"
	"github.com/bhager42/teslachargingmonitor/internal/notify/smtpmock"
	"github.com/bhager42/teslachargingmonitor/internal/poller"
	"github.com/bhager42/teslachargingmonitor/internal/secrets"
	"github.com/bhager42/teslachargingmonitor/internal/store"
	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
	"github.com/bhager42/teslachargingmonitor/internal/wcsim"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	st     *store.Store
	dbPath string
	d      *Dispatcher
	clk    *clock
	logs   *bytes.Buffer
	smtp   *smtpmock.Server
}

func newEnv(t *testing.T, o smtpmock.Options) *env {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "tcmon.db")
	st, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	key, err := secrets.LoadOrCreateKey(filepath.Join(dir, "secret.key"), nil)
	if err != nil {
		t.Fatal(err)
	}
	box, _ := secrets.NewBox(key)
	s := mock(t, o)
	clk := &clock{t: t0}
	logs := &bytes.Buffer{}
	d := New(st, box, Config{Now: clk.now, Location: time.UTC, RootCAs: s.RootCAs, SendTimeout: 5 * time.Second,
		Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	return &env{st: st, dbPath: dbPath, d: d, clk: clk, logs: logs, smtp: s}
}

func (e *env) addChannel(t *testing.T, mut func(*EmailSettings)) ChannelInfo {
	t.Helper()
	s := EmailSettings{Name: "Gmail", Enabled: true, MinSeverity: alerts.Info, Email: cfgFor(e.smtp, SecurityStartTLS),
		Password: pass}
	if mut != nil {
		mut(&s)
	}
	ci, err := e.d.CreateEmailChannel(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	return ci
}

func note(rule string, sev alerts.Severity, id int64) alerts.Notification {
	return alerts.Notification{EventID: id, RuleKey: rule, RuleTitle: rule, DeviceID: 1, DeviceName: "Garage",
		Kind: alerts.KindFiring, Severity: sev, Message: rule + " message", At: t0}
}

func TestPasswordNeverStoredOrShownInPlaintext(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, smtpmock.Options{})
	ci := e.addChannel(t, nil)
	if !ci.PasswordSet || ci.Email.Username != user {
		t.Fatalf("info = %+v", ci)
	}
	js, _ := json.Marshal(ci)
	if strings.Contains(string(js), pass) || strings.Contains(fmt.Sprintf("%+v", ci), pass) {
		t.Error("password in ChannelInfo")
	}
	// Send something so the logs have content, then check every artifact.
	_ = e.d.Enqueue(ctx, []alerts.Notification{note("overcurrent", alerts.Critical, 1)})
	_ = e.d.DeliverDue(ctx)
	if err := e.d.Test(ctx, ci.ID); err != nil {
		t.Fatal(err)
	}
	_ = e.st.Close() // flush WAL into the main file
	var files []string
	for _, suffix := range []string{"", "-wal", "-shm"} {
		files = append(files, e.dbPath+suffix)
	}
	for _, f := range files {
		b, err := os.ReadFile(f) //nolint:gosec // test temp file
		if err == nil && bytes.Contains(b, []byte(pass)) {
			t.Errorf("password found in plaintext in %s", filepath.Base(f))
		}
	}
	if strings.Contains(e.logs.String(), pass) {
		t.Error("password found in logs")
	}
	if len(e.smtp.Messages()) != 2 {
		t.Errorf("messages = %d", len(e.smtp.Messages()))
	}
}

func TestEnqueueBatchesAndFilters(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, smtpmock.Options{})
	all := e.addChannel(t, nil)
	critOnly := e.addChannel(t, func(s *EmailSettings) {
		s.Name, s.MinSeverity, s.Email.To = "Critical only", alerts.Critical, []string{"pager@example.com"}
	})
	e.addChannel(t, func(s *EmailSettings) { s.Name, s.Enabled = "Disabled", false })
	quiet := e.addChannel(t, func(s *EmailSettings) {
		s.Name, s.QuietHours, s.Email.To = "Quiet at night", "17:00-07:00", []string{"night@example.com"}
	})

	batch := []alerts.Notification{note("handle_temp_high", alerts.Warning, 1), note("overcurrent", alerts.Critical, 2),
		note("wifi_weak", alerts.Info, 3)}
	if err := e.d.Enqueue(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if err := e.d.DeliverDue(ctx); err != nil {
		t.Fatal(err)
	}
	byRcpt := map[string]string{}
	for _, m := range e.smtp.Messages() {
		byRcpt[m.To[0]] = string(m.Data)
	}
	if len(byRcpt) != 3 {
		t.Fatalf("emails to %v, want 3 (disabled channel skipped)", byRcpt)
	}
	// One email per channel per batch, with all three items.
	allMail := byRcpt["me@example.com"]
	for _, s := range []string{"handle_temp_high message", "overcurrent message", "wifi_weak message"} {
		if !strings.Contains(allMail, s) {
			t.Errorf("batched email missing %q", s)
		}
	}
	if m := byRcpt["pager@example.com"]; !strings.Contains(m, "overcurrent message") || strings.Contains(m, "wifi_weak message") {
		t.Error("critical-only channel received non-critical items")
	}
	// 18:00 UTC is inside 17:00-07:00: only the critical item gets through.
	if m := byRcpt["night@example.com"]; !strings.Contains(m, "overcurrent message") || strings.Contains(m, "handle_temp_high message") {
		t.Error("quiet hours not applied")
	}
	log, _ := e.st.Deliveries(ctx, all.ID, 10)
	if len(log) != 1 || log[0].Status != store.DeliverySent || len(log[0].EventIDs) != 3 || log[0].Attempts != 1 {
		t.Errorf("delivery log = %+v", log)
	}
	if ci, _ := e.d.Channel(ctx, critOnly.ID); ci.LastSuccess == nil || ci.ConsecutiveFailures != 0 {
		t.Errorf("channel health = %+v", ci)
	}
	_ = quiet
}

func TestDigestGoesOnlyToOptedInChannels(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, smtpmock.Options{})
	e.addChannel(t, nil) // alerts only
	digest := e.addChannel(t, func(s *EmailSettings) {
		s.Name, s.Digest, s.Email.To = "Digest", true, []string{"digest@example.com"}
		// The digest ignores quiet hours and the severity filter.
		s.MinSeverity, s.QuietHours = alerts.Critical, "00:00-23:59"
	})
	e.addChannel(t, func(s *EmailSettings) { s.Name, s.Digest, s.Enabled = "Off", true, false })
	if ci, _ := e.d.Channel(ctx, digest.ID); !ci.Digest {
		t.Fatal("Digest flag not stored")
	}
	msg := Message{Subject: "Weekly summary", Text: "weekly text\n", HTML: "<p>weekly html</p>", Severity: alerts.Info}
	n, err := e.d.EnqueueDigest(ctx, msg)
	if err != nil || n != 1 {
		t.Fatalf("EnqueueDigest = %d, %v", n, err)
	}
	if err := e.d.DeliverDue(ctx); err != nil {
		t.Fatal(err)
	}
	ms := e.smtp.Messages()
	if len(ms) != 1 || ms[0].To[0] != "digest@example.com" || !strings.Contains(string(ms[0].Data), "weekly text") {
		t.Fatalf("messages = %+v", ms)
	}
	// SendNow (the "send digest now" button) is immediate and unqueued.
	if err := e.d.SendNow(ctx, digest.ID, msg); err != nil || len(e.smtp.Messages()) != 2 {
		t.Fatalf("SendNow = %v, %d messages", err, len(e.smtp.Messages()))
	}
	// Turning it off on update.
	if _, err := e.d.UpdateEmailChannel(ctx, digest.ID, EmailSettings{Name: "Digest", Enabled: true,
		MinSeverity: alerts.Info, Email: cfgFor(e.smtp, SecurityStartTLS)}); err != nil {
		t.Fatal(err)
	}
	if n, err := e.d.EnqueueDigest(ctx, msg); err != nil || n != 0 {
		t.Errorf("after opting out: %d, %v", n, err)
	}
}

func TestRetryThenSuccess(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, smtpmock.Options{TempFail: 2})
	ci := e.addChannel(t, nil)
	_ = e.d.Enqueue(ctx, []alerts.Notification{note("overcurrent", alerts.Critical, 1)})

	_ = e.d.DeliverDue(ctx) // attempt 1: 421
	ds, _ := e.st.Deliveries(ctx, ci.ID, 1)
	if ds[0].Status != store.DeliveryPending || ds[0].Attempts != 1 || !ds[0].NextAttempt.Equal(t0.Add(time.Minute)) ||
		!strings.Contains(ds[0].LastError, "temporarily unavailable") {
		t.Fatalf("after attempt 1: %+v", ds[0])
	}
	_ = e.d.DeliverDue(ctx) // not due yet
	if ds, _ := e.st.Deliveries(ctx, ci.ID, 1); ds[0].Attempts != 1 {
		t.Error("retried before backoff elapsed")
	}
	e.clk.add(time.Minute)
	_ = e.d.DeliverDue(ctx) // attempt 2: 421 again, next in 5 min
	e.clk.add(5 * time.Minute)
	_ = e.d.DeliverDue(ctx) // attempt 3: success
	ds, _ = e.st.Deliveries(ctx, ci.ID, 1)
	if ds[0].Status != store.DeliverySent || ds[0].Attempts != 3 || len(e.smtp.Messages()) != 1 {
		t.Errorf("final = %+v, messages=%d", ds[0], len(e.smtp.Messages()))
	}
	info, _ := e.d.Channel(ctx, ci.ID)
	if info.ConsecutiveFailures != 0 || info.LastError == "" {
		t.Errorf("health = %+v", info)
	}
}

func TestPermanentFailureAndGiveUp(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, smtpmock.Options{})
	bad := e.addChannel(t, func(s *EmailSettings) { s.Password = "wrong" })
	_ = e.d.Enqueue(ctx, []alerts.Notification{note("overcurrent", alerts.Critical, 1)})
	_ = e.d.DeliverDue(ctx)
	ds, _ := e.st.Deliveries(ctx, bad.ID, 1)
	if ds[0].Status != store.DeliveryFailed || ds[0].Attempts != 1 || !strings.Contains(ds[0].LastError, "app password") {
		t.Errorf("auth failure = %+v", ds[0])
	}

	// Transient failures give up after 24 h.
	e2 := newEnv(t, smtpmock.Options{TempFail: 1000})
	ci := e2.addChannel(t, nil)
	_ = e2.d.Enqueue(ctx, []alerts.Notification{note("overcurrent", alerts.Critical, 1)})
	for range 40 {
		_ = e2.d.DeliverDue(ctx)
		e2.clk.add(time.Hour)
	}
	ds, _ = e2.st.Deliveries(ctx, ci.ID, 1)
	if ds[0].Status != store.DeliveryFailed || ds[0].Attempts < 20 {
		t.Errorf("give up = %+v", ds[0])
	}
	if info, _ := e2.d.Channel(ctx, ci.ID); info.ConsecutiveFailures < 20 {
		t.Errorf("failures = %d", info.ConsecutiveFailures)
	}
}

func TestChannelCRUD(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, smtpmock.Options{})
	ci := e.addChannel(t, nil)

	upd := EmailSettings{Name: "Gmail (renamed)", Enabled: true, MinSeverity: alerts.Warning,
		Email: cfgFor(e.smtp, SecurityStartTLS), QuietHours: "22:00-07:00"}
	got, err := e.d.UpdateEmailChannel(ctx, ci.ID, upd) // empty password: keep
	if err != nil || got.Name != "Gmail (renamed)" || got.MinSeverity != alerts.Warning || !got.PasswordSet {
		t.Fatalf("update = %+v, %v", got, err)
	}
	if err := e.d.Test(ctx, ci.ID); err != nil {
		t.Fatalf("password not kept: %v", Describe(err))
	}
	upd.Password = "wrong"
	_, _ = e.d.UpdateEmailChannel(ctx, ci.ID, upd)
	if err := e.d.Test(ctx, ci.ID); err == nil {
		t.Error("new password not applied")
	}
	for i, bad := range []EmailSettings{
		{Name: "", MinSeverity: alerts.Info, Email: cfgFor(e.smtp, SecurityStartTLS)},
		{Name: "x", MinSeverity: alerts.None, Email: cfgFor(e.smtp, SecurityStartTLS)},
		{Name: "x", MinSeverity: alerts.Info, QuietHours: "nope", Email: cfgFor(e.smtp, SecurityStartTLS)},
		{Name: "x", MinSeverity: alerts.Info, Email: EmailConfig{}},
		{Name: "x", MinSeverity: alerts.Info, Email: cfgFor(e.smtp, SecurityStartTLS)}, // username without password
	} {
		if _, err := e.d.CreateEmailChannel(ctx, bad); err == nil {
			t.Errorf("bad settings %d accepted", i)
		}
	}
	list, _ := e.d.Channels(ctx)
	if len(list) != 1 {
		t.Errorf("channels = %d", len(list))
	}
	if err := e.d.DeleteChannel(ctx, ci.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.d.Channel(ctx, ci.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after delete: %v", err)
	}
}

func TestWrongKeyCannotDecrypt(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, smtpmock.Options{})
	ci := e.addChannel(t, nil)
	otherBox, _ := secrets.NewBox(bytes.Repeat([]byte{9}, secrets.KeySize))
	d2 := New(e.st, otherBox, Config{RootCAs: e.smtp.RootCAs})
	if err := d2.Test(ctx, ci.ID); !errors.Is(err, secrets.ErrDecrypt) {
		t.Errorf("err = %v, want ErrDecrypt", err)
	}
	if info, _ := d2.Channel(ctx, ci.ID); info.PasswordSet {
		t.Error("PasswordSet with wrong key")
	}
}

func TestNoChannelLogsWarning(t *testing.T) {
	e := newEnv(t, smtpmock.Options{})
	_ = e.d.Enqueue(context.Background(), []alerts.Notification{note("overcurrent", alerts.Critical, 1)})
	if !strings.Contains(e.logs.String(), "no notification channel configured") {
		t.Error("missing warning")
	}
}

// Acceptance (plan Phase 4): an alert raised by the simulator arrives as
// one batched email.
func TestSimulatorAlertArrivesAsOneEmail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "tcmon.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	sim, _ := wcsim.NewServer(wcsim.Options{Scenario: "grid-low-voltage"})
	ts := httptest.NewServer(sim)
	defer ts.Close()
	if _, err := st.CreateDevice(ctx, store.NewDevice("Garage", ts.URL), time.Now()); err != nil {
		t.Fatal(err)
	}
	smtp := mock(t, smtpmock.Options{})
	key, _ := secrets.LoadOrCreateKey(filepath.Join(dir, "secret.key"), nil)
	box, _ := secrets.NewBox(key)
	d := New(st, box, Config{RootCAs: smtp.RootCAs, SendTimeout: 5 * time.Second})
	if _, err := d.CreateEmailChannel(ctx, EmailSettings{Name: "Gmail", Enabled: true, MinSeverity: alerts.Info,
		Email: cfgFor(smtp, SecurityStartTLS), Password: pass}); err != nil {
		t.Fatal(err)
	}

	m := poller.New(st, poller.Config{IntervalOverride: time.Hour, SyncEvery: time.Hour,
		Client: wallconnector.Options{Timeout: time.Second}})
	updates, unsub := m.Subscribe(8)
	defer unsub()
	eng := alerts.New(st, nil)
	_ = eng.Load(ctx)
	batches, unsubB := eng.Subscribe(8)
	defer unsubB()
	go func() { _ = m.Run(ctx) }()
	go eng.Run(ctx, updates)
	go d.Run(ctx, batches)

	deadline := time.Now().Add(15 * time.Second)
	for len(smtp.Messages()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no email received")
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	msgs := smtp.Messages()
	if len(msgs) != 1 {
		t.Fatalf("received %d emails, want 1 batched email", len(msgs))
	}
	body := string(msgs[0].Data)
	for _, want := range []string{"Grid voltage out of range", "Grid frequency out of range", "211.0 V"} {
		if !strings.Contains(body, want) {
			t.Errorf("email missing %q", want)
		}
	}
	hist, _ := st.AlertEvents(ctx, store.AlertEventFilter{})
	if len(hist) != 2 {
		t.Errorf("alert history = %d events, want 2", len(hist))
	}
}
