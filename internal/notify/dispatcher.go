// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package notify

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/alerts"
	"github.com/bhager42/teslachargingmonitor/internal/secrets"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

// TypeEmail is the email channel type.
const TypeEmail = "email"

var emailAAD = []byte("tcmon:notify_channel:email:v1")

// Config tunes the Dispatcher. Zero values select production defaults.
type Config struct {
	Logger *slog.Logger
	Now    func() time.Time
	// Location for times shown in messages and for quiet hours.
	Location *time.Location
	// RootCAs for SMTP TLS verification; nil means the system roots
	// (plus any mounted custom CA bundle via SSL_CERT_FILE).
	RootCAs *x509.CertPool
	// Backoff between delivery attempts (default 1 m, 5 m, 15 m, 1 h; the
	// last value repeats) until GiveUpAfter (default 24 h).
	Backoff     []time.Duration
	GiveUpAfter time.Duration
	// SendTimeout bounds one SMTP conversation (default 60 s).
	SendTimeout time.Duration
	// PollEvery is the worker's fallback wake-up interval (default 30 s).
	PollEvery time.Duration
}

// Dispatcher queues notification batches per channel and delivers them.
type Dispatcher struct {
	st   *store.Store
	box  *secrets.Box
	cfg  Config
	wake chan struct{}
}

// New returns a Dispatcher; box encrypts channel credentials.
func New(st *store.Store, box *secrets.Box, cfg Config) *Dispatcher {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Location == nil {
		cfg.Location = time.Local
	}
	if cfg.Backoff == nil {
		cfg.Backoff = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour}
	}
	if cfg.GiveUpAfter == 0 {
		cfg.GiveUpAfter = 24 * time.Hour
	}
	if cfg.PollEvery == 0 {
		cfg.PollEvery = 30 * time.Second
	}
	return &Dispatcher{st: st, box: box, cfg: cfg, wake: make(chan struct{}, 1)}
}

// EmailSettings creates or updates an email channel.
type EmailSettings struct {
	Name        string
	Enabled     bool
	MinSeverity alerts.Severity
	QuietHours  string // "HH:MM-HH:MM" or ""
	Email       EmailConfig
	// Password is the SMTP (Gmail app) password. On update, an empty
	// value keeps the stored one.
	Password secrets.Secret
}

// ChannelInfo is a channel as shown to users: never includes secrets.
type ChannelInfo struct {
	ID                  int64
	Type                string
	Name                string
	Enabled             bool
	MinSeverity         alerts.Severity
	QuietHours          string
	Email               EmailConfig
	PasswordSet         bool
	LastSuccess         *time.Time
	LastError           string
	LastErrorAt         *time.Time
	ConsecutiveFailures int
}

type emailSecret struct {
	Password string `json:"password"`
}

func (s *EmailSettings) validate() error {
	if n := len([]rune(s.Name)); n < 1 || n > 64 || !noCRLF(s.Name) {
		return errors.New("channel name must be 1-64 characters")
	}
	if s.MinSeverity < alerts.Info || s.MinSeverity > alerts.Critical {
		return errors.New("minimum severity must be info, warning or critical")
	}
	if s.QuietHours != "" {
		if _, err := alerts.ParseQuietHours(s.QuietHours); err != nil {
			return err
		}
	}
	return s.Email.Normalize()
}

func (d *Dispatcher) seal(pw secrets.Secret) ([]byte, error) {
	b, err := json.Marshal(emailSecret{Password: pw.Reveal()})
	if err != nil {
		return nil, err
	}
	return d.box.Seal(b, emailAAD)
}

// CreateEmailChannel validates, encrypts the password and stores a channel.
func (d *Dispatcher) CreateEmailChannel(ctx context.Context, s EmailSettings) (ChannelInfo, error) {
	if err := s.validate(); err != nil {
		return ChannelInfo{}, err
	}
	if s.Email.Username != "" && !s.Password.IsSet() {
		return ChannelInfo{}, errors.New("a password (Gmail: app password) is required when a username is set")
	}
	cfgJSON, err := json.Marshal(s.Email)
	if err != nil {
		return ChannelInfo{}, err
	}
	sealed, err := d.seal(s.Password)
	if err != nil {
		return ChannelInfo{}, err
	}
	ch, err := d.st.CreateNotifyChannel(ctx, store.NotifyChannel{Type: TypeEmail, Name: s.Name, Enabled: s.Enabled,
		MinSeverity: s.MinSeverity.String(), QuietHours: s.QuietHours, Config: cfgJSON, SecretEnc: sealed}, d.cfg.Now())
	if err != nil {
		return ChannelInfo{}, err
	}
	return d.info(ch)
}

// UpdateEmailChannel saves new settings; an empty password keeps the old one.
func (d *Dispatcher) UpdateEmailChannel(ctx context.Context, id int64, s EmailSettings) (ChannelInfo, error) {
	if err := s.validate(); err != nil {
		return ChannelInfo{}, err
	}
	ch, err := d.st.NotifyChannel(ctx, id)
	if err != nil {
		return ChannelInfo{}, err
	}
	if s.Password.IsSet() {
		if ch.SecretEnc, err = d.seal(s.Password); err != nil {
			return ChannelInfo{}, err
		}
	}
	if ch.Config, err = json.Marshal(s.Email); err != nil {
		return ChannelInfo{}, err
	}
	ch.Name, ch.Enabled, ch.MinSeverity, ch.QuietHours = s.Name, s.Enabled, s.MinSeverity.String(), s.QuietHours
	if err := d.st.UpdateNotifyChannel(ctx, ch, d.cfg.Now()); err != nil {
		return ChannelInfo{}, err
	}
	return d.Channel(ctx, id)
}

// DeleteChannel removes a channel and its delivery log.
func (d *Dispatcher) DeleteChannel(ctx context.Context, id int64) error {
	return d.st.DeleteNotifyChannel(ctx, id)
}

// Channel returns one channel without secrets.
func (d *Dispatcher) Channel(ctx context.Context, id int64) (ChannelInfo, error) {
	ch, err := d.st.NotifyChannel(ctx, id)
	if err != nil {
		return ChannelInfo{}, err
	}
	return d.info(ch)
}

// Channels lists channels without secrets.
func (d *Dispatcher) Channels(ctx context.Context) ([]ChannelInfo, error) {
	chs, err := d.st.NotifyChannels(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ChannelInfo, 0, len(chs))
	for _, ch := range chs {
		ci, err := d.info(ch)
		if err != nil {
			return nil, err
		}
		out = append(out, ci)
	}
	return out, nil
}

func (d *Dispatcher) info(ch store.NotifyChannel) (ChannelInfo, error) {
	sev, err := alerts.ParseSeverity(ch.MinSeverity)
	if err != nil {
		return ChannelInfo{}, err
	}
	ci := ChannelInfo{ID: ch.ID, Type: ch.Type, Name: ch.Name, Enabled: ch.Enabled, MinSeverity: sev,
		QuietHours: ch.QuietHours, LastSuccess: ch.LastSuccess, LastError: ch.LastError, LastErrorAt: ch.LastErrorAt,
		ConsecutiveFailures: ch.ConsecutiveFailures}
	if err := json.Unmarshal(ch.Config, &ci.Email); err != nil {
		return ChannelInfo{}, fmt.Errorf("notify: channel %d config: %w", ch.ID, err)
	}
	if pw, err := d.password(ch); err == nil {
		ci.PasswordSet = pw.IsSet()
	}
	return ci, nil
}

func (d *Dispatcher) password(ch store.NotifyChannel) (secrets.Secret, error) {
	if len(ch.SecretEnc) == 0 {
		return "", nil
	}
	pt, err := d.box.Open(ch.SecretEnc, emailAAD)
	if err != nil {
		return "", err
	}
	var s emailSecret
	if err := json.Unmarshal(pt, &s); err != nil {
		return "", err
	}
	return secrets.Secret(s.Password), nil
}

func (d *Dispatcher) sender(ch store.NotifyChannel) (emailSender, error) {
	if ch.Type != TypeEmail {
		return emailSender{}, fmt.Errorf("notify: unsupported channel type %q", ch.Type)
	}
	var cfg EmailConfig
	if err := json.Unmarshal(ch.Config, &cfg); err != nil {
		return emailSender{}, err
	}
	pw, err := d.password(ch)
	if err != nil {
		return emailSender{}, fmt.Errorf("notify: decrypting credentials for %q: %w", ch.Name, err)
	}
	return emailSender{cfg: cfg, password: pw, roots: d.cfg.RootCAs, timeout: d.cfg.SendTimeout, now: d.cfg.Now}, nil
}

// filter keeps what a channel should receive: at or above its minimum
// severity, and outside quiet hours unless critical.
func (d *Dispatcher) filter(ch store.NotifyChannel, batch []alerts.Notification) []alerts.Notification {
	minSev, err := alerts.ParseSeverity(ch.MinSeverity)
	if err != nil {
		minSev = alerts.Info
	}
	var q alerts.QuietHours
	if ch.QuietHours != "" {
		q, _ = alerts.ParseQuietHours(ch.QuietHours)
	}
	now := d.cfg.Now().In(d.cfg.Location)
	var out []alerts.Notification
	for _, n := range batch {
		if n.Severity >= minSev && q.Allows(n.Severity, now) {
			out = append(out, n)
		}
	}
	return out
}

// Enqueue renders a batch once per enabled channel and queues it.
func (d *Dispatcher) Enqueue(ctx context.Context, batch []alerts.Notification) error {
	chs, err := d.st.NotifyChannels(ctx)
	if err != nil {
		return err
	}
	now := d.cfg.Now()
	var ds []store.Delivery
	for _, ch := range chs {
		if !ch.Enabled {
			continue
		}
		items := d.filter(ch, batch)
		if len(items) == 0 {
			continue
		}
		msg := Build(items, d.cfg.Location)
		js, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		ids := make([]int64, 0, len(items))
		for _, n := range items {
			ids = append(ids, n.EventID)
		}
		ds = append(ds, store.Delivery{ChannelID: ch.ID, CreatedAt: now, NextAttempt: now, Subject: msg.Subject,
			MessageJSON: js, EventIDs: ids})
	}
	if len(ds) == 0 {
		if len(chs) == 0 && len(batch) > 0 {
			d.cfg.Logger.Warn("alert not delivered: no notification channel configured", "notifications", len(batch))
		}
		return nil
	}
	if err := d.st.EnqueueDeliveries(ctx, ds); err != nil {
		return err
	}
	d.kick()
	return nil
}

func (d *Dispatcher) kick() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// Run enqueues batches from the alert engine and delivers the queue until
// ctx ends.
func (d *Dispatcher) Run(ctx context.Context, batches <-chan []alerts.Notification) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case b, ok := <-batches:
				if !ok {
					return
				}
				if err := d.Enqueue(ctx, b); err != nil && ctx.Err() == nil {
					d.cfg.Logger.Error("queueing notifications", "err", err)
				}
			}
		}
	}()
	for {
		if err := d.DeliverDue(ctx); err != nil && ctx.Err() == nil {
			d.cfg.Logger.Error("delivering notifications", "err", err)
		}
		wait := d.cfg.PollEvery
		if next, ok, err := d.st.NextDeliveryAt(ctx); err == nil && ok {
			wait = min(wait, max(next.Sub(d.cfg.Now()), 0))
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-d.wake:
			t.Stop()
		case <-t.C:
		}
	}
}

// DeliverDue attempts every due delivery once.
func (d *Dispatcher) DeliverDue(ctx context.Context) error {
	due, err := d.st.DueDeliveries(ctx, d.cfg.Now(), 50)
	if err != nil {
		return err
	}
	for _, del := range due {
		if err := d.deliver(ctx, del); err != nil {
			return err
		}
	}
	return nil
}

func (d *Dispatcher) deliver(ctx context.Context, del store.Delivery) error {
	log := d.cfg.Logger.With("delivery_id", del.ID, "channel_id", del.ChannelID)
	ch, err := d.st.NotifyChannel(ctx, del.ChannelID)
	if err != nil {
		return err
	}
	var msg Message
	if err := json.Unmarshal(del.MessageJSON, &msg); err != nil {
		return d.st.MarkDeliveryFailed(ctx, del.ID, del.Attempts, "corrupt queued message: "+err.Error())
	}
	attempts := del.Attempts + 1
	snd, err := d.sender(ch)
	if err == nil {
		err = snd.send(ctx, msg)
	}
	now := d.cfg.Now()
	if err == nil {
		log.Info("notification sent", "channel", ch.Name, "subject", msg.Subject, "attempts", attempts)
		if err := d.st.RecordChannelResult(ctx, ch.ID, true, "", now); err != nil {
			return err
		}
		return d.st.MarkDeliverySent(ctx, del.ID, attempts, now)
	}
	if ctx.Err() != nil {
		return nil // shutting down: leave it pending
	}
	text := Describe(err)
	_ = d.st.RecordChannelResult(ctx, ch.ID, false, text, now)
	var se *SendError
	permanent := errors.As(err, &se) && se.Permanent
	if permanent || now.Sub(del.CreatedAt) >= d.cfg.GiveUpAfter {
		log.Error("notification delivery failed; giving up", "channel", ch.Name, "attempts", attempts, "err", text)
		return d.st.MarkDeliveryFailed(ctx, del.ID, attempts, text)
	}
	backoff := d.cfg.Backoff[min(attempts-1, len(d.cfg.Backoff)-1)]
	log.Warn("notification delivery failed; will retry", "channel", ch.Name, "attempts", attempts,
		"retry_in", backoff.String(), "err", text)
	return d.st.MarkDeliveryRetry(ctx, del.ID, attempts, now.Add(backoff), text)
}

// Describe returns an error message with the plain-English hint, if any.
func Describe(err error) string {
	var se *SendError
	if errors.As(err, &se) && se.Hint != "" {
		return se.Hint + " (" + se.Err.Error() + ")"
	}
	return err.Error()
}

// Test sends a test message through a channel immediately (not queued).
func (d *Dispatcher) Test(ctx context.Context, id int64) error {
	ch, err := d.st.NotifyChannel(ctx, id)
	if err != nil {
		return err
	}
	snd, err := d.sender(ch)
	if err != nil {
		return err
	}
	now := d.cfg.Now()
	msg := Build([]alerts.Notification{{RuleTitle: "Test notification", DeviceName: "Tesla Charger Monitoring",
		Kind: alerts.KindEvent, Severity: alerts.Info, At: now,
		Message: "This is a test from Tesla Charger Monitoring. If you can read this, email alerts work."}}, d.cfg.Location)
	msg.Subject = "Test notification"
	err = snd.send(ctx, msg)
	_ = d.st.RecordChannelResult(ctx, ch.ID, err == nil, describeOrEmpty(err), now)
	return err
}

func describeOrEmpty(err error) string {
	if err == nil {
		return ""
	}
	return Describe(err)
}
