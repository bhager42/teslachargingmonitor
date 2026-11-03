// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package web

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/alerts"
	"github.com/bhager42/teslachargingmonitor/internal/auth"
	"github.com/bhager42/teslachargingmonitor/internal/notify"
	"github.com/bhager42/teslachargingmonitor/internal/notify/smtpmock"
	"github.com/bhager42/teslachargingmonitor/internal/poller"
	"github.com/bhager42/teslachargingmonitor/internal/secrets"
	"github.com/bhager42/teslachargingmonitor/internal/store"
	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
	"github.com/bhager42/teslachargingmonitor/internal/wcsim"
)

type fakePoll struct {
	mu      sync.Mutex
	reloads int
	polled  []int64
	limit   bool
}

func (f *fakePoll) Reload(context.Context) error { f.mu.Lock(); f.reloads++; f.mu.Unlock(); return nil }
func (f *fakePoll) PollNow(id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.limit {
		return poller.ErrRateLimited
	}
	f.polled = append(f.polled, id)
	return nil
}

type full struct {
	*harness
	poll   *fakePoll
	engine *alerts.Engine
	smtp   *smtpmock.Server
	simURL string
	sim    *wcsim.Server
	c      *http.Cookie
	csrf   string
}

func newFull(t *testing.T) *full {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "tcmon.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	clk := &clock{t: time.Now()}
	am := auth.NewManager(st, auth.Config{Params: fast, Now: clk.now})
	token, _ := am.Init(context.Background(), auth.Bootstrap{})
	engine := alerts.New(st, nil)
	key, _ := secrets.LoadOrCreateKey(filepath.Join(dir, "secret.key"), nil)
	box, _ := secrets.NewBox(key)
	smtp, err := smtpmock.Start(smtpmock.Options{Username: "owner@gmail.com", Password: "abcdefghijklmnop"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(smtp.Close)
	disp := notify.New(st, box, notify.Config{RootCAs: smtp.RootCAs, SendTimeout: 5 * time.Second})
	fp := &fakePoll{}
	srv, err := New(Config{DataDir: dir}, Options{Store: st, Auth: am, Now: clk.now, Alerts: engine, Notify: disp, Poll: fp})
	if err != nil {
		t.Fatal(err)
	}
	sim, _ := wcsim.NewServer(wcsim.Options{Scenario: "charging"})
	ts := httptest.NewServer(sim)
	t.Cleanup(ts.Close)
	f := &full{harness: &harness{t: t, srv: srv, st: st, auth: am, clk: clk, token: token, dir: dir},
		poll: fp, engine: engine, smtp: smtp, simURL: ts.URL, sim: sim}
	f.c = f.setup()
	f.csrf = f.harness.csrf(f.c)
	return f
}

func (f *full) get(path string) (int, string) {
	f.t.Helper()
	r := f.do("GET", path, nil, cookie(f.c))
	return r.StatusCode, bodyOf(f.t, r)
}

func (f *full) post(path string, form url.Values) *http.Response {
	f.t.Helper()
	form.Set("csrf_token", f.csrf)
	return f.do("POST", path, form, cookie(f.c))
}

func (f *full) addDevice() store.Device {
	f.t.Helper()
	d := store.NewDevice("Garage", f.simURL)
	d.BreakerA = 60
	d, err := f.st.CreateDevice(context.Background(), d, time.Now())
	if err != nil {
		f.t.Fatal(err)
	}
	return d
}

func (f *full) saveSnapshot(d store.Device, scenario string, at time.Time) {
	f.t.Helper()
	sc, _ := wcsim.Lookup(scenario)
	st, _ := sc.State(10 * time.Minute)
	snap := &wallconnector.Snapshot{FetchedAt: at, Version: st.Version, Vitals: st.Vitals, Lifetime: st.Lifetime,
		WifiStatus: st.WifiStatus, Reports: map[wallconnector.Endpoint]wallconnector.Report{},
		Raw: map[wallconnector.Endpoint][]byte{wallconnector.EndpointVitals: []byte(`{"grid_v":240,"brand_new":1}`)}}
	if err := f.st.SaveSnapshot(context.Background(), d.ID, snap, nil, 1, 3*time.Millisecond); err != nil {
		f.t.Fatal(err)
	}
}

func TestAllPagesRender(t *testing.T) {
	f := newFull(t)
	d := f.addDevice()
	f.saveSnapshot(d, "charging", f.clk.now())
	ch, err := f.srv.notify.CreateEmailChannel(context.Background(), notify.EmailSettings{Name: "Gmail", Enabled: true,
		MinSeverity: alerts.Info, Email: notify.GmailPreset("owner@gmail.com", "me@example.com"), Password: "abcdefghijklmnop"})
	if err != nil {
		t.Fatal(err)
	}
	pages := []string{"/", "/alerts", "/notifications", "/notifications/new", "/notifications/" + itoa(ch.ID),
		"/settings", "/settings/devices", "/settings/devices/new", "/settings/devices/" + itoa(d.ID), "/diagnostics",
		"/devices/" + itoa(d.ID), "/devices/" + itoa(d.ID) + "?range=7d", "/alerts/rules/handle_temp_high",
		"/alerts/rules/unexpected_reboot", "/settings/security", "/about"}
	for _, p := range pages {
		status, body := f.get(p)
		if status != http.StatusOK {
			t.Errorf("GET %s = %d", p, status)
			continue
		}
		if inlineScript.MatchString(body) || strings.Contains(body, "style=") || strings.Contains(body, " on") && strings.Contains(body, "onclick=") {
			t.Errorf("%s has inline script/style/handlers", p)
		}
		if !strings.Contains(body, `<main id="main"`) || !strings.Contains(body, "<h1") {
			t.Errorf("%s lacks main landmark or heading", p)
		}
		if strings.Contains(body, "abcdefghijklmnop") {
			t.Errorf("%s leaks the email password", p)
		}
	}
	for _, p := range []string{"/devices/999", "/settings/devices/999", "/alerts/rules/nope", "/notifications/999"} {
		if status, _ := f.get(p); status != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, status)
		}
	}
	_, body := f.get("/")
	for _, want := range []string{"Charging", "47.9 A of 48 A", "11.47 kW", `data-device-id="` + itoa(d.ID) + `"`, "Garage"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	_, body = f.get("/diagnostics")
	if !strings.Contains(body, "brand_new") {
		t.Error("diagnostics does not report the unknown field")
	}
	_, body = f.get("/devices/" + itoa(d.ID))
	if !strings.Contains(body, "REDACTED") && !strings.Contains(body, "•") || strings.Contains(body, "02:00:00:00:00:00") {
		t.Error("device page shows identifiers")
	}
}

func itoa(n int64) string { return strconvItoa(n) }

func TestDeviceFormWithSimulator(t *testing.T) {
	f := newFull(t)
	form := url.Values{"name": {"Garage"}, "address": {f.simURL}, "breaker": {"60"}, "voltage": {"240"}, "hz": {"60"},
		"interval": {"60"}, "plugged_interval": {"5"}, "fast_when_plugged": {"1"}, "enabled": {"1"}}

	test := url.Values{}
	for k, v := range form {
		test[k] = v
	}
	test.Set("action", "test")
	r := f.post("/settings/devices/new", test)
	if b := bodyOf(t, r); r.StatusCode != 200 || !strings.Contains(b, "Found a Wall Connector") || !strings.Contains(b, "26.26.10") {
		t.Fatalf("test connection = %d %s", r.StatusCode, b)
	}
	if list, _ := f.st.Devices(context.Background()); len(list) != 0 {
		t.Fatal("test connection saved the device")
	}

	bad := url.Values{}
	for k, v := range form {
		bad[k] = v
	}
	bad.Set("address", "8.8.8.8")
	if r := f.post("/settings/devices/new", bad); r.StatusCode != 400 || !strings.Contains(bodyOf(t, r), "not a local network address") {
		t.Errorf("non-LAN address = %d", r.StatusCode)
	}
	bad.Set("address", "127.0.0.1:1")
	if r := f.post("/settings/devices/new", bad); r.StatusCode != 400 || !strings.Contains(bodyOf(t, r), "No Wall Connector answered") {
		t.Errorf("unreachable address = %d", r.StatusCode)
	}

	form.Set("action", "save")
	if r := f.post("/settings/devices/new", form); r.StatusCode != 303 {
		t.Fatalf("save = %d %s", r.StatusCode, bodyOf(t, r))
	}
	list, _ := f.st.Devices(context.Background())
	if len(list) != 1 || list[0].MaxCurrentA != 48 || list[0].PollInterval != time.Hour || f.poll.reloads != 1 {
		t.Fatalf("saved = %+v reloads=%d", list, f.poll.reloads)
	}
	id := itoa(list[0].ID)

	// Changing only the name does not re-test; an unreachable address does.
	form.Set("name", "Garage UWC")
	if r := f.post("/settings/devices/"+id, form); r.StatusCode != 303 {
		t.Errorf("rename = %d", r.StatusCode)
	}
	form.Set("address", "127.0.0.1:1")
	if r := f.post("/settings/devices/"+id, form); r.StatusCode != 400 {
		t.Errorf("edit to unreachable address = %d", r.StatusCode)
	}
	form.Set("skip_test", "1")
	if r := f.post("/settings/devices/"+id, form); r.StatusCode != 303 {
		t.Errorf("save without test = %d", r.StatusCode)
	}

	if r := f.post("/settings/devices/"+id+"/delete", url.Values{"confirm": {"wrong"}}); r.StatusCode != 400 {
		t.Errorf("delete without confirmation = %d", r.StatusCode)
	}
	if r := f.post("/settings/devices/"+id+"/delete", url.Values{"confirm": {"Garage UWC"}}); r.StatusCode != 303 {
		t.Errorf("delete = %d", r.StatusCode)
	}
	if list, _ := f.st.Devices(context.Background()); len(list) != 0 {
		t.Error("device not deleted")
	}
	audit, _ := f.st.AuditLog(context.Background(), 20)
	var saved int
	for _, e := range audit {
		if e.Action == "device_saved" {
			saved++
		}
	}
	if saved != 3 {
		t.Errorf("device_saved audit entries = %d", saved)
	}
}

func TestPollNowSeriesAndCSV(t *testing.T) {
	f := newFull(t)
	d := f.addDevice()
	for i := range 12 {
		f.saveSnapshot(d, "charging", f.clk.now().Add(-time.Duration(12-i)*time.Hour))
	}
	r := f.post("/devices/"+itoa(d.ID)+"/poll", url.Values{"back": {"home"}})
	if r.StatusCode != 303 || r.Header.Get("Location") != "/?ok=polling" || len(f.poll.polled) != 1 {
		t.Errorf("poll now = %d %s %v", r.StatusCode, r.Header.Get("Location"), f.poll.polled)
	}
	f.poll.limit = true
	if r := f.post("/devices/"+itoa(d.ID)+"/poll", url.Values{}); !strings.HasSuffix(r.Header.Get("Location"), "ok=poll-limited") {
		t.Errorf("rate limited = %s", r.Header.Get("Location"))
	}

	status, body := f.get("/api/devices/" + itoa(d.ID) + "/series?metric=handle_temp_c&range=24h")
	var res struct {
		Unit   string              `json:"unit"`
		Points []store.SeriesPoint `json:"points"`
	}
	if status != 200 || json.Unmarshal([]byte(body), &res) != nil || res.Unit != "°C" || len(res.Points) < 10 {
		t.Fatalf("series = %d %s", status, body)
	}
	for _, bad := range []string{"?metric=nope&range=24h", "?metric=grid_v&range=2d"} {
		if status, _ := f.get("/api/devices/" + itoa(d.ID) + "/series" + bad); status != 400 {
			t.Errorf("series%s = %d", bad, status)
		}
	}

	r = f.do("GET", "/devices/"+itoa(d.ID)+"/export.csv?range=7d", nil, cookie(f.c))
	csv := bodyOf(t, r)
	if r.StatusCode != 200 || !strings.HasPrefix(csv, "time_utc,vehicle_connected") || strings.Count(csv, "\n") != 13 ||
		!strings.Contains(r.Header.Get("Content-Disposition"), "attachment") {
		t.Errorf("csv = %d %q", r.StatusCode, csv[:min(len(csv), 200)])
	}

	// °F display preference applies to cards and charts.
	if r := f.post("/settings", url.Values{"temp_unit": {"F"}, "readings_days": {"730"}, "raw_payloads_days": {"90"},
		"rollups_days": {"0"}, "events_days": {"730"}, "poll_log_days": {"90"}, "audit_days": {"365"}}); r.StatusCode != 303 {
		t.Fatalf("settings = %d %s", r.StatusCode, bodyOf(t, r))
	}
	if _, body := f.get("/"); !strings.Contains(body, "°F") {
		t.Error("dashboard not in °F")
	}
	if _, body := f.get("/api/devices/" + itoa(d.ID) + "/series?metric=handle_temp_c&range=24h"); !strings.Contains(body, `"unit":"°F"`) {
		t.Error("series not in °F")
	}
}

func TestAlertPages(t *testing.T) {
	f := newFull(t)
	d := f.addDevice()
	ctx := context.Background()
	form := url.Values{"enabled": {"1"}, "p_warn_c": {"60"}, "p_crit_c": {"75"}, "p_hysteresis_c": {"5"}, "for_s": {"60"},
		"min_samples": {"1"}, "repeat_h": {"6"}, "cooldown_min": {"30"}, "notify_resolved": {"1"}, "action": {"save"}}
	if r := f.post("/alerts/rules/handle_temp_high", form); r.StatusCode != 303 {
		t.Fatalf("save rule = %d %s", r.StatusCode, bodyOf(t, r))
	}
	cfgs, _ := f.engine.Configs(ctx, 0)
	if cfgs["handle_temp_high"].Params["warn_c"] != 60 {
		t.Errorf("rule not saved: %+v", cfgs["handle_temp_high"])
	}
	form.Set("p_warn_c", "90")
	if r := f.post("/alerts/rules/handle_temp_high", form); r.StatusCode != 400 || !strings.Contains(bodyOf(t, r), "below critical") {
		t.Errorf("invalid rule = %d", r.StatusCode)
	}
	form.Set("p_warn_c", "abc")
	if r := f.post("/alerts/rules/handle_temp_high", form); r.StatusCode != 400 {
		t.Errorf("non-numeric = %d", r.StatusCode)
	}

	// Preview against a stored hot reading.
	f.saveSnapshot(d, "overheat", f.clk.now().Add(-time.Hour))
	form.Set("p_warn_c", "40")
	form.Set("action", "preview")
	r := f.post("/alerts/rules/handle_temp_high", form)
	if b := bodyOf(t, r); r.StatusCode != 200 || !strings.Contains(b, "Preview: last 24 hours") || !strings.Contains(b, "firing") {
		t.Errorf("preview = %d", r.StatusCode)
	}
	form.Set("action", "reset")
	_ = f.post("/alerts/rules/handle_temp_high", form)
	if cfgs, _ := f.engine.Configs(ctx, 0); cfgs["handle_temp_high"].Params["warn_c"] != 55 {
		t.Error("reset did not restore defaults")
	}

	// Snooze, history and acknowledgement.
	if r := f.post("/alerts/snooze", url.Values{"device_id": {itoa(d.ID)}, "hours": {"4"}, "reason": {"electrician"}}); r.StatusCode != 303 {
		t.Errorf("snooze = %d", r.StatusCode)
	}
	if r := f.post("/alerts/snooze", url.Values{"device_id": {itoa(d.ID)}, "hours": {"5"}}); r.StatusCode != 400 {
		t.Errorf("odd snooze duration = %d", r.StatusCode)
	}
	_, body := f.get("/alerts")
	if !strings.Contains(body, "muted until") {
		t.Error("snooze not listed")
	}
	snz, _ := f.st.ActiveSnoozes(ctx, d.ID, f.clk.now())
	_ = f.post("/alerts/snooze/"+itoa(snz[0].ID)+"/end", url.Values{})
	if snz, _ := f.st.ActiveSnoozes(ctx, d.ID, f.clk.now()); len(snz) != 0 {
		t.Error("snooze not ended")
	}
	ev := []store.AlertEvent{{RuleKey: "overcurrent", DeviceID: d.ID, TS: f.clk.now(), Kind: "firing", Severity: "critical", Message: "too much", Notified: true}}
	_ = f.st.SaveAlertResult(ctx, nil, ev, f.clk.now())
	if r := f.post("/alerts/events/"+itoa(ev[0].ID)+"/ack", url.Values{}); !strings.Contains(r.Header.Get("Location"), "acked") {
		t.Errorf("ack = %s", r.Header.Get("Location"))
	}
	if _, body := f.get("/alerts"); !strings.Contains(body, "acknowledged") || !strings.Contains(body, "Overcurrent") {
		t.Error("ack not shown")
	}
}

func TestNotificationPages(t *testing.T) {
	f := newFull(t)
	port := strings.TrimPrefix(f.smtp.Addr, "127.0.0.1:")
	form := url.Values{"name": {"Gmail"}, "username": {"owner@gmail.com"}, "password": {"abcd efgh ijkl mnop"},
		"to": {"me@example.com, partner@example.com"}, "host": {"localhost"}, "port": {port}, "security": {"starttls"},
		"min_severity": {"warning"}, "quiet_hours": {"22:00-07:00"}, "enabled": {"1"}, "action": {"save_test"}}
	r := f.post("/notifications/new", form)
	if r.StatusCode != 303 || !strings.Contains(r.Header.Get("Location"), "test-sent") || len(f.smtp.Messages()) != 1 {
		t.Fatalf("save and test = %d %s msgs=%d", r.StatusCode, bodyOf(t, r), len(f.smtp.Messages()))
	}
	chs, _ := f.srv.notify.Channels(context.Background())
	if len(chs) != 1 || chs[0].MinSeverity != alerts.Warning || chs[0].Email.From != "owner@gmail.com" || len(chs[0].Email.To) != 2 {
		t.Fatalf("channel = %+v", chs)
	}
	id := itoa(chs[0].ID)
	_, body := f.get("/notifications/" + id)
	if strings.Contains(body, "abcdefghijklmnop") || !strings.Contains(body, "Leave empty to keep it") {
		t.Error("edit form leaks or misdescribes the password")
	}
	// Empty password keeps the stored one.
	form.Set("password", "")
	form.Set("action", "save")
	_ = f.post("/notifications/"+id, form)
	if r := f.post("/notifications/"+id+"/test", url.Values{}); !strings.Contains(r.Header.Get("Location"), "test-sent") {
		t.Errorf("test after edit = %d", r.StatusCode)
	}
	form.Set("password", "wrong")
	form.Set("action", "save_test")
	if r := f.post("/notifications/"+id, form); r.StatusCode != 400 || !strings.Contains(bodyOf(t, r), "app password") {
		t.Errorf("wrong password = %d", r.StatusCode)
	}
	form.Set("to", "not an address")
	if r := f.post("/notifications/new", form); r.StatusCode != 400 {
		t.Errorf("bad recipient = %d", r.StatusCode)
	}
	if r := f.post("/notifications/"+id+"/delete", url.Values{}); r.StatusCode != 303 {
		t.Errorf("delete = %d", r.StatusCode)
	}
	if chs, _ := f.srv.notify.Channels(context.Background()); len(chs) != 0 {
		t.Error("channel not deleted")
	}
}

func TestSettingsRetentionAndBackup(t *testing.T) {
	f := newFull(t)
	// "Keep forever" (0) must not prefill the min="1" custom box, or the
	// browser refuses to submit the form.
	if _, body := f.get("/settings"); !strings.Contains(body, `name="rollups_days_custom" type="number" min="1" max="36500" value=""`) {
		t.Error(`"Keep forever" prefills the custom days box`)
	}
	form := url.Values{"temp_unit": {"C"}, "readings_days": {"custom"}, "readings_days_custom": {"45"}, "raw_payloads_days": {"90"},
		"rollups_days": {"0"}, "events_days": {"730"}, "poll_log_days": {"90"}, "audit_days": {"365"}}
	if r := f.post("/settings", form); r.StatusCode != 400 || !strings.Contains(bodyOf(t, r), "permanently deletes") {
		t.Errorf("shrinking without confirmation = %d", r.StatusCode)
	}
	form.Set("confirm_delete", "1")
	if r := f.post("/settings", form); r.StatusCode != 303 {
		t.Fatalf("save = %d %s", r.StatusCode, bodyOf(t, r))
	}
	if ret, _ := f.st.Retention(context.Background()); ret.ReadingsDays != 45 {
		t.Errorf("retention = %+v", ret)
	}
	if _, body := f.get("/settings"); !strings.Contains(body, `value="custom" selected`) {
		t.Error("custom retention not preselected")
	}
	form.Set("readings_days", "-5")
	if r := f.post("/settings", form); r.StatusCode != 400 {
		t.Errorf("negative retention = %d", r.StatusCode)
	}
	r := f.post("/settings/backup", url.Values{})
	if b := bodyOf(t, r); r.StatusCode != 200 || !strings.HasPrefix(b, "SQLite format 3") {
		t.Errorf("backup = %d", r.StatusCode)
	}
}

func TestThemeCookie(t *testing.T) {
	f := newFull(t)
	r := f.do("GET", "/", nil, cookie(f.c), cookie(&http.Cookie{Name: "tcmon_theme", Value: "light"})) //nolint:gosec // request-side test cookie
	if b := bodyOf(t, r); !strings.Contains(b, `data-theme="light"`) || !strings.Contains(b, `data-set-theme="light" aria-pressed="true"`) {
		t.Error("light theme not rendered server-side")
	}
	r = f.do("GET", "/login", nil, cookie(&http.Cookie{Name: "tcmon_theme", Value: "<script>"})) //nolint:gosec // request-side test cookie
	if b := bodyOf(t, r); !strings.Contains(b, `data-theme="system"`) {
		t.Error("invalid theme cookie not ignored")
	}
}

func TestLiveEvents(t *testing.T) {
	f := newFull(t)
	d := f.addDevice()
	ts := httptest.NewUnstartedServer(f.srv.Handler())
	ts.EnableHTTP2 = false
	ts.StartTLS()
	defer ts.Close()
	client := ts.Client()
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test server
	req, _ := http.NewRequestWithContext(context.Background(), "GET", ts.URL+"/events", nil)
	req.Host = "localhost"
	req.AddCookie(f.c)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("events = %v %v", resp, err)
	}
	defer func() { _ = resp.Body.Close() }()
	rd := bufio.NewReader(resp.Body)
	if line, _ := rd.ReadString('\n'); !strings.HasPrefix(line, "retry:") {
		t.Fatalf("first line = %q", line)
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.srv.hub.Clients() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	f.saveSnapshot(d, "charging", f.clk.now())
	f.srv.HandleUpdate(poller.Update{Device: d})
	f.srv.HandleAlerts([]alerts.Notification{{RuleTitle: "Overcurrent", DeviceName: "Garage", Kind: "firing", Severity: alerts.Critical}})
	got := map[string]string{}
	for len(got) < 2 && time.Now().Before(deadline) {
		line, err := rd.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "event: ") {
			data, _ := rd.ReadString('\n')
			got[strings.TrimSpace(strings.TrimPrefix(line, "event: "))] = data
		}
	}
	if !strings.Contains(got["device"], `"state":"Charging"`) || !strings.Contains(got["alerts"], "Overcurrent") {
		t.Errorf("events = %v", got)
	}
	// Without a session the stream is refused.
	if r := f.do("GET", "/events", nil); r.StatusCode != 303 {
		t.Errorf("anonymous events = %d", r.StatusCode)
	}
}

func strconvItoa(n int64) string { return strconv.FormatInt(n, 10) }
