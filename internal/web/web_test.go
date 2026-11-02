// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package web

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/auth"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

const goodPassword = "purple otter kayak sunrise"

var fast = auth.Params{MemoryKiB: 8 * 1024, Time: 1, Threads: 1}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type harness struct {
	t     *testing.T
	srv   *Server
	st    *store.Store
	auth  *auth.Manager
	clk   *clock
	token string
	dir   string
}

func newHarness(t *testing.T, cfg Config, b auth.Bootstrap) *harness {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "tcmon.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	clk := &clock{t: time.Now()}
	am := auth.NewManager(st, auth.Config{Params: fast, Now: clk.now})
	token, err := am.Init(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DataDir = dir
	srv, err := New(cfg, Options{Store: st, Auth: am, Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, srv: srv, st: st, auth: am, clk: clk, token: token, dir: dir}
}

type reqOpt func(*http.Request)

func from(ip string) reqOpt        { return func(r *http.Request) { r.RemoteAddr = ip + ":51000" } }
func host(h string) reqOpt         { return func(r *http.Request) { r.Host = h } }
func cookie(c *http.Cookie) reqOpt { return func(r *http.Request) { r.AddCookie(c) } }
func header(k, v string) reqOpt    { return func(r *http.Request) { r.Header.Set(k, v) } }

func (h *harness) do(method, path string, form url.Values, opts ...reqOpt) *http.Response {
	h.t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, "https://192.168.1.10:8443"+path, body)
	r.RemoteAddr = "192.168.1.50:51000"
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	for _, o := range opts {
		o(r)
	}
	w := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(w, r)
	return w.Result()
}

func bodyOf(t *testing.T, r *http.Response) string {
	t.Helper()
	b := new(strings.Builder)
	_, _ = new(strings.Builder).WriteString("")
	buf := make([]byte, 64<<10)
	for {
		n, err := r.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return b.String()
}

func sessionCookie(t *testing.T, r *http.Response) *http.Cookie {
	t.Helper()
	for _, c := range r.Cookies() {
		if c.Name == "__Host-tcmon_session" && c.Value != "" {
			return c
		}
	}
	t.Fatalf("no session cookie in %v", r.Header.Values("Set-Cookie"))
	return nil
}

var csrfRE = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (h *harness) csrf(c *http.Cookie) string {
	h.t.Helper()
	m := csrfRE.FindStringSubmatch(bodyOf(h.t, h.do("GET", "/settings/security", nil, cookie(c))))
	if m == nil {
		h.t.Fatal("no CSRF token on page")
	}
	return m[1]
}

// setup completes first-run setup and returns the session cookie.
func (h *harness) setup() *http.Cookie {
	h.t.Helper()
	r := h.do("POST", "/setup", url.Values{"token": {h.token}, "password": {goodPassword}, "confirm": {goodPassword}})
	if r.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("setup = %d %s", r.StatusCode, bodyOf(h.t, r))
	}
	return sessionCookie(h.t, r)
}

func (h *harness) login(pw string, remember bool) *http.Response {
	f := url.Values{"password": {pw}}
	if remember {
		f.Set("remember", "1")
	}
	return h.do("POST", "/login", f)
}

func TestSecurityHeadersEverywhere(t *testing.T) {
	h := newHarness(t, Config{}, auth.Bootstrap{})
	paths := []string{"/login", "/setup", "/healthz", "/readyz", "/static/app.css", "/nope", "/"}
	for _, p := range paths {
		r := h.do("GET", p, nil)
		for k, want := range map[string]string{
			"X-Content-Type-Options":       "nosniff",
			"X-Frame-Options":              "DENY",
			"Referrer-Policy":              "no-referrer",
			"Cross-Origin-Opener-Policy":   "same-origin",
			"Cross-Origin-Embedder-Policy": "require-corp",
			"Cross-Origin-Resource-Policy": "same-origin",
		} {
			if got := r.Header.Get(k); got != want {
				t.Errorf("%s %s = %q, want %q", p, k, got, want)
			}
		}
		csp := r.Header.Get("Content-Security-Policy")
		for _, d := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'",
			"require-trusted-types-for 'script'", "form-action 'self'", "base-uri 'none'"} {
			if !strings.Contains(csp, d) {
				t.Errorf("%s CSP missing %q", p, d)
			}
		}
		if strings.Contains(csp, "unsafe-") {
			t.Errorf("%s CSP allows unsafe-*: %s", p, csp)
		}
		if !strings.Contains(r.Header.Get("Permissions-Policy"), "camera=()") {
			t.Errorf("%s Permissions-Policy missing", p)
		}
		if r.Header.Get("Strict-Transport-Security") != "" {
			t.Errorf("%s: HSTS must not be sent with a self-signed certificate", p)
		}
		if !strings.HasPrefix(p, "/static/") && r.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s Cache-Control = %q", p, r.Header.Get("Cache-Control"))
		}
	}
	// Pages have no inline scripts or styles (CSP would block them anyway).
	for _, p := range []string{"/setup", "/nope"} {
		b := bodyOf(t, h.do("GET", p, nil))
		if strings.Contains(b, "<script") || strings.Contains(b, "style=") || strings.Contains(b, "<style") {
			t.Errorf("%s contains inline script/style", p)
		}
	}
	// Static assets: immutable only with the right content hash.
	css := h.do("GET", "/static/app.css?v="+h.srv.assetHash["app.css"], nil)
	if css.StatusCode != 200 || !strings.Contains(css.Header.Get("Cache-Control"), "immutable") ||
		!strings.HasPrefix(css.Header.Get("Content-Type"), "text/css") {
		t.Errorf("css = %d %v", css.StatusCode, css.Header)
	}
	if r := h.do("GET", "/static/app.css?v=old", nil); r.Header.Get("Cache-Control") != "no-cache" {
		t.Errorf("stale asset cache = %q", r.Header.Get("Cache-Control"))
	}

	hsts := newHarness(t, Config{HSTS: true}, auth.Bootstrap{})
	if r := hsts.do("GET", "/login", nil); r.Header.Get("Strict-Transport-Security") != "max-age=31536000" {
		t.Error("HSTS not sent when enabled")
	}
}

func TestLANOnlyAndHostCheck(t *testing.T) {
	proxy := netip.MustParsePrefix("192.168.1.2/32")
	h := newHarness(t, Config{PublicHostnames: []string{"truenas.lan"}, TrustedProxies: []netip.Prefix{proxy}}, auth.Bootstrap{})
	cases := []struct {
		name string
		opts []reqOpt
		want int
	}{
		{"LAN client", []reqOpt{from("192.168.1.50")}, 200},
		{"loopback", []reqOpt{from("127.0.0.1")}, 200},
		{"IPv6 ULA", []reqOpt{from("[fd00::5]")}, 200},
		{"internet client", []reqOpt{from("8.8.8.8")}, 403},
		{"CGNAT/Tailscale not LAN", []reqOpt{from("100.64.0.9")}, 403},
		{"spoofed XFF from untrusted peer", []reqOpt{from("8.8.8.8"), header("X-Forwarded-For", "192.168.1.9")}, 403},
		{"trusted proxy forwarding LAN client", []reqOpt{from("192.168.1.2"), header("X-Forwarded-For", "192.168.1.77")}, 200},
		{"trusted proxy forwarding internet client", []reqOpt{from("192.168.1.2"), header("X-Forwarded-For", "192.168.1.77, 1.2.3.4")}, 403},
		{"public hostname", []reqOpt{host("truenas.lan:8443")}, 200},
		{"localhost", []reqOpt{host("localhost:8443")}, 200},
		{"IPv6 literal host", []reqOpt{host("[fd00::1]:8443")}, 200},
		{"DNS rebinding host", []reqOpt{host("attacker.example:8443")}, http.StatusMisdirectedRequest},
	}
	for _, c := range cases {
		if r := h.do("GET", "/healthz", nil, c.opts...); r.StatusCode != c.want {
			t.Errorf("%s: status %d, want %d", c.name, r.StatusCode, c.want)
		}
	}
	custom := newHarness(t, Config{AllowedClients: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}}, auth.Bootstrap{})
	if r := custom.do("GET", "/healthz", nil, from("10.0.0.5")); r.StatusCode != 403 {
		t.Errorf("narrowed allowlist not applied: %d", r.StatusCode)
	}
}

func TestSetupFlow(t *testing.T) {
	h := newHarness(t, Config{}, auth.Bootstrap{})
	if h.token == "" {
		t.Fatal("no setup token issued")
	}
	if r := h.do("GET", "/", nil); r.StatusCode != 303 || r.Header.Get("Location") != "/login" {
		t.Fatalf("/ = %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	if r := h.do("GET", "/login", nil); r.Header.Get("Location") != "/setup" {
		t.Fatalf("/login without password should go to setup: %s", r.Header.Get("Location"))
	}
	if r := h.do("GET", "/setup", nil); r.StatusCode != 200 || !strings.Contains(bodyOf(t, r), "setup token") {
		t.Fatal("setup page")
	}
	bad := []struct {
		form url.Values
		want string
	}{
		{url.Values{"token": {"WRONG"}, "password": {goodPassword}, "confirm": {goodPassword}}, "incorrect setup token"},
		{url.Values{"token": {h.token}, "password": {"short"}, "confirm": {"short"}}, "at least 12"},
		{url.Values{"token": {h.token}, "password": {"password1234"}, "confirm": {"password1234"}}, "commonly used"},
		{url.Values{"token": {h.token}, "password": {goodPassword}, "confirm": {goodPassword + "x"}}, "do not match"},
	}
	for _, b := range bad {
		r := h.do("POST", "/setup", b.form)
		if r.StatusCode != 400 || !strings.Contains(bodyOf(t, r), b.want) {
			t.Errorf("setup %v = %d, want message %q", b.form["password"], r.StatusCode, b.want)
		}
	}
	c := h.setup()
	if c.Path != "/" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Domain != "" || c.MaxAge != 0 {
		t.Errorf("cookie flags = %+v", c)
	}
	if r := h.do("GET", "/", nil, cookie(c)); r.StatusCode != 200 || !strings.Contains(bodyOf(t, r), "Dashboard") {
		t.Errorf("dashboard after setup = %d", r.StatusCode)
	}
	if r := h.do("GET", "/setup", nil); r.Header.Get("Location") != "/login" {
		t.Error("setup still reachable after a password was set")
	}
	if r := h.do("POST", "/setup", url.Values{"token": {h.token}, "password": {goodPassword}, "confirm": {goodPassword}}); r.StatusCode != http.StatusGone {
		t.Errorf("reusing the setup token = %d", r.StatusCode)
	}
	// The token expires.
	h2 := newHarness(t, Config{}, auth.Bootstrap{})
	h2.clk.add(31 * time.Minute)
	if r := h2.do("GET", "/setup", nil); r.StatusCode != http.StatusGone {
		t.Errorf("expired setup = %d", r.StatusCode)
	}
}

func TestLoginLogoutAndThrottle(t *testing.T) {
	h := newHarness(t, Config{}, auth.Bootstrap{})
	h.setup()
	if r := h.login("wrong password here", false); r.StatusCode != 401 || !strings.Contains(bodyOf(t, r), "Incorrect password") {
		t.Fatalf("bad login = %d", r.StatusCode)
	}
	r := h.login(goodPassword, true)
	if r.StatusCode != 303 {
		t.Fatalf("login = %d", r.StatusCode)
	}
	c := sessionCookie(t, r)
	if c.MaxAge < 29*24*3600 {
		t.Errorf("remember-me cookie MaxAge = %d", c.MaxAge)
	}
	if r := h.do("GET", "/login", nil, cookie(c)); r.Header.Get("Location") != "/" {
		t.Error("signed-in user not redirected from /login")
	}

	// Logout needs the CSRF token.
	if r := h.do("POST", "/logout", url.Values{}, cookie(c)); r.StatusCode != 403 {
		t.Errorf("logout without CSRF = %d", r.StatusCode)
	}
	token := h.csrf(c)
	if r := h.do("POST", "/logout", url.Values{"csrf": {token}}, cookie(c), header("Sec-Fetch-Site", "cross-site")); r.StatusCode != 403 {
		t.Errorf("cross-site logout = %d", r.StatusCode)
	}
	r = h.do("POST", "/logout", url.Values{"csrf": {token}}, cookie(c))
	if r.StatusCode != 303 || !strings.HasPrefix(r.Header.Get("Location"), "/login") {
		t.Fatalf("logout = %d", r.StatusCode)
	}
	if r := h.do("GET", "/", nil, cookie(c)); r.StatusCode != 303 {
		t.Error("session still valid after logout")
	}

	// 5 failures per IP → 429 with Retry-After; other IPs unaffected.
	for range 5 {
		h.login("nope nope nope nope", false)
	}
	r = h.login(goodPassword, false)
	if r.StatusCode != http.StatusTooManyRequests || r.Header.Get("Retry-After") == "" {
		t.Errorf("throttled login = %d", r.StatusCode)
	}
	if r := h.do("POST", "/login", url.Values{"password": {goodPassword}}, from("192.168.1.51")); r.StatusCode != 303 {
		t.Errorf("other IP blocked: %d", r.StatusCode)
	}
	h.clk.add(16 * time.Minute)
	if r := h.login(goodPassword, false); r.StatusCode != 303 {
		t.Errorf("after window = %d", r.StatusCode)
	}
	log, _ := h.st.AuditLog(context.Background(), 50)
	actions := map[string]int{}
	for _, e := range log {
		actions[e.Action]++
	}
	if actions["login_failed"] < 6 || actions["login_throttled"] < 1 || actions["logout"] != 1 || actions["password_set_setup"] != 1 {
		t.Errorf("audit = %v", actions)
	}
}

func TestSessionsExpire(t *testing.T) {
	h := newHarness(t, Config{}, auth.Bootstrap{})
	c := h.setup()
	h.clk.add(11 * time.Hour)
	if r := h.do("GET", "/", nil, cookie(c)); r.StatusCode != 200 {
		t.Fatal("session expired too early")
	}
	h.clk.add(13 * time.Hour) // idle 13 h > 12 h
	if r := h.do("GET", "/", nil, cookie(c)); r.StatusCode != 303 {
		t.Error("idle session not expired")
	}
	// Absolute lifetime (7 days) even when active.
	c = sessionCookie(t, h.login(goodPassword, false))
	for range 8 {
		h.clk.add(23 * time.Hour)
		h.do("GET", "/", nil, cookie(c))
	}
	if r := h.do("GET", "/", nil, cookie(c)); r.StatusCode != 303 {
		t.Error("session outlived its absolute lifetime")
	}
	forged := &http.Cookie{Name: "__Host-tcmon_session", Value: "forged"} //nolint:gosec // G124: request-side test cookie
	if r := h.do("GET", "/", nil, cookie(forged)); r.StatusCode != 303 {
		t.Error("forged cookie accepted")
	}
}

func TestChangePasswordAndRevoke(t *testing.T) {
	h := newHarness(t, Config{}, auth.Bootstrap{})
	me := h.setup()
	other := sessionCookie(t, h.login(goodPassword, false))
	token := h.csrf(me)

	newPW := "granite lantern meadow 42"
	r := h.do("POST", "/settings/password", url.Values{"csrf": {token}, "current": {"wrong one entirely"}, "password": {newPW}, "confirm": {newPW}}, cookie(me))
	if r.StatusCode != 400 || !strings.Contains(bodyOf(t, r), "incorrect password") {
		t.Errorf("wrong current = %d", r.StatusCode)
	}
	r = h.do("POST", "/settings/password", url.Values{"csrf": {token}, "current": {goodPassword}, "password": {newPW}, "confirm": {newPW}}, cookie(me))
	if r.StatusCode != 303 {
		t.Fatalf("change = %d %s", r.StatusCode, bodyOf(t, r))
	}
	fresh := sessionCookie(t, r)
	if fresh.Value == me.Value {
		t.Error("session not rotated on password change")
	}
	for name, c := range map[string]*http.Cookie{"old": me, "other device": other} {
		if r := h.do("GET", "/", nil, cookie(c)); r.StatusCode != 303 {
			t.Errorf("%s session survived password change", name)
		}
	}
	if r := h.do("GET", "/settings/security?ok=password-changed", nil, cookie(fresh)); !strings.Contains(bodyOf(t, r), "Password changed") {
		t.Error("flash missing")
	}
	if r := h.login(goodPassword, false); r.StatusCode != 401 {
		t.Error("old password still works")
	}

	second := sessionCookie(t, h.login(newPW, false))
	r = h.do("POST", "/settings/sessions/revoke", url.Values{"csrf": {h.csrf(fresh)}}, cookie(fresh))
	if r.StatusCode != 303 {
		t.Fatalf("revoke = %d", r.StatusCode)
	}
	if r := h.do("GET", "/", nil, cookie(second)); r.StatusCode != 303 {
		t.Error("other session survived revoke")
	}
	if r := h.do("GET", "/", nil, cookie(fresh)); r.StatusCode != 200 {
		t.Error("own session revoked")
	}
}

func TestEnvManagedPassword(t *testing.T) {
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "pw")
	_ = os.WriteFile(pwFile, []byte(goodPassword+"\n"), 0o600)
	h := newHarness(t, Config{}, auth.Bootstrap{PasswordFile: pwFile})
	if h.token != "" {
		t.Error("setup token issued although a password file is configured")
	}
	c := sessionCookie(t, h.login(goodPassword, false))
	b := bodyOf(t, h.do("GET", "/settings/security", nil, cookie(c)))
	if !strings.Contains(b, "TCMON_PASSWORD_FILE") || strings.Contains(b, `action="/settings/password"`) {
		t.Error("security page should say the password is env-managed")
	}

	ctx := context.Background()
	am := auth.NewManager(h.st, auth.Config{Params: fast})
	if _, err := am.Init(ctx, auth.Bootstrap{PlainPasswordSet: true}); err == nil || !strings.Contains(err.Error(), "docker inspect") {
		t.Errorf("plaintext env accepted: %v", err)
	}
	if _, err := am.Init(ctx, auth.Bootstrap{PasswordHash: "nope"}); err == nil {
		t.Error("invalid hash accepted")
	}
	weak := filepath.Join(dir, "weak")
	_ = os.WriteFile(weak, []byte("short"), 0o600)
	if _, err := am.Init(ctx, auth.Bootstrap{PasswordFile: weak}); err == nil {
		t.Error("weak password file accepted")
	}
	hash, _ := auth.Hash("another long passphrase", fast)
	hashFile := filepath.Join(dir, "hash")
	_ = os.WriteFile(hashFile, []byte(hash), 0o600)
	if _, err := am.Init(ctx, auth.Bootstrap{PasswordHashFile: hashFile}); err != nil {
		t.Fatal(err)
	}
	if _, err := am.ChangePassword(ctx, "another long passphrase", "x", "x", "", ""); err == nil {
		t.Error("env-managed password changed")
	}
	if r := h.login("another long passphrase", false); r.StatusCode != 303 {
		t.Errorf("hash from env not applied: %d", r.StatusCode)
	}
}

func TestCertificate(t *testing.T) {
	h := newHarness(t, Config{PublicHostnames: []string{"truenas.lan", "192.168.1.10"}}, auth.Bootstrap{})
	certs := h.srv.Certs()
	leaf := certs.Leaf()
	for _, name := range []string{"truenas.lan", "192.168.1.10", "localhost", "127.0.0.1"} {
		if err := leaf.VerifyHostname(name); err != nil {
			t.Errorf("certificate does not cover %s: %v", name, err)
		}
	}
	if fi, _ := os.Stat(filepath.Join(h.dir, "tls", "key.pem")); fi.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %o", fi.Mode().Perm())
	}
	if fp := certs.Fingerprint(); len(fp) != 95 || strings.Count(fp, ":") != 31 {
		t.Errorf("fingerprint = %q", fp)
	}
	if strings.Contains(string(certs.PEM()), "PRIVATE KEY") {
		t.Fatal("certificate download includes the key")
	}
	// Reloading keeps the certificate; near expiry it is renewed.
	again, err := NewAutoCert(filepath.Join(h.dir, "tls"), []string{"truenas.lan", "192.168.1.10"}, time.Now)
	if err != nil || again.Fingerprint() != certs.Fingerprint() {
		t.Errorf("reload regenerated the certificate: %v", err)
	}
	later, err := NewAutoCert(filepath.Join(h.dir, "tls"), []string{"truenas.lan", "192.168.1.10"},
		func() time.Time { return time.Now().Add(certValidity - 10*24*time.Hour) })
	if err != nil || later.Fingerprint() == certs.Fingerprint() {
		t.Errorf("certificate near expiry not renewed: %v", err)
	}
	newName, _ := NewAutoCert(filepath.Join(h.dir, "tls"), []string{"wc.home.arpa"}, time.Now)
	if newName.Leaf().VerifyHostname("wc.home.arpa") != nil {
		t.Error("new hostname not added")
	}

	if r := h.do("GET", "/settings/certificate.pem", nil); r.StatusCode != 303 {
		t.Error("certificate download without sign-in")
	}
	c := h.setup()
	r := h.do("GET", "/settings/certificate.pem", nil, cookie(c))
	if r.StatusCode != 200 || !strings.Contains(bodyOf(t, r), "BEGIN CERTIFICATE") {
		t.Errorf("download = %d", r.StatusCode)
	}
	if b := bodyOf(t, h.do("GET", "/about", nil, cookie(c))); !strings.Contains(b, newName.Fingerprint()[:20]) && !strings.Contains(b, "SHA-256") {
		t.Error("about page lacks the fingerprint")
	}
}

func TestTLSVersionsAndServe(t *testing.T) {
	h := newHarness(t, Config{}, auth.Bootstrap{})
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.srv.Serve(ctx, ln) }()
	addr := ln.Addr().String()
	pool := x509.NewCertPool()
	pool.AddCert(h.srv.Certs().Leaf())

	dial := func(maxV uint16) error {
		conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, ServerName: "localhost", MaxVersion: maxV, MinVersion: tls.VersionTLS12})
		if err == nil {
			_ = conn.Close()
		}
		return err
	}
	if err := dial(tls.VersionTLS12); err == nil {
		t.Error("TLS 1.2 accepted with the default TLS 1.3 minimum")
	}
	if err := dial(tls.VersionTLS13); err != nil {
		t.Errorf("TLS 1.3 refused: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13}}}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+addr+"/healthz", nil)
	req.Host = "localhost"
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz over TLS: %v %v", resp, err)
	}
	_ = resp.Body.Close()
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Serve: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	bad := []Config{
		{TLSMode: "maybe"},
		{TLSMode: TLSFile},
		{TLSMode: TLSOff},
		{TLSMinVersion: "1.1"},
	}
	for i, c := range bad {
		if err := c.Normalize(); err == nil {
			t.Errorf("bad config %d accepted", i)
		}
	}
	ok := Config{TLSMode: TLSOff, AllowInsecureHTTP: true}
	if err := ok.Normalize(); err != nil || ok.cookieName() != "tcmon_session" || ok.secureCookies() {
		t.Errorf("insecure http config: %v", err)
	}
	proxied := Config{TLSMode: TLSOff, TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}}
	if err := proxied.Normalize(); err != nil || proxied.cookieName() != "__Host-tcmon_session" {
		t.Errorf("proxied config: %v", err)
	}
	if p, err := ParsePrefixes("10.0.0.0/8, 192.168.1.5 ,fd00::/8"); err != nil || len(p) != 3 || p[1].Bits() != 32 {
		t.Errorf("ParsePrefixes = %v %v", p, err)
	}
	if _, err := ParsePrefixes("nope"); err == nil {
		t.Error("bad CIDR accepted")
	}
	// Plain HTTP shows a warning banner on every page.
	h := newHarness(t, Config{TLSMode: TLSOff, AllowInsecureHTTP: true}, auth.Bootstrap{})
	if b := bodyOf(t, h.do("GET", "/setup", nil)); !strings.Contains(b, "not encrypted") {
		t.Error("insecure banner missing")
	}
	if h.srv.Certs() != nil {
		t.Error("certificate created with TLS off")
	}
}

func TestLogSafe(t *testing.T) {
	if got := logSafe("/a\r\nFAKE log line"); strings.ContainsAny(got, "\r\n") {
		t.Errorf("logSafe kept line breaks: %q", got)
	}
	if got := logSafe(strings.Repeat("x", 500)); len(got) > 210 {
		t.Errorf("logSafe did not truncate: %d", len(got))
	}
}
