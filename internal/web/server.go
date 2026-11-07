// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package web serves the HTTPS web UI: TLS (self-signed by default), the
// single-password login, sessions, CSRF protection, LAN-only access and the
// security headers from docs/DEVELOPMENT_PLAN.md §10.
package web

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"maps"
	"mime"
	"net"
	"net/http"
	"path"
	"path/filepath"
	"strconv"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/alerts"
	"github.com/bhager42/teslachargingmonitor/internal/auth"
	"github.com/bhager42/teslachargingmonitor/internal/heartbeat"
	"github.com/bhager42/teslachargingmonitor/internal/i18n"
	"github.com/bhager42/teslachargingmonitor/internal/notify"
	"github.com/bhager42/teslachargingmonitor/internal/store"
	webui "github.com/bhager42/teslachargingmonitor/web"
)

func init() {
	// Not in every platform's MIME table; module scripts must be JavaScript.
	_ = mime.AddExtensionType(".webmanifest", "application/manifest+json")
	_ = mime.AddExtensionType(".mjs", "text/javascript; charset=utf-8")
}

// Server is the web UI server.
type Server struct {
	cfg   Config
	st    *store.Store
	auth  *auth.Manager
	certs *CertSource // nil when TLS is off
	log   *slog.Logger
	now   func() time.Time

	alerts *alerts.Engine     // optional in tests
	notify *notify.Dispatcher // optional in tests
	poll   PollControl        // optional in tests
	beat   *heartbeat.Pinger  // optional in tests
	hub    *Hub

	pages     map[string]*template.Template
	assetHash map[string]string
	handler   http.Handler
}

// Options are the Server's collaborators.
type Options struct {
	Store  *store.Store
	Auth   *auth.Manager
	Logger *slog.Logger
	Now    func() time.Time
	Alerts *alerts.Engine
	Notify *notify.Dispatcher
	Poll   PollControl
	// Heartbeat is the dead-man's-switch pinger (optional).
	Heartbeat *heartbeat.Pinger
	Hub       *Hub
}

// New validates cfg, prepares the certificate and builds the handler.
func New(cfg Config, o Options) (*Server, error) {
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Hub == nil {
		o.Hub = NewHub()
	}
	s := &Server{cfg: cfg, st: o.Store, auth: o.Auth, log: o.Logger, now: o.Now, alerts: o.Alerts, notify: o.Notify,
		poll: o.Poll, beat: o.Heartbeat, hub: o.Hub}
	var err error
	switch cfg.TLSMode {
	case TLSAuto:
		s.certs, err = NewAutoCert(filepath.Join(cfg.DataDir, "tls"), cfg.PublicHostnames, o.Now)
	case TLSFile:
		s.certs, err = NewFileCert(cfg.TLSCertFile, cfg.TLSKeyFile)
	}
	if err != nil {
		return nil, err
	}
	if err := s.loadAssets(); err != nil {
		return nil, err
	}
	s.handler = s.routes()
	return s, nil
}

// Handler returns the complete middleware chain (for tests).
func (s *Server) Handler() http.Handler { return s.handler }

// Certs returns the certificate source (nil when TLS is off).
func (s *Server) Certs() *CertSource { return s.certs }

// tr is the message catalog for user-facing text (ADR 0006). English is the
// only language, so one catalog serves every request.
var tr = i18n.English()

func (s *Server) loadAssets() error {
	s.assetHash = map[string]string{}
	err := fs.WalkDir(webui.Static, "static", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := webui.Static.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		s.assetHash[path[len("static/"):]] = hex.EncodeToString(sum[:8])
		return nil
	})
	if err != nil {
		return err
	}
	funcs := template.FuncMap{
		"asset": func(name string) (string, error) {
			h, ok := s.assetHash[name]
			if !ok {
				return "", fmt.Errorf("unknown asset %q", name)
			}
			return "/static/" + name + "?v=" + h, nil
		},
		"field": func(m map[string]string, k string) string { return m[k] },
		"ago": func(t *time.Time) string {
			if t == nil {
				return "never"
			}
			return fmtAgo(*t, s.now())
		},
		"mins": func(d time.Duration) int { return int(d.Minutes()) },
		"eq":   func(a, b any) bool { return a == b },
		"num":  func(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) },
		// Display names for stored severity, alert kind and delivery status names.
		"severity":  severityLabel,
		"alertkind": alerts.KindLabel,
		"delivery":  deliveryLabel,
	}
	maps.Copy(funcs, tr.Funcs())
	s.pages = map[string]*template.Template{}
	for _, p := range []string{"login", "setup", "setup_closed", "home", "security", "about", "error", "device",
		"devices", "device_form", "alerts", "rule", "notifications", "channel", "settings", "diagnostics", "costs", "energy", "digest"} {
		t, err := template.New(p).Funcs(funcs).ParseFS(webui.Templates, "templates/layout.html", "templates/"+p+".html")
		if err != nil {
			return fmt.Errorf("web: parsing %s template: %w", p, err)
		}
		s.pages[p] = t
	}
	return nil
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.Handle("GET /static/", s.static())
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("GET /setup", s.setupPage)
	mux.HandleFunc("POST /setup", s.setupSubmit)
	mux.Handle("POST /logout", s.authed(s.logout))
	mux.Handle("GET /{$}", s.authed(s.home))
	mux.Handle("GET /events", s.authed(s.events))
	mux.Handle("GET /devices/{id}", s.authed(s.deviceDetail))
	mux.Handle("GET /devices/{id}/export.csv", s.authed(s.exportCSV))
	mux.Handle("POST /devices/{id}/poll", s.authed(s.pollNow))
	mux.Handle("GET /api/devices/{id}/series", s.authed(s.series))
	mux.Handle("GET /settings/devices", s.authed(s.devicesPage))
	mux.Handle("GET /settings/devices/new", s.authed(s.newDeviceForm))
	mux.Handle("POST /settings/devices/new", s.authed(s.saveDevice))
	mux.Handle("GET /settings/devices/{id}", s.authed(s.editDeviceForm))
	mux.Handle("POST /settings/devices/{id}", s.authed(s.saveDevice))
	mux.Handle("POST /settings/devices/{id}/delete", s.authed(s.deleteDevice))
	mux.Handle("GET /alerts", s.authed(s.alertsPage))
	mux.Handle("POST /alerts/events/{id}/ack", s.authed(s.ackAlert))
	mux.Handle("POST /alerts/snooze", s.authed(s.snooze))
	mux.Handle("POST /alerts/snooze/{id}/end", s.authed(s.unsnooze))
	mux.Handle("GET /alerts/rules/{key}", s.authed(s.ruleForm))
	mux.Handle("POST /alerts/rules/{key}", s.authed(s.saveRule))
	mux.Handle("GET /notifications", s.authed(s.notificationsPage))
	mux.Handle("GET /notifications/new", s.authed(s.newChannel))
	mux.Handle("GET /notifications/digest", s.authed(s.digestPreview))
	mux.Handle("POST /notifications/{id}/digest", s.authed(s.sendDigest))
	mux.Handle("POST /notifications/new", s.authed(s.saveChannel))
	mux.Handle("GET /notifications/{id}", s.authed(s.editChannel))
	mux.Handle("POST /notifications/{id}", s.authed(s.saveChannel))
	mux.Handle("POST /notifications/{id}/test", s.authed(s.testChannel))
	mux.Handle("POST /notifications/{id}/delete", s.authed(s.deleteChannel))
	mux.Handle("GET /settings", s.authed(s.settingsPage))
	mux.Handle("POST /settings", s.authed(s.saveSettings))
	mux.Handle("POST /settings/backup", s.authed(s.backup))
	mux.Handle("POST /settings/heartbeat", s.authed(s.saveHeartbeat))
	mux.Handle("GET /diagnostics", s.authed(s.diagnostics))
	mux.Handle("GET /costs", s.authed(s.costsPage))
	mux.Handle("GET /costs/{kind}", s.authed(s.costsCSV))
	mux.Handle("GET /settings/energy", s.authed(s.energyPage))
	mux.Handle("POST /settings/energy", s.authed(s.saveEnergy))
	mux.Handle("POST /settings/energy/{id}/delete", s.authed(s.deleteRate))
	mux.Handle("GET /about", s.authed(s.about))
	mux.Handle("GET /settings/security", s.authed(s.securityPage))
	mux.Handle("POST /settings/password", s.authed(s.changePassword))
	mux.Handle("POST /settings/sessions/revoke", s.authed(s.revokeSessions))
	mux.Handle("GET /settings/certificate.pem", s.authed(s.certificate))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.renderError(w, r, http.StatusNotFound, tr.T("error.not_found_title"), tr.T("error.not_found"))
	})

	cop := http.NewCrossOriginProtection()
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.renderError(w, r, http.StatusForbidden, tr.T("error.blocked_title"),
			tr.T("error.cross_origin"))
	}))
	var h http.Handler = mux
	h = cop.Handler(h)
	h = limitBody(h)
	h = s.securityHeaders(h)
	h = s.hostCheck(h)
	h = s.logRequests(h)
	h = s.lanOnly(h)
	return h
}

func (s *Server) static() http.Handler {
	sub, _ := fs.Sub(webui.Static, "static")
	files := http.FileServerFS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path[len("/static/"):]
		// Serve files only: http.FileServer would list directories (ASVS V13.4.3).
		if fi, err := fs.Stat(sub, path.Clean("/" + name)[1:]); err != nil || fi.IsDir() {
			s.renderError(w, r, http.StatusNotFound, tr.T("error.not_found_title"), tr.T("error.not_found"))
			return
		}
		if want, ok := s.assetHash[name]; ok && r.URL.Query().Get("v") == want {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		http.StripPrefix("/static/", files).ServeHTTP(w, r)
	})
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if _, err := s.st.SchemaVersion(r.Context()); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ready\n"))
}

func (s *Server) tlsConfig() *tls.Config {
	minV := uint16(tls.VersionTLS13)
	if s.cfg.TLSMinVersion == "1.2" {
		minV = tls.VersionTLS12
	}
	// Go's defaults include the hybrid post-quantum X25519MLKEM768 group.
	return &tls.Config{MinVersion: minV, GetCertificate: s.certs.GetCertificate}
}

// Run serves until ctx is canceled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("web: listening on %s: %w", s.cfg.Listen, err)
	}
	return s.Serve(ctx, ln)
}

// Serve serves on an existing listener (tests).
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug), // TLS handshake noise
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	scheme := "http"
	if s.certs != nil {
		srv.TLSConfig = s.tlsConfig()
		ln = tls.NewListener(ln, srv.TLSConfig)
		scheme = "https"
		s.log.Info("HTTPS certificate", "self_signed", s.certs.SelfSigned(), "sha256", s.certs.Fingerprint(),
			"not_after", s.certs.Leaf().NotAfter.Format(time.DateOnly))
		go s.renewLoop(ctx)
	} else {
		s.log.Warn("serving plain HTTP; TLS must be terminated by a trusted proxy", "insecure_allowed", s.cfg.AllowInsecureHTTP)
	}
	s.log.Info("web UI listening", "url", fmt.Sprintf("%s://<this-host>%s", scheme, portOf(ln.Addr().String())))
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx) //nolint:contextcheck // parent is already canceled
	}
}

func portOf(addr string) string {
	if _, p, err := net.SplitHostPort(addr); err == nil {
		return ":" + p
	}
	return ""
}

func (s *Server) renewLoop(ctx context.Context) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			before := s.certs.Fingerprint()
			if err := s.certs.Renew(); err != nil {
				s.log.Error("renewing TLS certificate", "err", err)
			} else if after := s.certs.Fingerprint(); after != before {
				s.log.Warn("HTTPS certificate renewed; browsers will warn once again", "sha256", after)
			}
		}
	}
}
