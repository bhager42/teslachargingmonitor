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
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

type ctxKey int

const clientIPKey ctxKey = iota

// clientIP returns the address resolved by the clientIP middleware.
func clientIP(r *http.Request) netip.Addr {
	ip, _ := r.Context().Value(clientIPKey).(netip.Addr)
	return ip
}

func contains(list []netip.Prefix, ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range list {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// resolveClientIP uses X-Forwarded-For only when the direct peer is a
// trusted proxy, taking the right-most address that is not itself trusted.
func (s *Server) resolveClientIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	peer = peer.Unmap()
	if !contains(s.cfg.TrustedProxies, peer) {
		return peer
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return peer
		}
		if !contains(s.cfg.TrustedProxies, a) {
			return a.Unmap()
		}
	}
	return peer
}

// lanOnly rejects clients outside the allowed ranges before anything else
// (owner decision D12: LAN only).
func (s *Server) lanOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := s.resolveClientIP(r)
		if !ip.IsValid() || !contains(s.cfg.AllowedClients, ip) {
			s.log.Warn("rejected client outside allowed networks", "ip", ip.String())
			http.Error(w, tr.T("error.lan_only"), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientIPKey, ip)))
	})
}

// hostCheck defeats DNS rebinding: the Host header must be an IP literal,
// localhost, or one of TCMON_PUBLIC_HOSTNAMES.
func (s *Server) hostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
		ok := host == "localhost"
		if _, err := netip.ParseAddr(host); err == nil {
			ok = true
		}
		for _, h := range s.cfg.PublicHostnames {
			ok = ok || host == h
		}
		if !ok {
			http.Error(w, tr.T("error.misdirected"), http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; " +
	"connect-src 'self'; manifest-src 'self'; worker-src 'self'; form-action 'self'; frame-ancestors 'none'; " +
	"base-uri 'none'; require-trusted-types-for 'script'; trusted-types tcmon"

// securityHeaders sets the plan §10 response headers on every response.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		policy := csp
		if s.cfg.secureCookies() {
			policy += "; upgrade-insecure-requests"
		}
		h.Set("Content-Security-Policy", policy)
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Embedder-Policy", "require-corp")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=(), payment=(), "+
			"interest-cohort=(), browsing-topics=()")
		if s.cfg.HSTS && s.cfg.TLSMode != TLSOff {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			h.Set("Cache-Control", "no-store, no-cache, must-revalidate")
		}
		next.ServeHTTP(w, r)
	})
}

// limitBody caps request bodies (forms are tiny).
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		next.ServeHTTP(w, r)
	})
}

// logSafe strips line breaks and truncates request-controlled text before
// it is logged, so a crafted URL cannot forge log entries.
func logSafe(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// logRequests logs method, path (no query string), status and duration.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if p := recover(); p != nil {
				if p == http.ErrAbortHandler { //nolint:errorlint // sentinel compared by identity, as net/http does
					panic(p)
				}
				s.log.Error("panic serving request", "path", logSafe(r.URL.Path), "panic", p)
				http.Error(sw, tr.T("error.internal"), http.StatusInternalServerError)
			}
			level := slog.LevelDebug
			if sw.status >= 400 {
				level = slog.LevelInfo
			}
			s.log.Log(r.Context(), level, "http", "method", logSafe(r.Method), "path", logSafe(r.URL.Path), "status", sw.status,
				"ms", time.Since(start).Milliseconds(), "ip", clientIP(r).String())
		}()
		next.ServeHTTP(sw, r)
	})
}
