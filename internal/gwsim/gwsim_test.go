// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package gwsim

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/gateway/redact"
)

func TestScenariosBalance(t *testing.T) {
	for _, sc := range Scenarios() {
		site := sc.Site()
		if sc.GridStatus == "" && math.Abs(sc.Solar+sc.Battery+site-sc.Load) > 1e-9 {
			t.Errorf("%s: power does not balance", sc.Name)
		}
		if sc.GridStatus != "" && site != 0 {
			t.Errorf("%s: islanded but site = %g", sc.Name, site)
		}
		if sc.GridStatus != "" && math.Abs(sc.Solar+sc.Battery-sc.Load) > 1e-9 {
			t.Errorf("%s: islanded flow does not balance", sc.Name)
		}
	}
	if _, err := NewServer(Options{Scenario: "nope"}); err == nil {
		t.Error("unknown scenario accepted")
	}
}

func TestLoginAndAuthorization(t *testing.T) {
	s, err := NewServer(Options{Now: func() time.Time { return time.Unix(0, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	get := func(path, tok string) int {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}
	login := func(pw string) (int, string) {
		r := httptest.NewRequest(http.MethodPost, "/api/login/Basic", strings.NewReader(`{"username":"customer","password":"`+pw+`"}`))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		var resp struct{ Token string }
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return w.Code, resp.Token
	}
	if get("/api/status", "") != http.StatusOK {
		t.Error("/api/status should not need a login")
	}
	if get("/api/meters/aggregates", "") != http.StatusForbidden {
		t.Error("aggregates without a token should be 403")
	}
	if code, _ := login("nope"); code != http.StatusUnauthorized {
		t.Errorf("bad password: %d", code)
	}
	code, tok := login("SIMPW")
	if code != http.StatusOK || tok == "" {
		t.Fatalf("login: %d %q", code, tok)
	}
	if get("/api/meters/aggregates", tok) != http.StatusOK || get("/api/nope", tok) != http.StatusNotFound {
		t.Error("authorized requests")
	}
	s.ExpireSessions()
	if get("/api/meters/aggregates", tok) != http.StatusForbidden {
		t.Error("expired token still accepted")
	}
	if s.Logins() != 2 {
		t.Errorf("logins = %d", s.Logins())
	}
}

// Everything the simulator serves must pass the same redaction check as
// committed fixtures, so it can never be mistaken for a real capture.
func TestPayloadsAreRedacted(t *testing.T) {
	s, err := NewServer(Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/api/meters/aggregates", "/api/system_status", "/api/system_status/soe",
		"/api/system_status/grid_status", "/api/operation", "/api/sitemaster", "/api/site_info", "/api/solars"} {
		body, ok := s.payloadLocked(p)
		if !ok {
			t.Fatalf("%s: no payload", p)
		}
		b, _ := json.Marshal(body)
		var v any
		_ = json.Unmarshal(b, &v)
		if probs := redact.Check(v); len(probs) != 0 {
			t.Errorf("%s: %v", p, probs)
		}
	}
	var st any
	b, _ := json.Marshal(s.status())
	_ = json.Unmarshal(b, &st)
	if probs := redact.Check(st); len(probs) != 0 {
		t.Errorf("/api/status: %v", probs)
	}
}

func TestControlEndpoints(t *testing.T) {
	s, err := NewServer(Options{})
	if err != nil {
		t.Fatal(err)
	}
	fp := s.Fingerprint()
	r := httptest.NewRequest(http.MethodPost, "/_sim/scenario", strings.NewReader(url.Values{"name": {"cert-changed"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent || s.Fingerprint() == fp {
		t.Errorf("switch to cert-changed: %d, fingerprint changed %v", w.Code, s.Fingerprint() != fp)
	}
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/_sim", nil))
	if !strings.Contains(w.Body.String(), `"scenario":"cert-changed"`) {
		t.Errorf("/_sim = %s", w.Body.String())
	}
}
