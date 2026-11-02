// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package wcsim

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Server serves the simulated API:
//
//	GET  /api/1/{vitals,lifetime,wifi_status,version}
//	GET  /_sim               current scenario, elapsed time, scenario list
//	POST /_sim/scenario      form field "name": switch scenario, reset clock
//
// The control endpoints are unauthenticated; bind the simulator to loopback.
type Server struct {
	mu       sync.Mutex
	scenario Scenario
	start    time.Time
	speed    float64
	now      func() time.Time
	// SlowDelay is how long the "slow" scenario waits before answering.
	SlowDelay time.Duration
}

// Options configures a Server.
type Options struct {
	Scenario string           // default "idle"
	Speed    float64          // simulated seconds per real second; default 1
	Now      func() time.Time // clock; default time.Now
}

// NewServer returns a simulator.
func NewServer(opts Options) (*Server, error) {
	if opts.Scenario == "" {
		opts.Scenario = "idle"
	}
	sc, ok := Lookup(opts.Scenario)
	if !ok {
		return nil, fmt.Errorf("wcsim: unknown scenario %q", opts.Scenario)
	}
	if opts.Speed <= 0 {
		opts.Speed = 1
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Server{scenario: sc, start: opts.Now(), speed: opts.Speed, now: opts.Now, SlowDelay: 10 * time.Second}, nil
}

// Elapsed returns simulated time since the scenario started.
func (s *Server) Elapsed() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.elapsedLocked()
}

func (s *Server) elapsedLocked() time.Duration {
	return time.Duration(float64(s.now().Sub(s.start)) * s.speed)
}

// SetScenario switches scenario and restarts the simulated clock.
func (s *Server) SetScenario(name string) error {
	sc, ok := Lookup(name)
	if !ok {
		return fmt.Errorf("wcsim: unknown scenario %q", name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scenario, s.start = sc, s.now()
	return nil
}

// Current returns the active scenario's state and behavior.
func (s *Server) Current() (Scenario, State, Behavior) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, b := s.scenario.State(s.elapsedLocked())
	return s.scenario, st, b
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/_sim" && r.Method == http.MethodGet:
		s.serveStatus(w)
	case r.URL.Path == "/_sim/scenario" && r.Method == http.MethodPost:
		if err := s.SetScenario(r.FormValue("name")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.serveStatus(w)
	case r.Method == http.MethodGet:
		s.serveAPI(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	_, st, behavior := s.Current()
	var body any
	switch r.URL.Path {
	case "/api/1/vitals":
		body = st.Vitals
	case "/api/1/lifetime":
		body = st.Lifetime
	case "/api/1/wifi_status":
		body = st.WifiStatus
	case "/api/1/version":
		body = st.Version
	default:
		http.NotFound(w, r)
		return
	}
	switch behavior {
	case Offline:
		panic(http.ErrAbortHandler) // drops the connection, no response
	case Slow:
		select {
		case <-time.After(s.SlowDelay):
		case <-r.Context().Done():
			return
		}
	case Malformed:
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"grid_v": 240.1, "handle_temp_c": `))
		return
	case Normal:
	}
	writeJSON(w, body)
}

type scenarioInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Provisional bool   `json:"provisional"`
}

func (s *Server) serveStatus(w http.ResponseWriter) {
	sc, _, _ := s.Current()
	list := make([]scenarioInfo, 0, len(scenarios))
	for _, x := range scenarios {
		list = append(list, scenarioInfo{x.Name, x.Description, x.Provisional})
	}
	writeJSON(w, map[string]any{
		"scenario":        sc.Name,
		"elapsed_seconds": int64(s.Elapsed().Seconds()),
		"scenarios":       list,
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "encoding error", http.StatusInternalServerError)
	}
}
