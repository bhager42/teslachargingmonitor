// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package gwsim simulates a Tesla Backup Gateway 2's local API for
// development and tests: the customer login, session tokens, a self-signed
// certificate that can change, and the read endpoints tcmon uses.
//
// Payload shapes and the starting values reproduce the owner's capture
// (testdata/fixtures/gateway/26.34.2, identifiers redacted). Energy
// counters and the battery level integrate the scenario's power flow over
// simulated time, so counter-delta code sees realistic numbers.
//
// The grid_status value of the outage scenario ("SystemIslandedActive") is
// from community reports, not yet observed on the owner's hardware.
//
//	POST /api/login/Basic   {"username":"customer","password":...}
//	GET  /api/status        (no login)
//	GET  /api/{meters/aggregates,system_status,system_status/soe,
//	          system_status/grid_status,operation,sitemaster,site_info,solars}
//	GET  /_sim              current scenario and counters
//	POST /_sim/scenario     form field "name": switch scenario
//
// The control endpoints are unauthenticated; bind the simulator to loopback.
package gwsim

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"
)

// Scenario is a steady power flow plus behavior switches. Power is in watts
// with the Gateway's signs: Site < 0 exports, Battery < 0 charges.
type Scenario struct {
	Name        string
	Description string
	Solar       float64
	Load        float64 // home including the car
	Battery     float64
	// GridStatus is the grid_status string; "" means SystemGridConnected.
	GridStatus string
	// StartSOE, when non-zero, sets the raw battery percentage on switch.
	StartSOE float64
	// Behaviors.
	RejectLogin bool // every login gets 401
	RateLimit   bool // every login gets 429
	AltCert     bool // serve the second certificate
	Malformed   bool // /api/meters/aggregates returns broken JSON
}

// Site returns the grid power implied by the flow: load = solar + battery + site.
func (s Scenario) Site() float64 {
	if s.GridStatus != "" && s.GridStatus != gridConnected {
		return 0
	}
	return s.Load - s.Solar - s.Battery
}

const (
	gridConnected = "SystemGridConnected"
	gridIslanded  = "SystemIslandedActive" // community-reported; unverified
)

var scenarios = []Scenario{
	{Name: "sunny", Description: "midday sun: solar covers the home, charges the Powerwalls and exports", Solar: 6200, Load: 1500, Battery: -3200},
	{Name: "day", Description: "the owner's capture: solar 3.7 kW, home 2.4 kW, Powerwalls charging", Solar: 3730, Load: 2380, Battery: -1290},
	{Name: "cloudy", Description: "overcast: little solar, grid makes up the rest", Solar: 600, Load: 1500, Battery: 0},
	{Name: "charging", Description: "sunny with the car charging at 7.6 kW on the home load", Solar: 6000, Load: 9100, Battery: 0},
	{Name: "night", Description: "dark: the Powerwalls run the home", Solar: 0, Load: 1100, Battery: 1100},
	{Name: "outage", Description: "grid down: islanded, the Powerwalls and solar run the home", Solar: 0, Load: 1300, Battery: 1300, GridStatus: gridIslanded},
	{Name: "battery-low", Description: "night with the Powerwalls nearly empty (raw 12 %)", Solar: 0, Load: 900, Battery: 600, StartSOE: 12},
	{Name: "login-rejected", Description: "every login is rejected with 401", Solar: 3730, Load: 2380, Battery: -1290, RejectLogin: true},
	{Name: "rate-limited", Description: "every login is answered with 429", Solar: 3730, Load: 2380, Battery: -1290, RateLimit: true},
	{Name: "cert-changed", Description: "the Gateway presents a different certificate", Solar: 3730, Load: 2380, Battery: -1290, AltCert: true},
	{Name: "malformed", Description: "meters/aggregates returns broken JSON", Solar: 3730, Load: 2380, Battery: -1290, Malformed: true},
}

// Scenarios lists the available scenarios.
func Scenarios() []Scenario { return slices.Clone(scenarios) }

// Lookup finds a scenario by name.
func Lookup(name string) (Scenario, bool) {
	i := slices.IndexFunc(scenarios, func(s Scenario) bool { return s.Name == name })
	if i < 0 {
		return Scenario{}, false
	}
	return scenarios[i], true
}

// Options configures a Server.
type Options struct {
	Scenario string           // default "day"
	Password string           // the customer password; default "SIMPW"
	Speed    float64          // simulated seconds per real second; default 1
	Now      func() time.Time // clock; default time.Now
}

// counters are lifetime watt-hours, starting from the owner's capture.
type counters struct {
	SiteImp, SiteExp, BattImp, BattExp, LoadImp, SolarExp float64
	Remaining                                             [2]float64 // per block, Wh
}

var fullPack = [2]float64{13341, 13876}

// Server is the simulated Gateway. Use it as an http.Handler with
// TLSConfig, e.g. httptest.NewUnstartedServer(s) with srv.TLS = s.TLSConfig().
type Server struct {
	mu       sync.Mutex
	scenario Scenario
	password string
	speed    float64
	now      func() time.Time
	last     time.Time
	c        counters
	tokens   map[string]bool
	logins   int
	certs    [2]tls.Certificate
}

// NewServer returns a simulator with two fresh self-signed certificates.
func NewServer(opts Options) (*Server, error) {
	if opts.Scenario == "" {
		opts.Scenario = "day"
	}
	sc, ok := Lookup(opts.Scenario)
	if !ok {
		return nil, fmt.Errorf("gwsim: unknown scenario %q", opts.Scenario)
	}
	if opts.Password == "" {
		opts.Password = "SIMPW"
	}
	if opts.Speed <= 0 {
		opts.Speed = 1
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	s := &Server{
		password: opts.Password, speed: opts.Speed, now: opts.Now, last: opts.Now(),
		tokens: map[string]bool{},
		c: counters{
			SiteImp: 216018884.35, SiteExp: 1890463.38, BattImp: 9368416, BattExp: 7673944,
			LoadImp: 259411712.96, SolarExp: 46977764, Remaining: [2]float64{4684, 4849},
		},
	}
	for i := range s.certs {
		c, err := selfSigned()
		if err != nil {
			return nil, err
		}
		s.certs[i] = c
	}
	s.switchLocked(sc)
	return s, nil
}

func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "teg"},
		DNSNames:     []string{"teg", "powerwall"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// TLSConfig serves the current certificate (the second one in the
// cert-changed scenario). It uses GetConfigForClient rather than
// GetCertificate, which crypto/tls skips for clients without SNI (an IP
// address) whenever Certificates is set, as httptest does.
func (s *Server) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{s.certs[s.certIndexLocked()]}}, nil
		},
	}
}

func (s *Server) certIndexLocked() int {
	if s.scenario.AltCert {
		return 1
	}
	return 0
}

// Fingerprint returns the hex SHA-256 of the certificate the server
// presents now.
func (s *Server) Fingerprint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	sum := sha256.Sum256(s.certs[s.certIndexLocked()].Certificate[0])
	return hex.EncodeToString(sum[:])
}

// SetScenario switches scenario. Sessions stay valid.
func (s *Server) SetScenario(name string) error {
	sc, ok := Lookup(name)
	if !ok {
		return fmt.Errorf("gwsim: unknown scenario %q", name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.advanceLocked()
	s.switchLocked(sc)
	return nil
}

func (s *Server) switchLocked(sc Scenario) {
	s.scenario = sc
	if sc.StartSOE > 0 {
		for i := range s.c.Remaining {
			s.c.Remaining[i] = fullPack[i] * sc.StartSOE / 100
		}
	}
}

// Logins returns how many login attempts the server has received.
func (s *Server) Logins() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins
}

// ExpireSessions invalidates every token, as a Gateway restart would.
func (s *Server) ExpireSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.tokens)
}

// advanceLocked integrates the power flow since the last call.
func (s *Server) advanceLocked() {
	now := s.now()
	h := now.Sub(s.last).Hours() * s.speed
	s.last = now
	if h <= 0 {
		return
	}
	sc := s.scenario
	if site := sc.Site(); site >= 0 {
		s.c.SiteImp += site * h
	} else {
		s.c.SiteExp += -site * h
	}
	// Battery power is limited by what the Powerwalls hold.
	batt := sc.Battery
	total := s.c.Remaining[0] + s.c.Remaining[1]
	full := fullPack[0] + fullPack[1]
	switch {
	case batt > 0 && total <= 0, batt < 0 && total >= full:
		batt = 0
	}
	if batt >= 0 {
		s.c.BattExp += batt * h
	} else {
		s.c.BattImp += -batt * h
	}
	for i := range s.c.Remaining {
		share := fullPack[i] / full
		s.c.Remaining[i] = math.Max(0, math.Min(fullPack[i], s.c.Remaining[i]-batt*share*h))
	}
	s.c.LoadImp += sc.Load * h
	s.c.SolarExp += sc.Solar * h
}

func (s *Server) soeLocked() float64 {
	return 100 * (s.c.Remaining[0] + s.c.Remaining[1]) / (fullPack[0] + fullPack[1])
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.advanceLocked()
	switch {
	case r.URL.Path == "/_sim" && r.Method == http.MethodGet:
		writeJSON(w, map[string]any{"scenario": s.scenario.Name, "logins": s.logins, "counters": s.c, "soe": s.soeLocked()})
		return
	case r.URL.Path == "/_sim/scenario" && r.Method == http.MethodPost:
		sc, ok := Lookup(r.FormValue("name"))
		if !ok {
			http.Error(w, "unknown scenario", http.StatusBadRequest)
			return
		}
		s.switchLocked(sc)
		w.WriteHeader(http.StatusNoContent)
		return
	case r.URL.Path == "/api/login/Basic":
		s.login(w, r)
		return
	case r.URL.Path == "/api/status" && r.Method == http.MethodGet:
		writeJSON(w, s.status())
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, ok := s.payloadLocked(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	tok, found := cutBearer(r.Header.Get("Authorization"))
	if !found || !s.tokens[tok] {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":403,"error":"Unable to GET to resource","message":"User does not have adequate access rights"}`))
		return
	}
	if raw, isRaw := body.(rawBody); isRaw {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
		return
	}
	writeJSON(w, body)
}

type rawBody []byte

func cutBearer(h string) (string, bool) {
	const p = "Bearer "
	if len(h) <= len(p) || h[:len(p)] != p {
		return "", false
	}
	return h[len(p):], true
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.logins++
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)
	switch {
	case s.scenario.RateLimit:
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"code":429,"error":"Too Many Requests","message":"Your request was rate limited"}`))
		return
	case s.scenario.RejectLogin, req.Username != "customer",
		subtle.ConstantTimeCompare([]byte(req.Password), []byte(s.password)) != 1:
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":401,"error":"bad credentials","message":"Login Error"}`))
		return
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	s.tokens[tok] = true
	writeJSON(w, map[string]any{
		"email": "tcmon@example.com", "firstname": "Tesla", "lastname": "Energy",
		"roles": []string{"Home_Owner"}, "token": tok, "provider": "Basic",
		"loginTime": s.now().Format(time.RFC3339Nano),
	})
}

func (s *Server) status() map[string]any {
	return map[string]any{
		"can_reboot": false, "cellular_disabled": false, "commission_count": 0,
		"device_type": "teg", "din": "REDACTED", "git_hash": "56d7ba064772ad6d740825723c7e9c8524cd31b1",
		"is_new": false, "start_time": "2026-10-29 21:05:46 +0800", "sync_type": "v2.1", "teg_type": "unknown",
		"up_time_seconds": (420*time.Hour + 27*time.Minute + 56*time.Second).String(),
		"version":         "26.34.2 56d7ba06",
	}
}

func meter(power, imp, exp float64, aggregated int) map[string]any {
	m := map[string]any{
		"energy_exported": exp, "energy_imported": imp, "frequency": 0,
		"i_a_current": 0, "i_b_current": 0, "i_c_current": 0,
		"instant_apparent_power": math.Abs(power), "instant_average_current": 0,
		"instant_average_voltage": 122.2, "instant_power": power, "instant_reactive_power": 0,
		"instant_total_current": 0, "last_communication_time": "2026-11-16T08:33:53.815783-05:00",
		"last_phase_energy_communication_time":  "0001-01-01T00:00:00Z",
		"last_phase_power_communication_time":   "2026-11-16T08:33:53.815783-05:00",
		"last_phase_voltage_communication_time": "2026-11-16T08:33:53.735526-05:00",
		"timeout":                               1500000000,
	}
	if aggregated > 0 {
		m["num_meters_aggregated"] = aggregated
	}
	return m
}

func (s *Server) payloadLocked(path string) (any, bool) {
	sc := s.scenario
	grid := sc.GridStatus
	if grid == "" {
		grid = gridConnected
	}
	switch path {
	case "/api/meters/aggregates":
		if sc.Malformed {
			return rawBody(`{"site":{"instant_power":`), true
		}
		return map[string]any{
			"site":    meter(sc.Site(), s.c.SiteImp, s.c.SiteExp, 1),
			"battery": meter(sc.Battery, s.c.BattImp, s.c.BattExp, 2),
			"load":    meter(sc.Load, s.c.LoadImp, 0, 0),
			"solar":   meter(sc.Solar, 0, s.c.SolarExp, 1),
		}, true
	case "/api/system_status/soe":
		return map[string]any{"percentage": s.soeLocked()}, true
	case "/api/system_status/grid_status":
		return map[string]any{"grid_status": grid, "grid_services_active": false}, true
	case "/api/system_status":
		blocks := make([]map[string]any, 2)
		parts := [2]string{"3012170-25-B", "2012170-05-E"}
		for i := range blocks {
			share := fullPack[i] / (fullPack[0] + fullPack[1])
			blocks[i] = map[string]any{
				"Manufacturer": "", "OpSeqState": "Active", "PackagePartNumber": parts[i],
				"PackageSerialNumber": "REDACTED", "Type": "", "backup_ready": true,
				"charge_power_clamped": false, "disabled_reasons": []any{},
				"energy_charged": s.c.BattImp * share, "energy_discharged": s.c.BattExp * share,
				"f_out": 60.0, "i_out": 0, "nominal_energy_remaining": s.c.Remaining[i],
				"nominal_full_pack_energy": fullPack[i], "off_grid": grid != gridConnected,
				"p_out": sc.Battery * share, "pinv_grid_state": "Grid_Compliant",
				"pinv_state": "PINV_GridFollowing", "q_out": 0, "v_out": 245.0,
				"version": "56d7ba064772ad", "vf_mode": false, "wobble_detected": false,
			}
		}
		return map[string]any{
			"available_blocks": 2, "battery_blocks": blocks, "can_reboot": "Solar production hours",
			"grid_faults": []any{}, "max_charge_power": 11600, "max_discharge_power": 11600,
			"nominal_energy_remaining": s.c.Remaining[0] + s.c.Remaining[1],
			"nominal_full_pack_energy": fullPack[0] + fullPack[1], "system_island_state": grid,
		}, true
	case "/api/operation":
		return map[string]any{
			"backup_reserve_percent": 33.5, "freq_shift_load_shed_delta_f": -0.32,
			"freq_shift_load_shed_soe": 75, "real_mode": "self_consumption",
		}, true
	case "/api/sitemaster":
		return map[string]any{
			"can_reboot": "Solar production hours", "connected_to_tesla": false,
			"power_supply_mode": false, "running": true, "status": "StatusUp",
		}, true
	case "/api/site_info":
		return map[string]any{
			"grid_code":               map[string]any{"country": "REDACTED", "grid_code": "REDACTED", "utility": "REDACTED"},
			"max_site_meter_power_kW": 1000000000, "max_system_energy_kWh": 27, "max_system_power_kW": 12.68,
			"min_site_meter_power_kW": -1000000000, "nominal_system_energy_kWh": 27,
			"nominal_system_power_kW": 12.68, "panel_max_current": 100, "site_name": "REDACTED",
			"timezone": "America/New_York",
		}, true
	case "/api/solars":
		return []map[string]any{{"brand": "Tesla", "model": "Solar Inverter 7.6", "power_rating_watts": 7600}}, true
	}
	return nil, false
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
