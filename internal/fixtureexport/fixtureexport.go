// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package fixtureexport turns raw payloads stored by tcmon into redacted
// test fixtures ("tcmon fixture export"), so a capture (charging, night,
// grid outage) can be taken from what the poller already recorded instead
// of a live capture session.
//
// Redaction matches the capture tools: Wall Connector payloads get the
// rules of scripts/capture.sh, Gateway payloads internal/gateway/redact.
// The result is checked with the same rules as internal/fixturecheck, and
// nothing is returned when the check finds a possible identifier.
package fixtureexport

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/gateway/redact"
)

// Wall Connector placeholders (as written by scripts/capture.sh).
const (
	WCSerial = "REDACTED00000"
	WCMAC    = "02:00:00:00:00:00"
	WCSSID   = "REDACTED"
)

var (
	reVersion = regexp.MustCompile(`^\d+(\.\d+){1,3}`)
	testNet1  = netip.MustParsePrefix("192.0.2.0/24") // RFC 5737 TEST-NET-1
	// ErrCheck is wrapped by errors from a failed redaction check.
	ErrCheck = errors.New("redaction check failed; nothing written")
)

// Files maps a file name to its contents, all in one firmware directory.
type Files struct {
	Firmware string
	Files    map[string][]byte
}

// Names returns the file names in order.
func (f Files) Names() []string {
	out := make([]string, 0, len(f.Files))
	for n := range f.Files {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func decode(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func marshal(v any, indent bool) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if indent {
		e.SetIndent("", "  ")
	}
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func fileName(name, label string) string {
	if label != "" {
		name += "." + label
	}
	return name + ".json"
}

// RedactWallConnector applies the scripts/capture.sh rules to one decoded
// Wall Connector document in place.
func RedactWallConnector(doc map[string]any) {
	if _, ok := doc["serial_number"].(string); ok {
		doc["serial_number"] = WCSerial
	}
	if _, ok := doc["wifi_mac"].(string); ok {
		doc["wifi_mac"] = WCMAC
	}
	if _, ok := doc["wifi_ssid"].(string); ok {
		doc["wifi_ssid"] = base64.StdEncoding.EncodeToString([]byte(WCSSID))
	}
	if ip, ok := doc["wifi_infra_ip"].(string); ok && ip != "" {
		doc["wifi_infra_ip"] = "192.0.2.1"
		if a, err := netip.ParseAddr(ip); err == nil && a.Is4() {
			doc["wifi_infra_ip"] = fmt.Sprintf("192.0.2.%d", a.As4()[3])
		}
	}
}

// CheckWallConnector reports identifiers left in a Wall Connector document.
// It never includes the offending value.
func CheckWallConnector(doc map[string]any) []string {
	var problems []string
	if v, ok := doc["serial_number"]; ok && v != WCSerial {
		problems = append(problems, "serial_number is not redacted")
	}
	if v, ok := doc["wifi_mac"]; ok && v != WCMAC {
		problems = append(problems, "wifi_mac is not redacted")
	}
	if v, ok := doc["wifi_ssid"].(string); ok {
		dec, err := base64.StdEncoding.DecodeString(v)
		if err != nil || string(dec) != WCSSID {
			problems = append(problems, "wifi_ssid is not the redacted placeholder")
		}
	}
	if v, ok := doc["wifi_infra_ip"].(string); ok && v != "" {
		a, err := netip.ParseAddr(v)
		if err != nil || !testNet1.Contains(a) {
			problems = append(problems, "wifi_infra_ip must be in 192.0.2.0/24 (documentation range)")
		}
	}
	return problems
}

// WallConnectorEndpoints are the stored Wall Connector payloads, in the
// order they are exported.
var WallConnectorEndpoints = []string{"version", "vitals", "lifetime", "wifi_status"}

// WallConnector redacts one stored Wall Connector poll (payloads by
// endpoint name). Files are named like scripts/capture.sh, with label as a
// suffix on every file ("vitals.charging.json", "lifetime.charging.json"),
// so an export never replaces a committed fixture.
func WallConnector(raw map[string][]byte, label string) (Files, error) {
	out := Files{Files: map[string][]byte{}}
	var problems []string
	for _, ep := range WallConnectorEndpoints {
		b, ok := raw[ep]
		if !ok {
			continue
		}
		v, err := decode(b)
		if err != nil {
			return Files{}, fmt.Errorf("%s: stored payload is not JSON: %w", ep, err)
		}
		doc, ok := v.(map[string]any)
		if !ok {
			return Files{}, fmt.Errorf("%s: stored payload is not a JSON object", ep)
		}
		RedactWallConnector(doc)
		for _, p := range CheckWallConnector(doc) {
			problems = append(problems, ep+": "+p)
		}
		if ep == "version" {
			fw, _ := doc["firmware_version"].(string)
			out.Firmware = reVersion.FindString(fw)
		}
		if out.Files[fileName(ep, label)], err = marshal(doc, false); err != nil {
			return Files{}, err
		}
	}
	if len(problems) > 0 {
		return Files{}, fmt.Errorf("%w:\n  %s", ErrCheck, strings.Join(problems, "\n  "))
	}
	if _, ok := raw["vitals"]; !ok {
		return Files{}, errors.New("the stored poll has no vitals payload")
	}
	if out.Firmware == "" {
		return Files{}, errors.New("could not read the firmware version from the stored version payload")
	}
	return out, nil
}

// Gateway redacts one stored Gateway poll (payloads by endpoint path, e.g.
// "/api/status"). Files are named like cmd/gwcapture ("status.night.json",
// "system_status_grid_status.night.json") plus an index that records where
// the files came from.
func Gateway(raw map[string][]byte, label string, polledAt time.Time) (Files, error) {
	docs := map[string]any{}
	r := redact.New()
	for p, b := range raw {
		v, err := decode(b)
		if err != nil {
			return Files{}, fmt.Errorf("%s: stored payload is not JSON: %w", p, err)
		}
		docs[p] = v
		r.Learn(v)
	}
	paths := make([]string, 0, len(docs))
	for p := range docs {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	out := Files{Files: map[string][]byte{}}
	index := map[string]any{}
	var problems []string
	for _, p := range paths {
		red := r.Apply(docs[p])
		for _, prob := range redact.Check(red) {
			problems = append(problems, p+" "+prob)
		}
		b, err := marshal(red, true)
		if err != nil {
			return Files{}, err
		}
		name := fileName(strings.ReplaceAll(strings.TrimPrefix(p, "/api/"), "/", "_"), label)
		out.Files[name] = b
		index[p] = map[string]any{"status": 200, "file": name}
		if p == "/api/status" {
			m, _ := red.(map[string]any)
			v, _ := m["version"].(string)
			out.Firmware = reVersion.FindString(v)
		}
	}
	if len(problems) > 0 {
		return Files{}, fmt.Errorf("%w:\n  %s", ErrCheck, strings.Join(problems, "\n  "))
	}
	if out.Firmware == "" {
		return Files{}, errors.New("could not read the firmware version from the stored /api/status payload")
	}
	index["source"] = "tcmon fixture export"
	index["polled_at"] = polledAt.UTC().Format(time.RFC3339)
	b, err := marshal(index, true)
	if err != nil {
		return Files{}, err
	}
	out.Files[fileName("index", label)] = b
	return out, nil
}
