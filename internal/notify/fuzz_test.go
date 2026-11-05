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
	"mime"
	"net/mail"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/alerts"
)

// FuzzEmail builds messages from arbitrary configuration (as entered in the
// web form) and arbitrary alert text (device names, rule messages), and
// checks that whatever passes validation produces a well-formed message
// with exactly the expected headers: no header injection.
func FuzzEmail(f *testing.F) {
	f.Add("tcmon@example.com", "Garage monitor", "me@example.com", "you@example.org", "[tcmon]", "user",
		"Garage", "Handle temperature high", "Handle 71.0 °C")
	f.Add("a@b.c", "", "x@y.z", "", "", "", "", "", "")
	f.Add("a@b.c\r\nBcc: evil@x.y", "Name\nBcc: x@y", "me@example.com", "me@example.com,evil@x.y", "p\r\n", "u\r\n",
		"Dev\r\nBcc: evil@x.y", "Rule\r\nX-Evil: 1", "line1\nline2")
	f.Add(`"quoted"@example.com`, "Ünïcødé ✓", "me@[192.0.2.1]", "o'brien@example.com", "=?utf-8?q?x?=", "",
		"=?utf-8?b?QmNjOiBldmls?=", "Résumé", "<b>html</b>")
	f.Fuzz(func(t *testing.T, from, fromName, to1, to2, prefix, user, device, rule, msg string) {
		cfg := EmailConfig{Host: "smtp.example.com", Port: 587, Security: SecurityStartTLS, Username: user,
			From: from, FromName: fromName, To: []string{to1}, SubjectPrefix: prefix}
		if to2 != "" {
			cfg.To = append(cfg.To, to2)
		}
		if cfg.Normalize() != nil {
			return
		}
		now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
		m := Build([]alerts.Notification{{RuleKey: "x", RuleTitle: rule, DeviceName: device, Kind: alerts.KindFiring,
			Severity: alerts.Warning, Message: msg, At: now}}, time.UTC)
		raw := compose(cfg, m, now)

		parsed, err := mail.ReadMessage(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("unparseable message: %v\n%q", err, raw)
		}
		want := []string{"Auto-Submitted", "Content-Type", "Date", "From", "Message-Id", "Mime-Version", "Subject",
			"To", "X-Auto-Response-Suppress"}
		var got []string
		for k, vs := range parsed.Header {
			if len(vs) != 1 {
				t.Fatalf("header %s appears %d times", k, len(vs))
			}
			got = append(got, k)
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Fatalf("headers = %v, want %v", got, want)
		}
		if a, err := mail.ParseAddress(parsed.Header.Get("From")); err != nil || a.Address != cfg.From {
			t.Fatalf("From = %q (%v), want %q", parsed.Header.Get("From"), err, cfg.From)
		}
		tos, err := parsed.Header.AddressList("To")
		if err != nil || len(tos) != len(cfg.To) {
			t.Fatalf("To = %q (%v), want %v", parsed.Header.Get("To"), err, cfg.To)
		}
		for i, a := range tos {
			if a.Address != cfg.To[i] {
				t.Fatalf("To[%d] = %q, want %q", i, a.Address, cfg.To[i])
			}
		}
		subject, err := new(mime.WordDecoder).DecodeHeader(parsed.Header.Get("Subject"))
		if err != nil || strings.ContainsAny(subject, "\r\n") {
			t.Fatalf("Subject = %q (%v)", subject, err)
		}
	})
}
