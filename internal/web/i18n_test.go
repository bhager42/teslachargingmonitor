// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package web

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sync"
	"testing"

	"github.com/bhager42/teslachargingmonitor/internal/alerts"
	"github.com/bhager42/teslachargingmonitor/internal/auth"
	"github.com/bhager42/teslachargingmonitor/internal/i18n"
	"github.com/bhager42/teslachargingmonitor/internal/store"
	webui "github.com/bhager42/teslachargingmonitor/web"
)

var (
	i18nMu     sync.Mutex
	i18nErrors []string
)

// TestMain fails the package when any test makes the web code format a
// message wrongly (unknown key, missing or unused argument), which tr.T
// would otherwise hide by showing the key.
func TestMain(m *testing.M) {
	i18n.ReportErrors = func(key string, err error) {
		i18nMu.Lock()
		defer i18nMu.Unlock()
		i18nErrors = append(i18nErrors, fmt.Sprintf("%s: %v", key, err))
	}
	code := m.Run()
	if len(i18nErrors) > 0 {
		fmt.Fprintln(os.Stderr, "message catalog errors:")
		for _, e := range i18nErrors {
			fmt.Fprintln(os.Stderr, "  ", e)
		}
		code = 1
	}
	os.Exit(code)
}

// Every message app.mjs uses must be delivered to the page.
func TestJavaScriptMessages(t *testing.T) {
	b, err := webui.Static.ReadFile("static/js/app.mjs")
	if err != nil {
		t.Fatal(err)
	}
	used := regexp.MustCompile(`\bmsg\('([a-z0-9_.]+)'`).FindAllStringSubmatch(string(b), -1)
	if len(used) == 0 {
		t.Fatal("app.mjs uses no messages")
	}
	for _, m := range used {
		if !slices.Contains(jsMessageKeys, m[1]) {
			t.Errorf("app.mjs uses %q, which jsMessageKeys does not deliver", m[1])
		}
	}
	for _, k := range jsMessageKeys {
		if _, ok := jsMessages[k]; !ok || jsMessages[k] == "" {
			t.Errorf("%q is not in the catalog", k)
		}
	}
	h := newHarness(t, Config{}, auth.Bootstrap{})
	body := bodyOf(t, h.do("GET", "/setup", nil))
	if !regexp.MustCompile(`<script type="application/json" id="tcmon-messages">\{"chart\.load_failed":"Could not load the chart\."`).MatchString(body) {
		t.Error("page does not carry the script's messages")
	}
}

// Severity, alert kind and delivery status names are stored in the
// database and used in CSS classes; the UI shows their catalog names,
// which in English are the stored names themselves.
func TestDisplayNames(t *testing.T) {
	for _, s := range []alerts.Severity{alerts.None, alerts.Info, alerts.Warning, alerts.Critical} {
		if got := severityLabel(s); got != s.String() {
			t.Errorf("severityLabel(%v) = %q", s, got)
		}
		if got := severityLabel(s.String()); got != s.String() {
			t.Errorf("severityLabel(%q) = %q", s.String(), got)
		}
	}
	for _, k := range []string{alerts.KindFiring, alerts.KindEscalated, alerts.KindRepeat, alerts.KindResolved, alerts.KindEvent, "other"} {
		if got := alerts.KindLabel(k); got != k {
			t.Errorf("KindLabel(%q) = %q", k, got)
		}
	}
	for _, s := range []string{store.DeliveryPending, store.DeliverySent, store.DeliveryFailed, "other"} {
		if got := deliveryLabel(s); got != s {
			t.Errorf("deliveryLabel(%q) = %q", s, got)
		}
	}
	b, _ := json.Marshal(CardAlert{Title: "Hot", Severity: "critical", SeverityLabel: alerts.Critical.Label()})
	if string(b) != `{"title":"Hot","severity":"critical","severity_label":"critical"}` {
		t.Errorf("CardAlert JSON = %s", b)
	}
}
