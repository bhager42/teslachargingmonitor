// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package web

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"sync"
	"testing"

	"github.com/bhager42/teslachargingmonitor/internal/auth"
	"github.com/bhager42/teslachargingmonitor/internal/i18n"
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
