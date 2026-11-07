// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package i18n

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Template calls: {{t "key" ...}}, {{th "key" ...}}, {{tn "key" ...}}, (t "key").
var templateCall = regexp.MustCompile(`[{(]-?\s*(t|th|tn)\s+"([^"]+)"`)

// TestCatalogCoverage checks that every key the templates use exists with
// the right kind (markup, plain, plural), and that every catalog key is
// used somewhere (templates or Go code), so the catalog stays the single,
// complete source of user-facing text.
func TestCatalogCoverage(t *testing.T) {
	c := English()
	root := filepath.Join("..", "..")
	used := map[string]bool{}
	var sources strings.Builder

	tpls, err := filepath.Glob(filepath.Join(root, "web", "templates", "*.html"))
	if err != nil || len(tpls) == 0 {
		t.Fatalf("no templates found: %v", err)
	}
	for _, p := range tpls {
		b, err := os.ReadFile(p) //nolint:gosec // test reads the repository's own templates
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range templateCall.FindAllStringSubmatch(string(b), -1) {
			fn, key := m[1], m[2]
			used[key] = true
			msg, ok := c.Lookup(key)
			switch {
			case !ok:
				t.Errorf("%s: unknown message %q", filepath.Base(p), key)
			case fn == "th" != strings.HasSuffix(key, "_html"):
				t.Errorf("%s: %s %q: use th exactly for _html keys", filepath.Base(p), fn, key)
			case fn == "tn" != msg.Plural():
				t.Errorf("%s: %s %q: use tn exactly for plural messages", filepath.Base(p), fn, key)
			}
		}
	}
	err = filepath.WalkDir(filepath.Join(root, "internal"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, err := os.ReadFile(p) //nolint:gosec // test reads the repository's own sources
		sources.Write(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	src := sources.String()
	for _, k := range c.Keys() {
		if !used[k] && !strings.Contains(src, `"`+k+`"`) {
			t.Errorf("message %q is not used anywhere", k)
		}
	}
}
