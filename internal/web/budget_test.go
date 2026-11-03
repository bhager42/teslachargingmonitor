// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package web

import (
	"bytes"
	"compress/gzip"
	"io/fs"
	"strings"
	"testing"

	webui "github.com/bhager42/teslachargingmonitor/web"
)

// The plan's performance budget: under 60 KB of JavaScript (gzipped), and
// no third-party scripts.
func TestJavaScriptBudget(t *testing.T) {
	var total int
	err := fs.WalkDir(webui.Static, "static", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".mjs") && !strings.HasSuffix(path, ".js") {
			return err
		}
		b, err := webui.Static.ReadFile(path)
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(b)
		_ = zw.Close()
		total += buf.Len()
		for _, banned := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"} {
			if bytes.Contains(b, []byte(banned)) {
				t.Errorf("%s uses %s (forbidden under Trusted Types)", path, banned)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if total == 0 || total > 60<<10 {
		t.Errorf("JavaScript is %d bytes gzipped (budget 60 KiB)", total)
	}
	t.Logf("JavaScript: %d bytes gzipped", total)
}
