// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package fixturecheck

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bhager42/teslachargingmonitor/internal/fixtureexport"
	"github.com/bhager42/teslachargingmonitor/internal/gateway/redact"
)

const fixturesDir = "../../testdata/fixtures"

func fixtureFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(fixturesDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".json") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking fixtures: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no fixtures found")
	}
	return files
}

// isGateway reports whether path is a Backup Gateway fixture
// (scripts/capture-gateway.sh) rather than a Wall Connector one.
func isGateway(path string) bool {
	rel, err := filepath.Rel(fixturesDir, path)
	return err == nil && strings.HasPrefix(filepath.ToSlash(rel), "gateway/")
}

func TestFixturesAreRedactedJSON(t *testing.T) {
	for _, path := range fixtureFiles(t) {
		t.Run(filepath.ToSlash(path), func(t *testing.T) {
			raw, err := os.ReadFile(path) //nolint:gosec // path comes from WalkDir over the repo fixtures directory
			if err != nil {
				t.Fatal(err)
			}
			var v any
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			if isGateway(path) {
				// Gateway responses can be arrays and nest identifiers
				// anywhere, so they get the recursive check.
				for _, p := range redact.Check(v) {
					t.Error(p)
				}
				return
			}
			doc, ok := v.(map[string]any)
			if !ok {
				t.Fatal("Wall Connector fixture is not a JSON object")
			}
			for _, p := range fixtureexport.CheckWallConnector(doc) {
				t.Error(p)
			}
		})
	}
}
