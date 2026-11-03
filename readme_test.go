// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors

// Package readme_test keeps the TrueNAS YAML shown in README.md identical to
// deploy/truenas/custom-app.yaml, so people copying from either get the same.
package readme_test

import (
	"os"
	"strings"
	"testing"
)

func TestReadmeTrueNASYAMLMatchesDeployFile(t *testing.T) {
	file, err := os.ReadFile("deploy/truenas/custom-app.yaml")
	if err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	want := string(file)
	i := strings.Index(want, "services:")
	if i < 0 {
		t.Fatal("custom-app.yaml has no services: section")
	}
	want = want[i:]
	if !strings.Contains(string(readme), "```yaml\n"+want+"```\n") {
		t.Error("README.md's TrueNAS YAML differs from deploy/truenas/custom-app.yaml " +
			"(from `services:` on); copy the file's content into the README block")
	}
}
