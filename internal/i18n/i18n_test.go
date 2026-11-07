// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package i18n

import (
	"html/template"
	"strings"
	"testing"
)

func testCatalog(t *testing.T, src string) *Catalog {
	t.Helper()
	msgs, err := parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return &Catalog{lang: "en", msgs: msgs}
}

func TestParseRejects(t *testing.T) {
	for name, src := range map[string]string{
		"duplicate key":     `{"a.b": "x", "a.b": "y"}`,
		"bad key":           `{"Ab": "x"}`,
		"no section":        `{"ab": "x"}`,
		"stray brace":       `{"a.b": "x { y"}`,
		"bad placeholder":   `{"a.b": "{Name}"}`,
		"markup in plain":   `{"a.b": "<b>x</b>"}`,
		"disallowed tag":    `{"a.b_html": "<script>x</script>"}`,
		"event attribute":   `{"a.b_html": "<a onclick=\"x\">x</a>"}`,
		"empty one":         `{"a.b": {"one": "", "other": "x"}}`,
		"unknown form":      `{"a.b": {"one": "x", "other": "y", "few": "z"}}`,
		"number":            `{"a.b": 3}`,
		"array":             `[]`,
		"trailing":          `{"a.b": "x"} {}`,
		"missing other":     `{"a.b": {"one": "x"}}`,
		"placeholder brace": `{"a.b": "{{x}}"}`,
	} {
		if _, err := parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted %s", name, src)
		}
	}
}

func TestFormatting(t *testing.T) {
	c := testCatalog(t, `{
		"x.plain": "Hello {name}, you",
		"x.none": "Static",
		"x.link_html": "See <a href=\"{url}\" rel=\"noopener\">{label}</a> or <code>{cmd}</code>",
		"x.count": {"one": "{n} session for {who}", "other": "{n} sessions for {who}"}
	}`)
	if s, err := c.Text("x.plain", "name", "<Bob>"); err != nil || s != "Hello <Bob>, you" {
		t.Errorf("Text = %q, %v (plain text is escaped by the template, not here)", s, err)
	}
	if s, _ := c.Text("x.none"); s != "Static" {
		t.Errorf("Text = %q", s)
	}
	h, err := c.HTML("x.link_html", "url", `/a?b="c"`, "label", "<i>", "cmd", template.HTML("<b>ok</b>"))
	if err != nil || h != `See <a href="/a?b=&#34;c&#34;" rel="noopener">&lt;i&gt;</a> or <code><b>ok</b></code>` {
		t.Errorf("HTML = %q, %v", h, err)
	}
	for n, want := range map[int]string{0: "0 sessions for me", 1: "1 session for me", 2: "2 sessions for me"} {
		if s, err := c.Count("x.count", n, "who", "me"); err != nil || s != want {
			t.Errorf("Count(%d) = %q, %v", n, s, err)
		}
	}
	for name, err := range map[string]error{
		"unknown":        func() error { _, err := c.Text("x.nope"); return err }(),
		"missing arg":    func() error { _, err := c.Text("x.plain"); return err }(),
		"unused arg":     func() error { _, err := c.Text("x.none", "a", 1); return err }(),
		"odd args":       func() error { _, err := c.Text("x.plain", "name"); return err }(),
		"non-string":     func() error { _, err := c.Text("x.plain", 1, 2); return err }(),
		"html via Text":  func() error { _, err := c.Text("x.link_html"); return err }(),
		"plain via HTML": func() error { _, err := c.HTML("x.none"); return err }(),
		"plural via Text": func() error {
			_, err := c.Text("x.count")
			return err
		}(),
		"Count on plain": func() error { _, err := c.Count("x.none", 1); return err }(),
	} {
		if err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if s := c.T("x.nope"); s != "x.nope" {
		t.Errorf("T on unknown key = %q, want the key", s)
	}
	if s := c.N("x.count", 3, "who", "you"); s != "3 sessions for you" {
		t.Errorf("N = %q", s)
	}
}

func TestTemplateFuncs(t *testing.T) {
	c := testCatalog(t, `{"x.hi": "Hi {name} & co", "x.b_html": "<strong>{name}</strong>"}`)
	tpl := template.Must(template.New("x").Funcs(c.Funcs()).Parse(
		`<p title="{{t "x.hi" "name" .}}" lang="{{lang}}">{{t "x.hi" "name" .}} {{th "x.b_html" "name" .}}</p>`))
	var b strings.Builder
	if err := tpl.Execute(&b, `"<x>"`); err != nil {
		t.Fatal(err)
	}
	want := `<p title="Hi &#34;&lt;x&gt;&#34; &amp; co" lang="en">Hi &#34;&lt;x&gt;&#34; &amp; co <strong>&#34;&lt;x&gt;&#34;</strong></p>`
	if b.String() != want {
		t.Errorf("got  %s\nwant %s", b.String(), want)
	}
	bad := template.Must(template.New("x").Funcs(c.Funcs()).Parse(`{{t "x.missing"}}`))
	if err := bad.Execute(&b, nil); err == nil {
		t.Error("unknown key rendered without error")
	}
}

func TestEnglishLoads(t *testing.T) {
	c := English()
	if c.Lang() != "en" || len(c.Keys()) < 100 {
		t.Fatalf("lang %q, %d keys", c.Lang(), len(c.Keys()))
	}
	if s := c.T("app.name"); s != "Tesla Charger Monitoring" {
		t.Errorf("app.name = %q", s)
	}
}
