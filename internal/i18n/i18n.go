// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package i18n holds the message catalog for user-facing text (web UI,
// emails, alert rules). Only English exists today; the catalog keeps the
// text in one place so another language can be added as one more file in
// locales/ (see docs/adr/0006-message-catalog.md).
//
// A catalog is a flat JSON object of key → message. A message is either a
// string or, when it depends on a count, {"one": "...", "other": "..."}.
// Messages name their arguments as {name}. Keys ending in "_html" may contain
// a few inline tags (a, code, strong, em, kbd); all other messages are plain
// text and are escaped wherever they are shown.
package i18n

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"regexp"
	"slices"
	"strings"
)

//go:embed locales/*.json
var locales embed.FS

// Message is one catalog entry. Plain messages only set Other.
type Message struct {
	One, Other string
}

// Plural reports whether the message has count-dependent forms.
func (m Message) Plural() bool { return m.One != "" }

// Catalog is the messages of one language.
type Catalog struct {
	lang string
	msgs map[string]Message
}

var english = mustLoad("en")

// English returns the built-in English catalog.
func English() *Catalog { return english }

func mustLoad(lang string) *Catalog {
	c, err := Load(lang)
	if err != nil {
		panic(err)
	}
	return c
}

// Load reads and validates locales/<lang>.json.
func Load(lang string) (*Catalog, error) {
	b, err := locales.ReadFile("locales/" + lang + ".json")
	if err != nil {
		return nil, err
	}
	msgs, err := parse(b)
	if err != nil {
		return nil, fmt.Errorf("i18n: %s.json: %w", lang, err)
	}
	return &Catalog{lang: lang, msgs: msgs}, nil
}

var (
	keyRE         = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)+$`)
	placeholderRE = regexp.MustCompile(`\{([a-z][a-z0-9_]*)\}`)
	tagRE         = regexp.MustCompile(`</?(a|code|strong|em|kbd)( href="[^"<>{}]*(\{[a-z][a-z0-9_]*\}[^"<>{}]*)?"( rel="noopener")?( download)?)?>`)
)

// parse decodes a catalog, rejecting duplicate keys (which encoding/json
// would silently merge) and malformed messages.
func parse(b []byte) (map[string]Message, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	msgs := map[string]Message{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := tok.(string)
		if !keyRE.MatchString(key) {
			return nil, fmt.Errorf("invalid key %q", key)
		}
		if _, dup := msgs[key]; dup {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		var m Message
		if err := json.Unmarshal(raw, &m.Other); err != nil {
			var forms struct {
				One   *string `json:"one"`
				Other *string `json:"other"`
			}
			d := json.NewDecoder(bytes.NewReader(raw))
			d.DisallowUnknownFields()
			if err := d.Decode(&forms); err != nil || forms.One == nil || forms.Other == nil || *forms.One == "" {
				return nil, fmt.Errorf("%s: want a string or {\"one\", \"other\"}", key)
			}
			m = Message{One: *forms.One, Other: *forms.Other}
		}
		for _, s := range []string{m.One, m.Other} {
			if err := check(key, s); err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
		}
		msgs[key] = m
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the object")
	}
	return msgs, nil
}

// check validates one message text: balanced placeholders, and markup only
// in _html keys and only from the allowed tags.
func check(key, s string) error {
	rest := placeholderRE.ReplaceAllString(s, "")
	if strings.ContainsAny(rest, "{}") {
		return errors.New("stray { or } (placeholders are {name})")
	}
	if strings.HasSuffix(key, "_html") {
		if strings.ContainsAny(tagRE.ReplaceAllString(s, ""), "<>") {
			return errors.New("markup other than a, code, strong, em, kbd")
		}
	} else if strings.ContainsAny(s, "<>") {
		return errors.New("markup in a plain-text message (use a key ending in _html)")
	}
	return nil
}

// Lang is the catalog's language tag.
func (c *Catalog) Lang() string { return c.lang }

// Keys returns all keys, sorted.
func (c *Catalog) Keys() []string {
	keys := make([]string, 0, len(c.msgs))
	for k := range c.msgs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// Lookup returns the raw message for key.
func (c *Catalog) Lookup(key string) (Message, bool) {
	m, ok := c.msgs[key]
	return m, ok
}

// Text formats a plain message. args are name, value pairs.
func (c *Catalog) Text(key string, args ...any) (string, error) {
	if strings.HasSuffix(key, "_html") {
		return "", fmt.Errorf("i18n: %s holds markup; use HTML", key)
	}
	m, err := c.plain(key)
	if err != nil {
		return "", err
	}
	return fill(key, m, args, false)
}

// HTML formats a message that holds markup, escaping the arguments (unless
// they are template.HTML already).
func (c *Catalog) HTML(key string, args ...any) (template.HTML, error) {
	if !strings.HasSuffix(key, "_html") {
		return "", fmt.Errorf("i18n: %s is plain text; use Text", key)
	}
	m, err := c.plain(key)
	if err != nil {
		return "", err
	}
	s, err := fill(key, m, args, true)
	return template.HTML(s), err //nolint:gosec // catalog markup is embedded and validated; arguments are escaped
}

// Count formats a count-dependent message; {n} is the count.
func (c *Catalog) Count(key string, n int, args ...any) (string, error) {
	m, ok := c.msgs[key]
	if !ok {
		return "", fmt.Errorf("i18n: unknown message %q", key)
	}
	if !m.Plural() {
		return "", fmt.Errorf("i18n: %s has no plural forms", key)
	}
	s := m.Other
	if c.pluralOne(n) {
		s = m.One
	}
	return fill(key, s, append([]any{"n", n}, args...), false)
}

// pluralOne is the plural rule; English (and the default) uses "one" for 1.
func (c *Catalog) pluralOne(n int) bool { return n == 1 }

// ReportErrors receives, when set, every mistake that T and N hide (unknown
// key, missing or unused argument). Tests set it so such mistakes fail; it
// must be set before any concurrent use and not changed afterwards.
var ReportErrors func(key string, err error)

// T is Text for Go code: a missing key or argument yields the key itself so
// a mistake shows up in the UI instead of an empty string (and reaches
// ReportErrors).
func (c *Catalog) T(key string, args ...any) string {
	s, err := c.Text(key, args...)
	if err != nil {
		if ReportErrors != nil {
			ReportErrors(key, err)
		}
		return key
	}
	return s
}

// N is Count for Go code (see T).
func (c *Catalog) N(key string, n int, args ...any) string {
	s, err := c.Count(key, n, args...)
	if err != nil {
		if ReportErrors != nil {
			ReportErrors(key, err)
		}
		return key
	}
	return s
}

func (c *Catalog) plain(key string) (string, error) {
	m, ok := c.msgs[key]
	if !ok {
		return "", fmt.Errorf("i18n: unknown message %q", key)
	}
	if m.Plural() {
		return "", fmt.Errorf("i18n: %s has plural forms; use Count", key)
	}
	return m.Other, nil
}

// fill replaces {name} placeholders. Every placeholder needs an argument and
// every argument must be used.
func fill(key, s string, args []any, escape bool) (string, error) {
	if len(args)%2 != 0 {
		return "", fmt.Errorf("i18n: %s: arguments must be name, value pairs", key)
	}
	vals := make(map[string]string, len(args)/2)
	for i := 0; i < len(args); i += 2 {
		name, ok := args[i].(string)
		if !ok {
			return "", fmt.Errorf("i18n: %s: argument name %v is not a string", key, args[i])
		}
		v := fmt.Sprint(args[i+1])
		if h, ok := args[i+1].(template.HTML); ok && escape {
			v = string(h)
		} else if escape {
			v = template.HTMLEscapeString(v)
		}
		vals[name] = v
	}
	used := map[string]bool{}
	var missing string
	out := placeholderRE.ReplaceAllStringFunc(s, func(p string) string {
		name := p[1 : len(p)-1]
		v, ok := vals[name]
		if !ok {
			missing = name
			return p
		}
		used[name] = true
		return v
	})
	if missing != "" {
		return "", fmt.Errorf("i18n: %s: no value for {%s}", key, missing)
	}
	for name := range vals {
		if !used[name] && name != "n" {
			return "", fmt.Errorf("i18n: %s: argument %q is not used", key, name)
		}
	}
	return out, nil
}

// Funcs returns the template functions t (plain text), th (markup) and tn
// (count-dependent) bound to c. They fail the render on any mistake.
func (c *Catalog) Funcs() template.FuncMap {
	return template.FuncMap{
		"t":    c.Text,
		"th":   c.HTML,
		"tn":   c.Count,
		"lang": c.Lang,
	}
}
