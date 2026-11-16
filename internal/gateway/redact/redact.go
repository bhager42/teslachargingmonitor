// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package redact removes the owner's identifiers from captured Tesla Backup
// Gateway responses before they become test fixtures, and checks committed
// fixtures for anything that slipped through.
//
// Two mechanisms work together:
//   - Key rules: a value under a sensitive key (serial, DIN, email, names,
//     tokens, addresses, locations, ...) is replaced by a placeholder.
//   - Value rules: anywhere in any string, IPv4 addresses outside the
//     documentation ranges, MAC addresses, email addresses and identifiers
//     learned from sensitive keys (e.g. the DIN repeated in another field)
//     are replaced.
//
// The Gateway API is undocumented, so the rules err on the side of redacting
// too much; the capture tool still asks the owner to review the files.
package redact

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Placeholders written in place of identifiers.
const (
	Placeholder      = "REDACTED"
	PlaceholderMAC   = "02:00:00:00:00:00"
	PlaceholderEmail = "redacted@example.com"
)

// sensitiveWords are key words (after splitting snake_case and camelCase)
// whose values identify the owner, the site or the hardware.
var sensitiveWords = map[string]bool{
	"serial": true, "din": true, "vin": true, "sn": true,
	"email": true, "firstname": true, "lastname": true, "phone": true,
	"token": true, "password": true, "secret": true, "cookie": true,
	"ssid": true, "mac": true, "ip": true, "hostname": true,
	"latitude": true, "longitude": true, "lat": true, "lng": true, "lon": true,
	"address": true, "street": true, "city": true, "zip": true, "postal": true,
	"installer": true, "utility": true, "customer": true,
}

// sensitiveKeys are whole keys (normalized: lower case, no separators) that
// are sensitive although none of their words is.
var sensitiveKeys = map[string]bool{
	"sitename": true, "gatewayid": true, "gridcode": true, "networkname": true,
}

var (
	reIPv4  = regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`)
	reMAC   = regexp.MustCompile(`(?i)\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b`)
	reEmail = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	docNets = []netip.Prefix{ // RFC 5737 and RFC 3849 documentation ranges
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
	}
)

// words splits a JSON key into lower-case words: "PackageSerialNumber" and
// "package_serial_number" both give [package serial number].
func words(key string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(key)
	for i, r := range rs {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
			continue
		case unicode.IsUpper(r) && i > 0 && (unicode.IsLower(rs[i-1]) ||
			(i+1 < len(rs) && unicode.IsLower(rs[i+1]) && unicode.IsUpper(rs[i-1]))):
			flush()
		}
		cur = append(cur, r)
	}
	flush()
	return out
}

// Sensitive reports whether values under key must be redacted.
func Sensitive(key string) bool {
	ws := words(key)
	if sensitiveKeys[strings.Join(ws, "")] {
		return true
	}
	for _, w := range ws {
		if sensitiveWords[w] {
			return true
		}
	}
	return false
}

// placeholderFor returns the replacement for a sensitive string value.
func placeholderFor(key, v string) string {
	if v == "" {
		return ""
	}
	for _, w := range words(key) {
		switch w {
		case "ip":
			return "192.0.2.1"
		case "mac":
			return PlaceholderMAC
		case "email":
			return PlaceholderEmail
		}
	}
	return Placeholder
}

// Redactor redacts a set of documents captured from one Gateway. Call Learn
// on every document first so identifiers found in one response are also
// removed from the others, then Apply.
type Redactor struct {
	known map[string]bool
}

// New returns an empty Redactor.
func New() *Redactor { return &Redactor{known: map[string]bool{}} }

// Learn records the values of sensitive keys in doc (a decoded JSON value).
func (r *Redactor) Learn(doc any) {
	visit(doc, "$", "", false, func(_, _ string, sens bool, v any) any {
		if s, ok := v.(string); ok && sens {
			r.add(s)
			// A DIN is "<part number>--<serial>"; learn the pieces too.
			for _, p := range strings.Split(s, "--") {
				r.add(p)
			}
		}
		return v
	})
}

func (r *Redactor) add(s string) {
	s = strings.TrimSpace(s)
	if len(s) >= 6 && s != Placeholder && s != PlaceholderMAC && s != PlaceholderEmail {
		r.known[s] = true
	}
}

// Apply returns a redacted copy of doc.
func (r *Redactor) Apply(doc any) any {
	known := make([]string, 0, len(r.known))
	for k := range r.known {
		known = append(known, k)
	}
	// Longest first, so a DIN is replaced before its serial part.
	sort.Slice(known, func(i, j int) bool { return len(known[i]) > len(known[j]) })
	return visit(doc, "$", "", false, func(_, key string, sens bool, v any) any {
		switch x := v.(type) {
		case string:
			if sens {
				return placeholderFor(key, x)
			}
			return scrub(x, known)
		case json.Number:
			if sens {
				return json.Number("0")
			}
		case float64:
			if sens {
				return float64(0)
			}
		}
		return v
	})
}

// scrub applies the value rules to one string.
func scrub(s string, known []string) string {
	for _, k := range known {
		s = strings.ReplaceAll(s, k, Placeholder)
	}
	s = reEmail.ReplaceAllString(s, PlaceholderEmail)
	s = reMAC.ReplaceAllString(s, PlaceholderMAC)
	return reIPv4.ReplaceAllStringFunc(s, func(m string) string {
		a, err := netip.ParseAddr(m)
		if err != nil || isDoc(a) {
			return m
		}
		return fmt.Sprintf("192.0.2.%d", a.As4()[3])
	})
}

func isDoc(a netip.Addr) bool {
	for _, p := range docNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func isPlaceholder(s string) bool {
	if s == "" || s == Placeholder || s == PlaceholderMAC || s == PlaceholderEmail {
		return true
	}
	a, err := netip.ParseAddr(s)
	return err == nil && isDoc(a)
}

// Check reports anything in doc that looks like an unredacted identifier, as
// JSON paths with a reason. It never includes the offending value.
func Check(doc any) []string {
	var problems []string
	visit(doc, "$", "", false, func(path, _ string, sens bool, v any) any {
		if sens {
			switch x := v.(type) {
			case string:
				if !isPlaceholder(x) {
					problems = append(problems, path+": sensitive key is not redacted")
				}
			case json.Number:
				if x != "0" {
					problems = append(problems, path+": sensitive key is not redacted")
				}
			case float64:
				if x != 0 {
					problems = append(problems, path+": sensitive key is not redacted")
				}
			}
			return v
		}
		s, ok := v.(string)
		if !ok {
			return v
		}
		for _, m := range reIPv4.FindAllString(s, -1) {
			if a, err := netip.ParseAddr(m); err == nil && !isDoc(a) {
				problems = append(problems, path+": IPv4 address outside the documentation ranges")
			}
		}
		for _, m := range reMAC.FindAllString(s, -1) {
			if m != PlaceholderMAC {
				problems = append(problems, path+": MAC address")
			}
		}
		for _, m := range reEmail.FindAllString(s, -1) {
			if !strings.HasSuffix(strings.ToLower(m), "@example.com") {
				problems = append(problems, path+": email address")
			}
		}
		return v
	})
	sort.Strings(problems)
	return problems
}

// visit rebuilds v, calling fn on every scalar with its JSON path, the
// nearest object key, and whether that key or any enclosing key is
// sensitive (so a whole "address" object is redacted, not just its
// sensitive-looking members).
func visit(v any, path, key string, sens bool, fn func(path, key string, sens bool, v any) any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, c := range x {
			out[k] = visit(c, path+"."+k, k, sens || Sensitive(k), fn)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, c := range x {
			out[i] = visit(c, fmt.Sprintf("%s[%d]", path, i), key, sens, fn)
		}
		return out
	default:
		return fn(path, key, sens, v)
	}
}
