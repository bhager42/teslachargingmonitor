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
	"embed"
	htmltemplate "html/template"
	"slices"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/alerts"
	"github.com/bhager42/teslachargingmonitor/internal/buildinfo"
)

// Message is one rendered notification (one per poll batch per channel).
type Message struct {
	Subject  string          `json:"subject"`
	Text     string          `json:"text"`
	HTML     string          `json:"html"`
	Severity alerts.Severity `json:"severity"`
}

//go:embed templates/*.tmpl
var templateFS embed.FS

var (
	funcs   = templateFuncs()
	textTpl = texttemplate.Must(texttemplate.New("email.txt.tmpl").Funcs(funcs).ParseFS(templateFS, "templates/email.txt.tmpl"))
	htmlTpl = htmltemplate.Must(htmltemplate.New("email.html.tmpl").Funcs(funcs).ParseFS(templateFS, "templates/email.html.tmpl"))
)

// templateFuncs are the catalog functions (t, th, tn, lang) plus upper.
func templateFuncs() map[string]any {
	f := map[string]any(tr.Funcs())
	f["upper"] = strings.ToUpper
	return f
}

// item is the only data templates can see (no secrets, no raw payloads).
type item struct {
	Severity, RuleTitle, KindLabel, Message, DeviceName, When, Color, SeverityIcon string
}

type view struct {
	Subject string
	Items   []item
	Footer  string
}

// kindLabel names a notice kind in an email (wording differs from the web UI).
func kindLabel(kind string) string {
	switch kind {
	case alerts.KindFiring:
		return tr.T("email.kind_firing")
	case alerts.KindEscalated:
		return tr.T("email.kind_escalated")
	case alerts.KindRepeat:
		return tr.T("email.kind_repeat")
	case alerts.KindResolved:
		return tr.T("email.kind_resolved")
	case alerts.KindEvent:
		return tr.T("email.kind_event")
	}
	return ""
}

func style(n alerts.Notification) (color, icon string) {
	if n.Kind == alerts.KindResolved {
		return "#2e7d32", "✅"
	}
	switch n.Severity {
	case alerts.Critical:
		return "#c62828", "⛔"
	case alerts.Warning:
		return "#ef6c00", "⚠️"
	default:
		return "#1565c0", "ℹ️"
	}
}

// Build renders one message for a batch of notifications. Times are shown
// in loc.
func Build(batch []alerts.Notification, loc *time.Location) Message {
	if loc == nil {
		loc = time.Local
	}
	m := Message{}
	devices := []string{}
	v := view{}
	for _, n := range batch {
		m.Severity = max(m.Severity, n.Severity)
		if !slices.Contains(devices, n.DeviceName) {
			devices = append(devices, n.DeviceName)
		}
		color, icon := style(n)
		v.Items = append(v.Items, item{
			Severity: n.Severity.Label(), RuleTitle: n.RuleTitle, KindLabel: kindLabel(n.Kind),
			Message: n.Message, DeviceName: n.DeviceName, When: n.At.In(loc).Format("Mon 2 Jan 2006 15:04 MST"),
			Color: color, SeverityIcon: icon,
		})
	}
	where := strings.Join(devices, ", ")
	switch {
	case len(batch) == 1 && batch[0].Kind == alerts.KindResolved:
		m.Subject = tr.T("email.subject_resolved", "title", batch[0].RuleTitle, "devices", where)
	case len(batch) == 1:
		m.Subject = tr.T("email.subject_one", "severity", strings.ToUpper(batch[0].Severity.Label()),
			"title", batch[0].RuleTitle, "devices", where)
	default:
		m.Subject = tr.N("email.subject_many", len(batch), "severity", m.Severity.Label(), "devices", where)
	}
	info := buildinfo.Get()
	v.Subject = m.Subject
	v.Footer = tr.T("email.footer", "version", info.Version, "source", info.SourceLink())
	var tb, hb bytes.Buffer
	_ = textTpl.Execute(&tb, v) // templates are embedded and tested; data is plain strings
	_ = htmlTpl.Execute(&hb, v)
	m.Text, m.HTML = strings.TrimSpace(tb.String())+"\n", hb.String()
	return m
}
