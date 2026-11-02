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
	"strconv"
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
	funcs   = map[string]any{"upper": strings.ToUpper}
	textTpl = texttemplate.Must(texttemplate.New("email.txt.tmpl").Funcs(funcs).ParseFS(templateFS, "templates/email.txt.tmpl"))
	htmlTpl = htmltemplate.Must(htmltemplate.New("email.html.tmpl").Funcs(funcs).ParseFS(templateFS, "templates/email.html.tmpl"))
)

// item is the only data templates can see (no secrets, no raw payloads).
type item struct {
	Severity, RuleTitle, KindLabel, Message, DeviceName, When, Color, SeverityIcon string
}

type view struct {
	Subject string
	Items   []item
	Footer  string
}

var kindLabels = map[string]string{
	alerts.KindFiring:    "alert",
	alerts.KindEscalated: "escalated",
	alerts.KindRepeat:    "still active",
	alerts.KindResolved:  "resolved",
	alerts.KindEvent:     "event",
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
			Severity: n.Severity.String(), RuleTitle: n.RuleTitle, KindLabel: kindLabels[n.Kind],
			Message: n.Message, DeviceName: n.DeviceName, When: n.At.In(loc).Format("Mon 2 Jan 2006 15:04 MST"),
			Color: color, SeverityIcon: icon,
		})
	}
	where := strings.Join(devices, ", ")
	switch {
	case len(batch) == 1 && batch[0].Kind == alerts.KindResolved:
		m.Subject = "Resolved: " + batch[0].RuleTitle + " — " + where
	case len(batch) == 1:
		m.Subject = strings.ToUpper(batch[0].Severity.String()) + ": " + batch[0].RuleTitle + " — " + where
	default:
		m.Subject = strconv.Itoa(len(batch)) + " notifications (highest: " + m.Severity.String() + ") — " + where
	}
	info := buildinfo.Get()
	v.Subject = m.Subject
	v.Footer = "Sent by Tesla Charger Monitoring " + info.Version + ". Manage alert rules and notifications in the web UI. " +
		"Tesla Charger Monitoring is an independent project, not affiliated with Tesla, Inc. Source: " + info.SourceLink()
	var tb, hb bytes.Buffer
	_ = textTpl.Execute(&tb, v) // templates are embedded and tested; data is plain strings
	_ = htmlTpl.Execute(&hb, v)
	m.Text, m.HTML = strings.TrimSpace(tb.String())+"\n", hb.String()
	return m
}
