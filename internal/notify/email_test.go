// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package notify

import (
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/alerts"
	"github.com/bhager42/teslachargingmonitor/internal/notify/smtpmock"
	"github.com/bhager42/teslachargingmonitor/internal/secrets"
)

const (
	user = "owner@gmail.com"
	pass = "abcd-efgh-ijkl-mnop"
)

var t0 = time.Date(2026, 11, 2, 18, 0, 0, 0, time.UTC)

func mock(t *testing.T, o smtpmock.Options) *smtpmock.Server {
	t.Helper()
	if o.Username == "" {
		o.Username, o.Password = user, pass
	}
	s, err := smtpmock.Start(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func cfgFor(s *smtpmock.Server, security string) EmailConfig {
	c := GmailPreset(user, "me@example.com", "partner@example.com")
	c.Host, c.Port, c.Security = s.Host, s.Port, security
	return c
}

func sender(s *smtpmock.Server, c EmailConfig, pw string) emailSender {
	return emailSender{cfg: c, password: secrets.Secret(pw), roots: s.RootCAs, timeout: 5 * time.Second,
		now: func() time.Time { return t0 }}
}

func testMsg() Message {
	return Build([]alerts.Notification{{RuleTitle: "Handle temperature high", DeviceName: "Garage",
		Kind: alerts.KindFiring, Severity: alerts.Warning, Message: "Handle temperature is 58.0 °C", At: t0}}, time.UTC)
}

func TestSendStartTLSAndImplicitTLS(t *testing.T) {
	for _, tc := range []struct {
		mode     smtpmock.Mode
		security string
	}{{smtpmock.StartTLS, SecurityStartTLS}, {smtpmock.ImplicitTLS, SecurityTLS}} {
		s := mock(t, smtpmock.Options{Mode: tc.mode})
		c := cfgFor(s, tc.security)
		if err := c.Normalize(); err != nil {
			t.Fatal(err)
		}
		if err := sender(s, c, pass).send(context.Background(), testMsg()); err != nil {
			t.Fatalf("%s: %v", tc.security, Describe(err))
		}
		msgs := s.Messages()
		if len(msgs) != 1 || !msgs[0].TLS || msgs[0].Auth != user || msgs[0].From != user || len(msgs[0].To) != 2 {
			t.Fatalf("%s: received %+v", tc.security, msgs)
		}
	}
}

func TestSendFailures(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name      string
		opts      smtpmock.Options
		security  string
		pw        string
		trustCA   bool
		permanent bool
		hint      string
		is        error
	}{
		{"wrong password", smtpmock.Options{}, SecurityStartTLS, "wrong", true, true, "app password, not your normal password", nil},
		{"gmail needs app password", smtpmock.Options{AuthError: "534 5.7.9 Application-specific password required"},
			SecurityStartTLS, pass, true, true, "myaccount.google.com/apppasswords", nil},
		{"rejected recipient", smtpmock.Options{Reject: []string{"partner@example.com"}}, SecurityStartTLS, pass, true, true,
			"recipient address was rejected", nil},
		{"plaintext refused", smtpmock.Options{Mode: smtpmock.PlainOnly}, SecurityStartTLS, pass, true, true,
			"does not support encryption", ErrPlaintextRefused},
		{"untrusted certificate", smtpmock.Options{}, SecurityStartTLS, pass, false, true, "certificate could not be verified", nil},
		{"temporary failure", smtpmock.Options{TempFail: 5}, SecurityStartTLS, pass, true, false, "temporarily unavailable", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := mock(t, tc.opts)
			snd := sender(s, cfgFor(s, tc.security), tc.pw)
			if !tc.trustCA {
				snd.roots = nil // system roots do not trust the mock's certificate
			}
			err := snd.send(ctx, testMsg())
			var se *SendError
			if !errors.As(err, &se) {
				t.Fatalf("err = %v, want *SendError", err)
			}
			if se.Permanent != tc.permanent || !strings.Contains(se.Hint, tc.hint) {
				t.Errorf("permanent=%v hint=%q (%v)", se.Permanent, se.Hint, err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("err = %v, want %v", err, tc.is)
			}
			if strings.Contains(Describe(err), pass) {
				t.Error("password leaked into error text")
			}
			if len(s.Messages()) != 0 {
				t.Error("message delivered despite failure")
			}
		})
	}
}

func TestConnectFailure(t *testing.T) {
	c := GmailPreset(user, "me@example.com")
	c.Host, c.Port = "127.0.0.1", 1
	err := emailSender{cfg: c, password: pass, timeout: 2 * time.Second, now: time.Now}.send(context.Background(), testMsg())
	var se *SendError
	if !errors.As(err, &se) || se.Permanent || !strings.Contains(se.Hint, "Connection refused") {
		t.Errorf("err = %v hint=%q", err, se.Hint)
	}
}

func TestComposeIsWellFormedAndSafe(t *testing.T) {
	c := GmailPreset(user, "me@example.com")
	_ = c.Normalize()
	m := Build([]alerts.Notification{{RuleTitle: "Rule\r\nBcc: evil@example.com", DeviceName: "Garage <b>",
		Kind: alerts.KindFiring, Severity: alerts.Critical, Message: "<script>alert(1)</script> 72 °C", At: t0}}, time.UTC)
	raw := compose(c, m, t0)
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	headers, _, _ := strings.Cut(string(raw), "\r\n\r\n")
	for _, line := range strings.Split(headers, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "bcc:") {
			t.Fatalf("header injection via rule title: %q", line)
		}
	}
	if msg.Header.Get("Bcc") != "" {
		t.Fatal("header injection via rule title")
	}
	dec := new(mime.WordDecoder)
	subj, _ := dec.DecodeHeader(msg.Header.Get("Subject"))
	if !strings.HasPrefix(subj, "[Tesla Charger Monitoring] CRITICAL: Rule Bcc: evil@example.com — Garage <b>") {
		t.Errorf("subject = %q", subj)
	}
	for k, want := range map[string]string{"Auto-Submitted": "auto-generated", "MIME-Version": "1.0", "To": "<me@example.com>"} {
		if got := msg.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if from, _ := mail.ParseAddress(msg.Header.Get("From")); from == nil || from.Address != user {
		t.Errorf("From = %q", msg.Header.Get("From"))
	}
	_, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	mr := multipart.NewReader(msg.Body, params["boundary"])
	var text, html string
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(p) // multipart decodes quoted-printable
		if strings.HasPrefix(p.Header.Get("Content-Type"), "text/html") {
			html = string(b)
		} else {
			text = string(b)
		}
	}
	if !strings.Contains(text, "<script>alert(1)</script> 72 °C") || !strings.Contains(text, "[CRITICAL]") ||
		!strings.Contains(text, "not affiliated with Tesla, Inc.") {
		t.Errorf("text part:\n%s", text)
	}
	if strings.Contains(html, "<script>") || !strings.Contains(html, "&lt;script&gt;") || !strings.Contains(html, "color-scheme") {
		t.Errorf("HTML part not escaped:\n%s", html)
	}
}

func TestBuildSubjects(t *testing.T) {
	n := alerts.Notification{RuleTitle: "Overcurrent", DeviceName: "Garage", Kind: alerts.KindFiring, Severity: alerts.Critical, At: t0}
	r := n
	r.Kind = alerts.KindResolved
	w := alerts.Notification{RuleTitle: "Weak Wi-Fi", DeviceName: "Garage", Kind: alerts.KindFiring, Severity: alerts.Info, At: t0}
	for _, tc := range []struct {
		batch []alerts.Notification
		want  string
		sev   alerts.Severity
	}{
		{[]alerts.Notification{n}, "CRITICAL: Overcurrent — Garage", alerts.Critical},
		{[]alerts.Notification{r}, "Resolved: Overcurrent — Garage", alerts.Critical},
		{[]alerts.Notification{w, n, w, w, w, w, w, w, w, w, w}, "11 notifications (highest: critical) — Garage", alerts.Critical},
	} {
		m := Build(tc.batch, time.UTC)
		if m.Subject != tc.want || m.Severity != tc.sev {
			t.Errorf("subject = %q sev=%v, want %q", m.Subject, m.Severity, tc.want)
		}
	}
}

func TestNormalize(t *testing.T) {
	good := GmailPreset("Owner@Gmail.com", "b@example.com", "a@example.com", "b@example.com")
	if err := good.Normalize(); err != nil || len(good.To) != 2 || good.To[0] != "a@example.com" || good.From != "Owner@Gmail.com" {
		t.Errorf("good = %+v, %v", good, err)
	}
	bad := []func(*EmailConfig){
		func(c *EmailConfig) { c.Host = "" },
		func(c *EmailConfig) { c.Host = "smtp.gmail.com\r\nX: y" },
		func(c *EmailConfig) { c.Port = 0 },
		func(c *EmailConfig) { c.Security = "none" },
		func(c *EmailConfig) { c.From = "not an address" },
		func(c *EmailConfig) { c.From = "Name <a@b.c>" },
		func(c *EmailConfig) { c.To = nil },
		func(c *EmailConfig) { c.To = []string{"x\r\nBcc: y@z"} },
		func(c *EmailConfig) { c.To = make([]string, MaxRecipients+1) },
		func(c *EmailConfig) { c.SubjectPrefix = "a\nb" },
		func(c *EmailConfig) { c.FromName = strings.Repeat("x", 65) },
	}
	for i, mut := range bad {
		c := GmailPreset(user, "a@example.com")
		mut(&c)
		if c.Normalize() == nil {
			t.Errorf("bad config %d accepted: %+v", i, c)
		}
	}
	p := GmailPreset(user)
	p.To = []string{"a@example.com"}
	p.SubjectPrefix = ""
	_ = p.Normalize()
	if p.SubjectPrefix != DefaultSubjectPrefix {
		t.Error("default subject prefix not applied")
	}
}
