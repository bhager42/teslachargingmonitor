// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package notify delivers alert notifications. Email (SMTP, Gmail preset)
// is the primary channel (owner decision D7/D11); messages are queued in
// SQLite and retried, and credentials are encrypted at rest.
package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/secrets"
)

// Security modes for SMTP. Plaintext SMTP is never supported.
const (
	SecurityStartTLS = "starttls" // port 587
	SecurityTLS      = "tls"      // implicit TLS, port 465
)

// EmailConfig is the non-secret part of an email channel.
type EmailConfig struct {
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	Security      string   `json:"security"`
	Username      string   `json:"username"`
	From          string   `json:"from"`
	FromName      string   `json:"from_name"`
	To            []string `json:"to"`
	SubjectPrefix string   `json:"subject_prefix"`
}

// DefaultSubjectPrefix starts every subject.
const DefaultSubjectPrefix = "[Tesla Charger Monitoring]"

// MaxRecipients bounds the To list.
const MaxRecipients = 10

// GmailPreset returns settings for a personal Gmail account. Gmail needs an
// app password (2-Step Verification on); the From address must be the
// account or a verified "Send mail as" alias, so it defaults to username.
func GmailPreset(username string, to ...string) EmailConfig {
	return EmailConfig{
		Host: "smtp.gmail.com", Port: 587, Security: SecurityStartTLS,
		Username: username, From: username, FromName: "Tesla Charger Monitoring",
		To: to, SubjectPrefix: DefaultSubjectPrefix,
	}
}

func noCRLF(s string) bool { return !strings.ContainsAny(s, "\r\n\x00") }

// Normalize validates the configuration and canonicalizes addresses.
func (c *EmailConfig) Normalize() error {
	c.Host = strings.ToLower(strings.TrimSpace(c.Host))
	if c.Host == "" || len(c.Host) > 253 || !noCRLF(c.Host) || strings.ContainsAny(c.Host, " /:@") {
		return errors.New("SMTP server must be a hostname or IP address")
	}
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("SMTP port must be 1-65535")
	}
	if c.Security != SecurityStartTLS && c.Security != SecurityTLS {
		return errors.New(`security must be "starttls" (port 587) or "tls" (port 465); plaintext SMTP is not supported`)
	}
	if !noCRLF(c.Username) || len(c.Username) > 254 {
		return errors.New("invalid username")
	}
	from, err := mail.ParseAddress(c.From)
	if err != nil || from.Name != "" {
		return fmt.Errorf("invalid From address %q", c.From)
	}
	c.From = from.Address
	if !noCRLF(c.FromName) || len([]rune(c.FromName)) > 64 {
		return errors.New("the From name must be at most 64 characters on one line")
	}
	if len(c.To) == 0 || len(c.To) > MaxRecipients {
		return fmt.Errorf("enter 1-%d recipient addresses", MaxRecipients)
	}
	for i, to := range c.To {
		a, err := mail.ParseAddress(strings.TrimSpace(to))
		if err != nil || a.Name != "" {
			return fmt.Errorf("invalid recipient address %q", to)
		}
		c.To[i] = a.Address
	}
	slices.Sort(c.To)
	c.To = slices.Compact(c.To)
	if c.SubjectPrefix == "" {
		c.SubjectPrefix = DefaultSubjectPrefix
	}
	if !noCRLF(c.SubjectPrefix) || len([]rune(c.SubjectPrefix)) > 64 {
		return errors.New("subject prefix must be at most 64 characters on one line")
	}
	return nil
}

// ErrPlaintextRefused means the server did not offer STARTTLS; we never
// send credentials or alerts unencrypted.
var ErrPlaintextRefused = errors.New("SMTP server does not offer STARTTLS; refusing to send without encryption")

// SendError classifies a delivery failure.
type SendError struct {
	Err       error
	Permanent bool   // retrying will not help (bad credentials, rejected recipient, ...)
	Hint      string // plain-English advice for the UI
}

func (e *SendError) Error() string { return e.Err.Error() }
func (e *SendError) Unwrap() error { return e.Err }

func classify(err error, stage string) *SendError {
	if err == nil {
		return nil
	}
	se := &SendError{Err: fmt.Errorf("%s: %w", stage, err)}
	var tp *textproto.Error
	var cert *tls.CertificateVerificationError
	var unk x509.UnknownAuthorityError
	var host x509.HostnameError
	var dns *net.DNSError
	switch {
	case errors.Is(err, ErrPlaintextRefused):
		se.Permanent, se.Hint = true, "The server does not support encryption on this port. For Gmail use smtp.gmail.com, port 587, STARTTLS."
	case errors.As(err, &tp):
		se.Permanent = tp.Code >= 500
		msg := strings.ToLower(tp.Msg)
		switch {
		case strings.Contains(msg, "5.7.9") || strings.Contains(msg, "application-specific password"):
			se.Hint = "Gmail requires an app password: turn on 2-Step Verification, then create one at https://myaccount.google.com/apppasswords and paste it here."
		case tp.Code == 535 || tp.Code == 534:
			se.Hint = "The username or password was rejected. For Gmail, use your full address and a 16-character app password, not your normal password."
		case stage == "recipient":
			se.Hint = "A recipient address was rejected by the mail server. Check the To addresses."
		case tp.Code == 530:
			se.Hint = "The server requires authentication. Enter a username and password."
		case tp.Code == 550 || tp.Code == 553 || tp.Code == 554:
			se.Hint = "The message was rejected. For Gmail, the From address must be your Gmail address or a verified alias."
		case tp.Code >= 400 && tp.Code < 500:
			se.Hint = "The mail server is temporarily unavailable; delivery will be retried."
		}
	case errors.As(err, &cert), errors.As(err, &unk), errors.As(err, &host):
		se.Permanent, se.Hint = true, "The mail server's TLS certificate could not be verified. Check the server name."
	case errors.As(err, &dns):
		se.Hint = "The mail server name could not be resolved. Check the SMTP server and the container's DNS."
	default:
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			se.Hint = "Timed out connecting to the mail server. Check the port and that outbound SMTP is allowed."
		} else if strings.Contains(err.Error(), "connection refused") {
			se.Hint = "Connection refused. Check the SMTP server and port."
		}
	}
	return se
}

// emailSender sends one message with one configuration.
type emailSender struct {
	cfg      EmailConfig
	password secrets.Secret
	roots    *x509.CertPool // nil = system roots
	timeout  time.Duration
	now      func() time.Time
}

func (s emailSender) send(ctx context.Context, m Message) error {
	if s.timeout == 0 {
		s.timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return classify(err, "connect")
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	tlsCfg := &tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12, RootCAs: s.roots}
	if s.cfg.Security == SecurityTLS {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return classify(err, "TLS handshake")
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		return classify(err, "greeting")
	}
	defer func() { _ = c.Close() }()
	if err := c.Hello(localName()); err != nil {
		return classify(err, "EHLO")
	}
	if s.cfg.Security == SecurityStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return classify(ErrPlaintextRefused, "STARTTLS")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return classify(err, "STARTTLS")
		}
	}
	if s.cfg.Username != "" {
		if ok, _ := c.Extension("AUTH"); !ok {
			return classify(errors.New("server does not offer AUTH"), "authentication")
		}
		// PlainAuth itself also refuses to authenticate without TLS.
		if err := c.Auth(smtp.PlainAuth("", s.cfg.Username, s.password.Reveal(), s.cfg.Host)); err != nil {
			return classify(err, "authentication")
		}
	}
	if err := c.Mail(s.cfg.From); err != nil {
		return classify(err, "sender")
	}
	for _, to := range s.cfg.To {
		if err := c.Rcpt(to); err != nil {
			return classify(fmt.Errorf("%s: %w", to, err), "recipient")
		}
	}
	w, err := c.Data()
	if err != nil {
		return classify(err, "data")
	}
	if _, err := w.Write(compose(s.cfg, m, s.now())); err != nil {
		return classify(err, "data")
	}
	if err := w.Close(); err != nil {
		return classify(err, "data")
	}
	_ = c.Quit()
	return nil
}

func localName() string {
	h, err := os.Hostname()
	if err != nil || h == "" || !noCRLF(h) || strings.ContainsAny(h, " ") {
		return "tcmon.localdomain"
	}
	return h
}

// compose renders an RFC 5322 multipart/alternative message.
func compose(cfg EmailConfig, m Message, now time.Time) []byte {
	var b bytes.Buffer
	hdr := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	from := (&mail.Address{Name: cfg.FromName, Address: cfg.From}).String()
	tos := make([]string, len(cfg.To))
	for i, t := range cfg.To {
		tos[i] = (&mail.Address{Address: t}).String()
	}
	subject := strings.Join(strings.Fields(cfg.SubjectPrefix+" "+m.Subject), " ") // also strips CR/LF
	boundary := randomHex(16)
	domain := cfg.From[strings.LastIndexByte(cfg.From, '@')+1:]
	hdr("From", from)
	hdr("To", strings.Join(tos, ", "))
	hdr("Subject", mime.QEncoding.Encode("utf-8", subject))
	hdr("Date", now.Format(time.RFC1123Z))
	hdr("Message-ID", "<"+randomHex(16)+"@"+domain+">")
	hdr("MIME-Version", "1.0")
	hdr("Auto-Submitted", "auto-generated")
	hdr("X-Auto-Response-Suppress", "All")
	hdr("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	b.WriteString("\r\n")
	part := func(ctype, body string) {
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: " + ctype + "; charset=utf-8\r\n")
		b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		qp := quotedprintable.NewWriter(&b)
		_, _ = qp.Write([]byte(strings.ReplaceAll(body, "\n", "\r\n")))
		_ = qp.Close()
		b.WriteString("\r\n")
	}
	part("text/plain", m.Text)
	if m.HTML != "" {
		part("text/html", m.HTML)
	}
	b.WriteString("--" + boundary + "--\r\n")
	return b.Bytes()
}

func randomHex(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}
