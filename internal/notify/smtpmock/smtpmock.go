// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package smtpmock is a minimal in-process SMTP server for tests. It
// supports STARTTLS, implicit TLS, AUTH PLAIN, rejected recipients, a
// plaintext-only mode (to prove the client refuses it) and Gmail-style
// authentication errors. It is not for production use.
package smtpmock

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// Mode selects how the server offers TLS.
type Mode int

// Modes.
const (
	StartTLS    Mode = iota // plain connection that advertises STARTTLS
	ImplicitTLS             // TLS from the first byte (port 465 style)
	PlainOnly               // never offers TLS
)

// Options configures a Server.
type Options struct {
	Mode     Mode
	Username string
	Password string
	// AuthError, if set, is returned for every AUTH attempt (e.g.
	// "534 5.7.9 Application-specific password required").
	AuthError string
	// Reject lists recipient addresses answered with 550.
	Reject []string
	// TempFail makes the first N MAIL commands fail with 421 (transient).
	TempFail int
}

// Message is one received email.
type Message struct {
	From string
	To   []string
	Data []byte
	TLS  bool
	Auth string // authenticated username
}

// Server is a running mock SMTP server.
type Server struct {
	Addr string
	Host string
	Port int
	// RootCAs trusts the server's self-signed certificate; CAPEM is the
	// same certificate PEM-encoded.
	RootCAs *x509.CertPool
	CAPEM   []byte

	opts   Options
	ln     net.Listener
	tlsCfg *tls.Config
	mu     sync.Mutex
	msgs   []Message
	temp   int
	wg     sync.WaitGroup
}

// Start listens on 127.0.0.1 with a fresh self-signed certificate for
// "localhost" and 127.0.0.1.
func Start(opts Options) (*Server, error) {
	cert, pool, err := selfSigned()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test server
	if err != nil {
		return nil, err
	}
	s := &Server{opts: opts, ln: ln, RootCAs: pool, temp: opts.TempFail,
		CAPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}),
		tlsCfg: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	addr := ln.Addr().(*net.TCPAddr) //nolint:forcetypeassert // TCP listener
	s.Addr, s.Host, s.Port = addr.String(), "localhost", addr.Port
	s.wg.Go(s.serve)
	return s, nil
}

// Close stops the server.
func (s *Server) Close() {
	_ = s.ln.Close()
	s.wg.Wait()
}

// Messages returns the emails received so far.
func (s *Server) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.msgs...)
}

func (s *Server) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Go(func() { s.handle(c) })
	}
}

type session struct {
	conn net.Conn
	r    *bufio.Reader
	tls  bool
	auth string
	from string
	to   []string
}

func (ss *session) reply(format string, a ...any) {
	_, _ = fmt.Fprintf(ss.conn, format+"\r\n", a...)
}

func (ss *session) line() (string, error) {
	l, err := ss.r.ReadString('\n')
	return strings.TrimRight(l, "\r\n"), err
}

func (s *Server) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	ss := &session{conn: c}
	if s.opts.Mode == ImplicitTLS {
		tc := tls.Server(c, s.tlsCfg)
		if err := tc.HandshakeContext(context.Background()); err != nil {
			return
		}
		ss.conn, ss.tls = tc, true
	}
	ss.r = bufio.NewReader(ss.conn)
	ss.reply("220 localhost mock ESMTP")
	for {
		l, err := ss.line()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(l, " ")
		switch strings.ToUpper(verb) {
		case "EHLO", "HELO":
			ss.reply("250-localhost")
			if s.opts.Mode == StartTLS && !ss.tls {
				ss.reply("250-STARTTLS")
			}
			if ss.tls || s.opts.Mode == PlainOnly {
				ss.reply("250-AUTH PLAIN")
			}
			ss.reply("250 8BITMIME")
		case "STARTTLS":
			if s.opts.Mode != StartTLS || ss.tls {
				ss.reply("502 5.5.1 not supported")
				continue
			}
			ss.reply("220 2.0.0 ready")
			tc := tls.Server(ss.conn, s.tlsCfg)
			if err := tc.HandshakeContext(context.Background()); err != nil {
				return
			}
			ss.conn, ss.tls, ss.r = tc, true, bufio.NewReader(tc)
		case "AUTH":
			s.auth(ss, arg)
		case "MAIL":
			s.mu.Lock()
			temp := s.temp > 0
			if temp {
				s.temp--
			}
			s.mu.Unlock()
			switch {
			case temp:
				ss.reply("421 4.7.0 try again later")
			case s.opts.Username != "" && ss.auth == "":
				ss.reply("530 5.7.0 Authentication Required")
			default:
				ss.from, ss.to = addr(arg), nil
				ss.reply("250 2.1.0 OK")
			}
		case "RCPT":
			to := addr(arg)
			rejected := false
			for _, r := range s.opts.Reject {
				rejected = rejected || strings.EqualFold(r, to)
			}
			if rejected {
				ss.reply("550 5.1.1 The email account that you tried to reach does not exist")
				continue
			}
			ss.to = append(ss.to, to)
			ss.reply("250 2.1.5 OK")
		case "DATA":
			ss.reply("354 go ahead")
			var buf bytes.Buffer
			for {
				l, err := ss.line()
				if err != nil {
					return
				}
				if l == "." {
					break
				}
				buf.WriteString(strings.TrimPrefix(l, ".") + "\r\n")
			}
			s.mu.Lock()
			s.msgs = append(s.msgs, Message{From: ss.from, To: ss.to, Data: buf.Bytes(), TLS: ss.tls, Auth: ss.auth})
			s.mu.Unlock()
			ss.reply("250 2.0.0 OK queued")
		case "RSET":
			ss.from, ss.to = "", nil
			ss.reply("250 OK")
		case "NOOP":
			ss.reply("250 OK")
		case "QUIT":
			ss.reply("221 2.0.0 bye")
			return
		default:
			ss.reply("502 5.5.2 unrecognized command")
		}
	}
}

func (s *Server) auth(ss *session, arg string) {
	mech, initial, _ := strings.Cut(arg, " ")
	if !strings.EqualFold(mech, "PLAIN") {
		ss.reply("504 5.5.4 unrecognized auth type")
		return
	}
	if initial == "" {
		ss.reply("334 ")
		l, err := ss.line()
		if err != nil {
			return
		}
		initial = l
	}
	if s.opts.AuthError != "" {
		ss.reply("%s", s.opts.AuthError)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(initial)
	parts := strings.Split(string(raw), "\x00")
	if err != nil || len(parts) != 3 || parts[1] != s.opts.Username || parts[2] != s.opts.Password {
		ss.reply("535 5.7.8 Username and Password not accepted")
		return
	}
	ss.auth = parts[1]
	ss.reply("235 2.7.0 Accepted")
}

func addr(arg string) string {
	if i, j := strings.Index(arg, "<"), strings.Index(arg, ">"); i >= 0 && j > i {
		return arg[i+1 : j]
	}
	return arg
}

func selfSigned() (tls.Certificate, *x509.CertPool, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "smtpmock"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool, nil
}
