// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Command gwcapture captures the local API of a Tesla Backup Gateway 2 into
// redacted test fixtures (Phase 9 step 9.0). Run it through
// scripts/capture-gateway.sh.
//
//	gwcapture -host 192.168.1.20 [-label day] [-pin SHA256HEX] [-out DIR]
//
// Safety properties:
//   - One login per run, never retried: the Gateway locks out repeated
//     failures. A rejected password ends the run.
//   - The customer password is read from standard input (hidden when it is a
//     terminal), never from arguments or the environment, and is never
//     printed. The session token is never printed or written.
//   - Only GET requests besides the login; nothing on the Gateway changes.
//   - The Gateway's self-signed certificate is pinned: the owner confirms its
//     SHA-256 fingerprint (or passes -pin), and every connection must present
//     that certificate.
//   - Connections are limited to LAN addresses (internal/netguard).
//   - Responses are redacted (internal/gateway/redact) and checked; nothing
//     is written if the check finds a possible identifier.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/gateway/redact"
	"github.com/bhager42/teslachargingmonitor/internal/netguard"
)

// endpoints are captured after login, in this order. All are GETs.
var endpoints = []string{
	"/api/meters/aggregates",
	"/api/meters/site",
	"/api/meters/solar",
	"/api/system_status/soe",
	"/api/system_status/grid_status",
	"/api/system_status",
	"/api/sitemaster",
	"/api/operation",
	"/api/site_info",
	"/api/powerwalls",
	"/api/solars",
	"/api/system/update/status",
}

const (
	maxBody  = 1 << 20
	timeout  = 10 * time.Second
	loginURL = "/api/login/Basic"
)

var (
	reLabel   = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	reVersion = regexp.MustCompile(`^\d+(\.\d+){1,3}`)
)

// ErrRedirect is returned when the Gateway answers with a redirect.
var ErrRedirect = errors.New("unexpected redirect")

type config struct {
	host  string
	label string
	pin   string
	out   string
}

// terminal abstracts the interactive parts so tests can drive them.
type terminal interface {
	confirm(prompt string) (bool, error)
	password(prompt string) (string, error)
}

func main() {
	// Ctrl-C keeps its default behavior (exit) so a blocked prompt can be
	// abandoned; password() restores terminal echo itself.
	ctx := context.Background()
	cfg, err := parseFlags(os.Args[1:], os.Stderr)
	if err != nil {
		os.Exit(2)
	}
	tty := &stdTerminal{in: bufio.NewReader(os.Stdin), out: os.Stderr}
	if err := run(ctx, cfg, tty, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "gwcapture:", err)
		os.Exit(1)
	}
}

func parseFlags(args []string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("gwcapture", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c config
	fs.StringVar(&c.host, "host", "", "Gateway IP address or host name on the LAN (required)")
	fs.StringVar(&c.label, "label", "", "suffix for the file names, e.g. day, night, charging (a-z, 0-9, -)")
	fs.StringVar(&c.pin, "pin", "", "expected SHA-256 fingerprint of the Gateway certificate (hex); asked for when empty")
	fs.StringVar(&c.out, "out", "testdata/fixtures/gateway", "output directory; files go in <out>/<firmware>/")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	switch {
	case fs.NArg() != 0:
		err := fmt.Errorf("unexpected arguments: %v (the password is prompted for, never an argument)", fs.Args())
		_, _ = fmt.Fprintln(stderr, err)
		return c, err
	case c.host == "" || strings.ContainsAny(c.host, "/?#@ "):
		err := errors.New("-host must be a bare IP address or host name")
		_, _ = fmt.Fprintln(stderr, err)
		return c, err
	case c.label != "" && !reLabel.MatchString(c.label):
		err := errors.New("-label may only contain a-z, 0-9 and '-'")
		_, _ = fmt.Fprintln(stderr, err)
		return c, err
	}
	c.pin = strings.ToLower(strings.ReplaceAll(c.pin, ":", ""))
	return c, nil
}

// fingerprint is the hex SHA-256 of a DER certificate.
func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func newClient(pin string) *http.Client {
	dialer := &net.Dialer{Timeout: timeout, ControlContext: netguard.DialControl(false)}
	tr := &http.Transport{
		Proxy:       nil,
		DialContext: dialer.DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// The Gateway's certificate is self-signed, so chain
			// verification is replaced by the pin check below.
			InsecureSkipVerify: true, //nolint:gosec // pinned in VerifyConnection
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("no certificate presented")
				}
				if pin != "" && fingerprint(cs.PeerCertificates[0].Raw) != pin {
					return errors.New("certificate fingerprint does not match the pin")
				}
				return nil
			},
		},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          1,
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRedirect },
	}
}

// probe returns the fingerprint of the certificate the Gateway presents.
func probe(ctx context.Context, base string) (string, error) {
	var fp string
	c := newClient("")
	c.Transport.(*http.Transport).TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("no certificate presented")
		}
		fp = fingerprint(cs.PeerCertificates[0].Raw)
		return nil
	}
	defer c.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, base+"/", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if fp != "" {
		if err == nil {
			_ = resp.Body.Close()
		}
		return fp, nil
	}
	if err != nil {
		return "", err
	}
	_ = resp.Body.Close()
	return "", errors.New("no certificate presented")
}

type response struct {
	Status int
	Doc    any // decoded JSON, nil when the body was not JSON
}

func get(ctx context.Context, c *http.Client, base, path, token string) (response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return response{}, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return do(c, req)
}

func do(c *http.Client, req *http.Request) (response, error) {
	resp, err := c.Do(req)
	if err != nil {
		return response{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return response{}, err
	}
	if len(raw) > maxBody {
		return response{}, fmt.Errorf("%s: response larger than %d bytes", req.URL.Path, maxBody)
	}
	r := response{Status: resp.StatusCode}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if d.Decode(&v) == nil {
		r.Doc = v
	}
	return r, nil
}

// login posts the customer credentials once and returns the token. The
// response's other fields (names, email) are discarded.
func login(ctx context.Context, c *http.Client, base, password string) (string, int, error) {
	body, err := json.Marshal(map[string]any{
		"username": "customer", "password": password,
		"email": "tcmon@example.com", "force_sm_off": false,
	})
	if err != nil {
		return "", 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+loginURL, bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	r, err := do(c, req)
	if err != nil {
		return "", 0, err
	}
	m, _ := r.Doc.(map[string]any)
	tok, _ := m["token"].(string)
	if r.Status != http.StatusOK || tok == "" {
		return "", r.Status, fmt.Errorf("login rejected (HTTP %d); not retrying, because the Gateway locks out repeated failures", r.Status)
	}
	return tok, r.Status, nil
}

// firmwareDir turns the Gateway's version string ("26.34.2 abc123") into a
// directory name ("26.34.2").
func firmwareDir(status any) (string, error) {
	m, _ := status.(map[string]any)
	v, _ := m["version"].(string)
	fw := reVersion.FindString(v)
	if fw == "" {
		return "", errors.New("could not read the firmware version from /api/status")
	}
	return fw, nil
}

func fileName(path, label string) string {
	name := strings.ReplaceAll(strings.TrimPrefix(path, "/api/"), "/", "_")
	if label != "" {
		name += "." + label
	}
	return name + ".json"
}

func run(ctx context.Context, cfg config, tty terminal, stdout io.Writer) error {
	base := "https://" + cfg.host
	if strings.Count(cfg.host, ":") > 1 && !strings.HasPrefix(cfg.host, "[") {
		base = "https://[" + cfg.host + "]"
	}

	pin := cfg.pin
	if pin == "" {
		fp, err := probe(ctx, base)
		if err != nil {
			return fmt.Errorf("connecting: %w", err)
		}
		ok, err := tty.confirm(fmt.Sprintf("Gateway certificate SHA-256: %s\nTrust this certificate for this capture?", fp))
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("certificate not trusted; nothing captured")
		}
		pin = fp
	}
	c := newClient(pin)
	defer c.CloseIdleConnections()

	docs := map[string]response{}
	status, err := get(ctx, c, base, "/api/status", "")
	if err != nil {
		return fmt.Errorf("/api/status: %w", err)
	}
	if status.Status != http.StatusOK {
		return fmt.Errorf("/api/status: HTTP %d", status.Status)
	}
	fw, err := firmwareDir(status.Doc)
	if err != nil {
		return err
	}
	docs["/api/status"] = status

	pw, err := tty.password("Gateway customer password (hidden): ")
	if err != nil {
		return err
	}
	if pw == "" {
		return errors.New("empty password; nothing captured")
	}
	token, _, err := login(ctx, c, base, pw)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, "login: ok")

	for _, p := range endpoints {
		r, err := get(ctx, c, base, p, token)
		if err != nil {
			_, _ = fmt.Fprintf(stdout, "%-32s error: %v\n", p, err)
			continue
		}
		docs[p] = r
	}
	// Best effort: end the session. Its response is ignored.
	_, _ = get(ctx, c, base, "/api/logout", token)

	return write(cfg, fw, docs, stdout)
}

// write redacts every document, checks the result and only then writes the
// files and an index of the HTTP status of each endpoint.
func write(cfg config, fw string, docs map[string]response, stdout io.Writer) error {
	r := redact.New()
	for _, d := range docs {
		if d.Doc != nil {
			r.Learn(d.Doc)
		}
	}
	paths := make([]string, 0, len(docs))
	for p := range docs {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	index := map[string]any{}
	files := map[string][]byte{}
	var problems []string
	for _, p := range paths {
		d := docs[p]
		entry := map[string]any{"status": d.Status}
		index[p] = entry
		if d.Doc == nil {
			entry["json"] = false
			continue
		}
		red := r.Apply(d.Doc)
		for _, prob := range redact.Check(red) {
			problems = append(problems, p+" "+prob)
		}
		b, err := marshal(red)
		if err != nil {
			return err
		}
		name := fileName(p, cfg.label)
		entry["file"] = name
		files[name] = b
	}
	if len(problems) > 0 {
		return fmt.Errorf("redaction check failed; nothing written:\n  %s", strings.Join(problems, "\n  "))
	}
	ib, err := marshal(index)
	if err != nil {
		return err
	}
	idx := "index.json"
	if cfg.label != "" {
		idx = "index." + cfg.label + ".json"
	}
	files[idx] = ib

	dir := filepath.Join(cfg.out, fw)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), files[n], 0o600); err != nil {
			return err
		}
	}
	for _, p := range paths {
		d := docs[p]
		_, _ = fmt.Fprintf(stdout, "%-32s HTTP %d %s\n", p, d.Status, shape(d.Doc))
	}
	_, _ = fmt.Fprintf(stdout, "\nWrote %d redacted files to %s\n", len(names), dir)
	_, _ = fmt.Fprintln(stdout, "Review them, then run 'make test' (it re-checks redaction) before committing.")
	return nil
}

func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// shape summarizes a document by its top-level keys, never its values.
func shape(v any) string {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return "{" + strings.Join(keys, ", ") + "}"
	case []any:
		return fmt.Sprintf("[%d items]", len(x))
	case nil:
		return "(not JSON)"
	default:
		return fmt.Sprintf("%T", v)
	}
}

// stdTerminal prompts on stderr and reads from stdin, turning echo off for
// the password when stdin is a terminal.
type stdTerminal struct {
	in  *bufio.Reader
	out io.Writer
}

func (t *stdTerminal) line() (string, error) {
	s, err := t.in.ReadString('\n')
	if err != nil && (s == "" || !errors.Is(err, io.EOF)) {
		return "", fmt.Errorf("reading input: %w", err)
	}
	return strings.TrimRight(s, "\r\n"), nil
}

func (t *stdTerminal) confirm(prompt string) (bool, error) {
	_, _ = fmt.Fprint(t.out, prompt+" [y/N] ")
	s, err := t.line()
	if err != nil {
		return false, err
	}
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "y" || s == "yes", nil
}

func (t *stdTerminal) password(prompt string) (string, error) {
	_, _ = fmt.Fprint(t.out, prompt)
	if isTerminal(os.Stdin) {
		if err := stty("-echo"); err != nil {
			return "", fmt.Errorf("cannot hide input (%w); not reading the password", err)
		}
		// Restore echo even if the user presses Ctrl-C at the prompt.
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		done := make(chan struct{})
		go func() {
			select {
			case <-sig:
				_ = stty("echo")
				_, _ = fmt.Fprintln(t.out)
				os.Exit(130)
			case <-done:
			}
		}()
		defer func() {
			signal.Stop(sig)
			close(done)
			_ = stty("echo")
			_, _ = fmt.Fprintln(t.out)
		}()
	}
	return t.line()
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func stty(arg string) error {
	cmd := exec.CommandContext(context.Background(), "stty", arg) //nolint:gosec // fixed arguments
	cmd.Stdin = os.Stdin
	return cmd.Run()
}
