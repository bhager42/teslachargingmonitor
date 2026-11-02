// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package cli

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/alerts"
	"github.com/bhager42/teslachargingmonitor/internal/notify"
	"github.com/bhager42/teslachargingmonitor/internal/secrets"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

func runNotify(ctx context.Context, args []string, env Env) int {
	if len(args) == 0 {
		notifyUsage(env)
		return 2
	}
	switch args[0] {
	case "add-email":
		return notifySave(ctx, args[1:], env, false)
	case "update":
		return notifySave(ctx, args[1:], env, true)
	case "list":
		return notifyList(ctx, args[1:], env)
	case "test":
		return notifyTest(ctx, args[1:], env)
	case "remove":
		return notifyRemove(ctx, args[1:], env)
	case "log":
		return notifyLog(ctx, args[1:], env)
	default:
		notifyUsage(env)
		return 2
	}
}

func notifyUsage(env Env) {
	_, _ = fmt.Fprint(env.Stderr, `Usage:
  tcmon notify add-email -username you@gmail.com -to you@gmail.com -password-stdin
  tcmon notify update ID [-to ...] [-password-stdin | -password-file F] [flags]
  tcmon notify list
  tcmon notify test ID
  tcmon notify remove ID -yes
  tcmon notify log [-limit 20]

Gmail is the default: smtp.gmail.com:587 with STARTTLS and a Google app
password (https://myaccount.google.com/apppasswords). Passwords are never
accepted as command-line arguments.
`)
}

// openDispatcher opens the store and the credential key.
func openDispatcher(ctx context.Context, env Env, dataDir string) (*store.Store, *notify.Dispatcher, error) {
	st, err := openStore(ctx, dataDir)
	if err != nil {
		return nil, nil, err
	}
	key, err := secrets.LoadOrCreateKey(secretKeyPath(env, dataDir), func(m string) { _, _ = fmt.Fprintln(env.Stderr, "warning:", m) })
	if err != nil {
		_ = st.Close()
		return nil, nil, err
	}
	box, err := secrets.NewBox(key)
	if err != nil {
		_ = st.Close()
		return nil, nil, err
	}
	roots, err := smtpRoots(env)
	if err != nil {
		_ = st.Close()
		return nil, nil, err
	}
	return st, notify.New(st, box, notify.Config{RootCAs: roots}), nil
}

// smtpRoots returns the system roots plus the PEM bundle in
// $TCMON_SMTP_CA_FILE (for a self-hosted mail server with a private CA),
// or nil (system roots) when unset.
func smtpRoots(env Env) (*x509.CertPool, error) {
	path := env.Getenv("TCMON_SMTP_CA_FILE")
	if path == "" {
		return nil, nil
	}
	pemBytes, err := os.ReadFile(path) //nolint:gosec // operator-configured CA bundle
	if err != nil {
		return nil, fmt.Errorf("reading TCMON_SMTP_CA_FILE: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("TCMON_SMTP_CA_FILE %s contains no PEM certificates", path)
	}
	return pool, nil
}

func readPassword(env Env, fromStdin bool, file string) (secrets.Secret, error) {
	var raw []byte
	var err error
	switch {
	case fromStdin && file != "":
		return "", errors.New("use either -password-stdin or -password-file")
	case fromStdin:
		raw, err = io.ReadAll(io.LimitReader(bufio.NewReader(env.Stdin), 1024))
	case file != "":
		raw, err = os.ReadFile(file) //nolint:gosec // operator-provided secret file
	default:
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	// Gmail shows app passwords in groups ("abcd efgh ijkl mnop"); spaces are not part of it.
	pw := strings.Join(strings.Fields(string(raw)), "")
	if pw == "" {
		return "", errors.New("password is empty")
	}
	return secrets.Secret(pw), nil
}

func notifySave(ctx context.Context, args []string, env Env, update bool) int {
	name := "notify add-email"
	if update {
		name = "notify update"
	}
	fs, dir := newFlagSet(name, env)
	def := notify.GmailPreset("")
	chName := fs.String("name", "Email", "channel name")
	username := fs.String("username", "", "SMTP username (Gmail: your full address)")
	to := fs.String("to", "", "comma-separated recipient addresses (max 10)")
	from := fs.String("from", "", "From address (default: username)")
	fromName := fs.String("from-name", def.FromName, "From display name")
	host := fs.String("host", def.Host, "SMTP server")
	port := fs.Int("port", def.Port, "SMTP port")
	security := fs.String("security", def.Security, `"starttls" (587) or "tls" (465)`)
	prefix := fs.String("subject-prefix", notify.DefaultSubjectPrefix, "subject prefix")
	minSev := fs.String("min-severity", "info", "only send info, warning or critical and above")
	quiet := fs.String("quiet-hours", "", `mute non-critical alerts, e.g. "22:00-07:00" (container time zone)`)
	enabled := fs.Bool("enabled", true, "send notifications through this channel")
	pwStdin := fs.Bool("password-stdin", false, "read the password (Gmail app password) from standard input")
	pwFile := fs.String("password-file", "", "read the password from a file (e.g. a Docker secret)")
	skipTest := fs.Bool("skip-test", false, "save without sending a test email")
	var err error
	if update {
		err = parseInterspersed(fs, args)
	} else {
		err = fs.Parse(args)
	}
	if err != nil {
		return 2
	}
	pw, err := readPassword(env, *pwStdin, *pwFile)
	if err != nil {
		return fail(env, "%v", err)
	}
	st, d, err := openDispatcher(ctx, env, *dir)
	if err != nil {
		return fail(env, "%v", err)
	}
	defer func() { _ = st.Close() }()

	var s notify.EmailSettings
	var id int64
	if update {
		if id, err = parseID(fs); err != nil {
			return fail(env, "%v", err)
		}
		cur, err := d.Channel(ctx, id)
		if err != nil {
			return fail(env, "channel %d: %v", id, err)
		}
		s = notify.EmailSettings{Name: cur.Name, Enabled: cur.Enabled, MinSeverity: cur.MinSeverity,
			QuietHours: cur.QuietHours, Email: cur.Email}
	} else {
		s = notify.EmailSettings{Name: *chName, Enabled: true, MinSeverity: alerts.Info, Email: def}
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	use := func(n string) bool { return !update || set[n] }
	if use("name") {
		s.Name = *chName
	}
	if use("username") {
		s.Email.Username = *username
		if !set["from"] {
			s.Email.From = *username
		}
	}
	if set["from"] {
		s.Email.From = *from
	}
	if use("to") {
		s.Email.To = nil
		for _, a := range strings.Split(*to, ",") {
			if a = strings.TrimSpace(a); a != "" {
				s.Email.To = append(s.Email.To, a)
			}
		}
	}
	if use("from-name") {
		s.Email.FromName = *fromName
	}
	if use("host") {
		s.Email.Host = *host
	}
	if use("port") {
		s.Email.Port = *port
	}
	if use("security") {
		s.Email.Security = *security
	}
	if use("subject-prefix") {
		s.Email.SubjectPrefix = *prefix
	}
	if use("min-severity") {
		if s.MinSeverity, err = alerts.ParseSeverity(*minSev); err != nil {
			return fail(env, "%v", err)
		}
	}
	if use("quiet-hours") {
		s.QuietHours = *quiet
	}
	if use("enabled") {
		s.Enabled = *enabled
	}
	s.Password = pw

	var ci notify.ChannelInfo
	if update {
		ci, err = d.UpdateEmailChannel(ctx, id, s)
	} else {
		ci, err = d.CreateEmailChannel(ctx, s)
	}
	if err != nil {
		return fail(env, "%v", err)
	}
	verb := "Added"
	if update {
		verb = "Updated"
	}
	_, _ = fmt.Fprintf(env.Stdout, "%s email channel %d (%s → %s).\n", verb, ci.ID, ci.Email.From, strings.Join(ci.Email.To, ", "))
	if *skipTest {
		return 0
	}
	_, _ = fmt.Fprintln(env.Stdout, "Sending a test email ...")
	if err := d.Test(ctx, ci.ID); err != nil {
		return fail(env, "test email failed: %s\nThe channel was saved; fix it with `tcmon notify update %d ...`", notify.Describe(err), ci.ID)
	}
	_, _ = fmt.Fprintln(env.Stdout, "Test email sent. Check your inbox (and spam folder).")
	return 0
}

func notifyList(ctx context.Context, args []string, env Env) int {
	fs, dir := newFlagSet("notify list", env)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	st, d, err := openDispatcher(ctx, env, *dir)
	if err != nil {
		return fail(env, "%v", err)
	}
	defer func() { _ = st.Close() }()
	chs, err := d.Channels(ctx)
	if err != nil {
		return fail(env, "%v", err)
	}
	if len(chs) == 0 {
		_, _ = fmt.Fprintln(env.Stdout, "No notification channels. Add Gmail with: tcmon notify add-email -username you@gmail.com -to you@gmail.com -password-stdin")
		return 0
	}
	tw := tabwriter.NewWriter(env.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tNAME\tENABLED\tSERVER\tFROM\tTO\tMIN\tQUIET\tPASSWORD\tLAST OK\tFAILURES\tLAST ERROR")
	for _, c := range chs {
		pw, last := "not set", "never"
		if c.PasswordSet {
			pw = "set"
		}
		if c.LastSuccess != nil {
			last = c.LastSuccess.Local().Format(time.DateTime)
		}
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%t\t%s:%d/%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n", c.ID, c.Name, c.Enabled,
			c.Email.Host, c.Email.Port, c.Email.Security, c.Email.From, strings.Join(c.Email.To, ","), c.MinSeverity,
			c.QuietHours, pw, last, c.ConsecutiveFailures, c.LastError)
	}
	_ = tw.Flush()
	return 0
}

func notifyTest(ctx context.Context, args []string, env Env) int {
	fs, dir := newFlagSet("notify test", env)
	if err := parseInterspersed(fs, args); err != nil {
		return 2
	}
	id, err := parseID(fs)
	if err != nil {
		return fail(env, "%v", err)
	}
	st, d, err := openDispatcher(ctx, env, *dir)
	if err != nil {
		return fail(env, "%v", err)
	}
	defer func() { _ = st.Close() }()
	if err := d.Test(ctx, id); err != nil {
		return fail(env, "test email failed: %s", notify.Describe(err))
	}
	_, _ = fmt.Fprintln(env.Stdout, "Test email sent.")
	return 0
}

func notifyRemove(ctx context.Context, args []string, env Env) int {
	fs, dir := newFlagSet("notify remove", env)
	yes := fs.Bool("yes", false, "confirm removal of the channel and its delivery log")
	if err := parseInterspersed(fs, args); err != nil {
		return 2
	}
	id, err := parseID(fs)
	if err != nil {
		return fail(env, "%v", err)
	}
	if !*yes {
		return fail(env, "re-run with -yes to remove channel %d", id)
	}
	st, d, err := openDispatcher(ctx, env, *dir)
	if err != nil {
		return fail(env, "%v", err)
	}
	defer func() { _ = st.Close() }()
	if err := d.DeleteChannel(ctx, id); err != nil {
		return fail(env, "channel %d: %v", id, err)
	}
	_, _ = fmt.Fprintf(env.Stdout, "Removed channel %d.\n", id)
	return 0
}

func notifyLog(ctx context.Context, args []string, env Env) int {
	fs, dir := newFlagSet("notify log", env)
	limit := fs.Int("limit", 20, "entries to show")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	st, err := openStore(ctx, *dir)
	if err != nil {
		return fail(env, "%v", err)
	}
	defer func() { _ = st.Close() }()
	ds, err := st.Deliveries(ctx, 0, *limit)
	if err != nil {
		return fail(env, "%v", err)
	}
	if len(ds) == 0 {
		_, _ = fmt.Fprintln(env.Stdout, "No notifications sent yet.")
		return 0
	}
	tw := tabwriter.NewWriter(env.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "CREATED\tCHANNEL\tSTATUS\tATTEMPTS\tSUBJECT\tLAST ERROR")
	for _, d := range ds {
		_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\t%d\t%s\t%s\n", d.CreatedAt.Local().Format(time.DateTime), d.ChannelID,
			d.Status, d.Attempts, d.Subject, d.LastError)
	}
	_ = tw.Flush()
	return 0
}
