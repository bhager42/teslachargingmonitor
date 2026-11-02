// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package wallconnector_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
	"github.com/bhager42/teslachargingmonitor/internal/wcsim"
)

func clientFor(t *testing.T, h http.Handler, opts wallconnector.Options) *wallconnector.Client {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	addr, err := wallconnector.ParseAddress(ts.URL, wallconnector.AddressOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return wallconnector.NewClient(addr, opts)
}

func simClient(t *testing.T, scenario string, opts wallconnector.Options) *wallconnector.Client {
	t.Helper()
	sim, err := wcsim.NewServer(wcsim.Options{Scenario: scenario})
	if err != nil {
		t.Fatal(err)
	}
	sim.SlowDelay = 2 * time.Second
	return clientFor(t, sim, opts)
}

func TestSnapshotAgainstSimulator(t *testing.T) {
	c := simClient(t, "idle", wallconnector.Options{})
	snap, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, ep := range wallconnector.Endpoints {
		if rep := snap.Reports[ep]; !rep.Clean() {
			t.Errorf("%s report: %+v", ep, rep)
		}
		if len(snap.Raw[ep]) == 0 {
			t.Errorf("%s raw payload missing", ep)
		}
	}
	if snap.Vitals.GridV != 240.1 || snap.Lifetime.EnergyWh < 433293 || snap.Version.PartNumber != "1734412-52-F" {
		t.Errorf("unexpected snapshot: %+v", snap)
	}
}

func TestProbe(t *testing.T) {
	c := simClient(t, "idle", wallconnector.Options{})
	res, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Firmware.Short() != "26.26.10" || res.MaskedSerial != "•••••••••0000" {
		t.Errorf("probe = %+v", res)
	}

	notWC := clientFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"hello":"router"}`))
	}), wallconnector.Options{})
	if _, err := notWC.Probe(context.Background()); !errors.Is(err, wallconnector.ErrNotWallConnector) {
		t.Errorf("non-WC JSON: err = %v", err)
	}
	html := clientFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html>router login</html>`))
	}), wallconnector.Options{})
	if _, err := html.Probe(context.Background()); !errors.Is(err, wallconnector.ErrNotWallConnector) {
		t.Errorf("HTML page: err = %v", err)
	}
	missing := clientFor(t, http.NotFoundHandler(), wallconnector.Options{})
	if _, err := missing.Probe(context.Background()); !errors.Is(err, wallconnector.ErrNotWallConnector) {
		t.Errorf("404: err = %v", err)
	}
}

func TestClientFailureModes(t *testing.T) {
	ctx := context.Background()

	t.Run("offline", func(t *testing.T) {
		c := simClient(t, "offline", wallconnector.Options{})
		if _, _, err := c.Vitals(ctx); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("slow device times out", func(t *testing.T) {
		c := simClient(t, "slow", wallconnector.Options{Timeout: 200 * time.Millisecond})
		start := time.Now()
		if _, _, err := c.Vitals(ctx); err == nil {
			t.Error("expected timeout")
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("timeout took %v", d)
		}
	})
	t.Run("malformed JSON", func(t *testing.T) {
		c := simClient(t, "malformed", wallconnector.Options{})
		if _, _, err := c.Vitals(ctx); !errors.Is(err, wallconnector.ErrNotObject) {
			t.Errorf("err = %v, want ErrNotObject", err)
		}
	})
	t.Run("redirects are not followed", func(t *testing.T) {
		c := clientFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
		}), wallconnector.Options{})
		if _, err := c.Fetch(ctx, wallconnector.EndpointVitals); !errors.Is(err, wallconnector.ErrRedirect) {
			t.Errorf("err = %v, want ErrRedirect", err)
		}
	})
	t.Run("oversized body", func(t *testing.T) {
		c := clientFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"x":"` + strings.Repeat("a", 2000) + `"}`))
		}), wallconnector.Options{MaxBodyBytes: 1024})
		if _, err := c.Fetch(ctx, wallconnector.EndpointVitals); !errors.Is(err, wallconnector.ErrBodyTooLarge) {
			t.Errorf("err = %v, want ErrBodyTooLarge", err)
		}
	})
	t.Run("non-200", func(t *testing.T) {
		c := clientFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "busy", http.StatusServiceUnavailable)
		}), wallconnector.Options{})
		var se *wallconnector.StatusError
		if _, err := c.Fetch(ctx, wallconnector.EndpointVitals); !errors.As(err, &se) || se.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("non-JSON body", func(t *testing.T) {
		c := clientFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`OK`))
		}), wallconnector.Options{})
		if _, err := c.Fetch(ctx, wallconnector.EndpointVitals); !errors.Is(err, wallconnector.ErrNotJSON) {
			t.Errorf("err = %v, want ErrNotJSON", err)
		}
	})
	t.Run("headers sent", func(t *testing.T) {
		var ua, accept string
		c := clientFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ua, accept = r.UserAgent(), r.Header.Get("Accept")
			_, _ = w.Write([]byte(`{}`))
		}), wallconnector.Options{UserAgent: "tcmon/test"})
		_, _ = c.Fetch(ctx, wallconnector.EndpointVitals)
		if ua != "tcmon/test" || accept != "application/json" {
			t.Errorf("ua=%q accept=%q", ua, accept)
		}
	})
	t.Run("non-LAN target refused at connect time", func(t *testing.T) {
		addr, err := wallconnector.ParseAddress("192.0.2.1", wallconnector.AddressOptions{AllowNonLAN: true})
		if err != nil {
			t.Fatal(err)
		}
		c := wallconnector.NewClient(addr, wallconnector.Options{Timeout: time.Second})
		if _, err := c.Fetch(ctx, wallconnector.EndpointVitals); !errors.Is(err, wallconnector.ErrBlockedAddress) {
			t.Errorf("err = %v, want ErrBlockedAddress", err)
		}
	})
}
