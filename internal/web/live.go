// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package web

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/alerts"
	"github.com/bhager42/teslachargingmonitor/internal/auth"
	"github.com/bhager42/teslachargingmonitor/internal/poller"
)

// liveEvent is one Server-Sent Event.
type liveEvent struct {
	name string
	data []byte
}

// Hub fans live events out to connected browsers.
type Hub struct {
	mu   sync.Mutex
	subs map[chan liveEvent]struct{}
}

// NewHub returns an empty hub.
func NewHub() *Hub { return &Hub{subs: map[chan liveEvent]struct{}{}} }

func (h *Hub) publish(name string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- liveEvent{name, b}:
		default: // slow browser: it will catch up on the next event
		}
	}
}

func (h *Hub) subscribe() (chan liveEvent, func()) {
	ch := make(chan liveEvent, 16)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}

// Clients returns the number of connected browsers.
func (h *Hub) Clients() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// HandleUpdate publishes a refreshed device card after every poll.
func (s *Server) HandleUpdate(u poller.Update) {
	if s.hub == nil {
		return
	}
	ctx, cancel := contextWithTimeout()
	defer cancel()
	d, err := s.st.Device(ctx, u.Device.ID)
	if err != nil {
		return
	}
	s.hub.publish("device", s.cardFor(ctx, d, s.display(ctx).TempUnit))
}

// HandleAlerts tells browsers about new alert notifications.
func (s *Server) HandleAlerts(batch []alerts.Notification) {
	if s.hub == nil || len(batch) == 0 {
		return
	}
	type item struct {
		Title, Severity, Kind, Device, Message string
	}
	out := make([]item, 0, len(batch))
	for _, n := range batch {
		out = append(out, item{n.RuleTitle, n.Severity.String(), n.Kind, n.DeviceName, n.Message})
	}
	s.hub.publish("alerts", out)
}

const ssePing = 25 * time.Second

// events streams live updates (text/event-stream) to a signed-in browser.
func (s *Server) events(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // long-lived stream: no write timeout
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("retry: 10000\n\n"))
	if err := rc.Flush(); err != nil || s.hub == nil {
		return
	}
	ch, unsub := s.hub.subscribe()
	defer unsub()
	ping := time.NewTicker(ssePing)
	defer ping.Stop()
	cookie, _ := r.Cookie(s.cfg.cookieName())
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			// End the stream when the session expires or is revoked.
			if cookie == nil {
				return
			}
			if _, err := s.auth.Session(r.Context(), cookie.Value); err != nil {
				return
			}
			_, _ = w.Write([]byte(": ping\n\n"))
		case ev := <-ch:
			_, _ = w.Write([]byte("event: " + ev.name + "\ndata: "))
			_, _ = w.Write(ev.data)
			_, _ = w.Write([]byte("\n\n"))
		}
		if err := rc.Flush(); err != nil {
			return
		}
	}
}

// allCards builds the dashboard cards.
func (s *Server) allCards(r *http.Request) []DeviceCard {
	ctx := r.Context()
	unit := s.display(ctx).TempUnit
	devices, _ := s.st.Devices(ctx)
	cards := make([]DeviceCard, 0, len(devices))
	for _, d := range devices {
		cards = append(cards, s.cardFor(ctx, d, unit))
	}
	return cards
}
