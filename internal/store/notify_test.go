// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNotifyChannelsAndDeliveries(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	ch, err := s.CreateNotifyChannel(ctx, NotifyChannel{Type: "email", Name: "Gmail", Enabled: true, MinSeverity: "info",
		Config: []byte(`{"host":"smtp.gmail.com"}`), SecretEnc: []byte{1, 2, 3}}, t0)
	if err != nil || ch.ID == 0 || string(ch.Config) != `{"host":"smtp.gmail.com"}` || len(ch.SecretEnc) != 3 {
		t.Fatalf("create = %+v, %v", ch, err)
	}
	if _, err := s.CreateNotifyChannel(ctx, NotifyChannel{Type: "sms", Name: "x", Config: []byte(`{}`)}, t0); err == nil {
		t.Error("unknown channel type accepted by schema")
	}
	ch.Name, ch.QuietHours = "Gmail 2", "22:00-07:00"
	if err := s.UpdateNotifyChannel(ctx, ch, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateNotifyChannel(ctx, NotifyChannel{ID: 99, Name: "x", Config: []byte(`{}`)}, t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("update missing = %v", err)
	}
	_ = s.RecordChannelResult(ctx, ch.ID, false, "boom", t0)
	_ = s.RecordChannelResult(ctx, ch.ID, false, "boom", t0)
	got, _ := s.NotifyChannel(ctx, ch.ID)
	if got.Name != "Gmail 2" || got.ConsecutiveFailures != 2 || got.LastError != "boom" || got.LastErrorAt == nil || got.LastSuccess != nil {
		t.Errorf("after failures = %+v", got)
	}
	_ = s.RecordChannelResult(ctx, ch.ID, true, "", t0.Add(time.Hour))
	if got, _ := s.NotifyChannel(ctx, ch.ID); got.ConsecutiveFailures != 0 || got.LastSuccess == nil {
		t.Errorf("after success = %+v", got)
	}

	ds := []Delivery{
		{ChannelID: ch.ID, CreatedAt: t0, NextAttempt: t0, Subject: "a", MessageJSON: []byte(`{}`), EventIDs: []int64{1, 2}},
		{ChannelID: ch.ID, CreatedAt: t0, NextAttempt: t0.Add(time.Hour), Subject: "b", MessageJSON: []byte(`{}`)},
	}
	if err := s.EnqueueDeliveries(ctx, ds); err != nil || ds[0].ID == 0 {
		t.Fatal(err)
	}
	due, _ := s.DueDeliveries(ctx, t0, 10)
	if len(due) != 1 || due[0].Subject != "a" || len(due[0].EventIDs) != 2 {
		t.Errorf("due = %+v", due)
	}
	if next, ok, _ := s.NextDeliveryAt(ctx); !ok || !next.Equal(t0) {
		t.Errorf("next = %v %v", next, ok)
	}
	_ = s.MarkDeliveryRetry(ctx, ds[0].ID, 1, t0.Add(5*time.Minute), "temp")
	_ = s.MarkDeliverySent(ctx, ds[0].ID, 2, t0.Add(6*time.Minute))
	_ = s.MarkDeliveryFailed(ctx, ds[1].ID, 3, "auth")
	log, _ := s.Deliveries(ctx, 0, 10)
	if len(log) != 2 {
		t.Fatalf("log = %+v", log)
	}
	for _, d := range log {
		switch d.Subject {
		case "a":
			if d.Status != DeliverySent || d.Attempts != 2 || d.SentAt == nil || d.LastError != "" {
				t.Errorf("sent = %+v", d)
			}
		case "b":
			if d.Status != DeliveryFailed || d.LastError != "auth" {
				t.Errorf("failed = %+v", d)
			}
		}
	}
	if _, ok, _ := s.NextDeliveryAt(ctx); ok {
		t.Error("no pending deliveries expected")
	}

	// Pruning keeps pending messages however old they are.
	pending := []Delivery{{ChannelID: ch.ID, CreatedAt: t0, NextAttempt: t0, Subject: "c", MessageJSON: []byte(`{}`)}}
	_ = s.EnqueueDeliveries(ctx, pending)
	res, err := s.Prune(ctx, t0.Add(200*24*time.Hour), DefaultRetention())
	if err != nil || res["notify_deliveries"] != 2 {
		t.Errorf("pruned = %v, %v", res, err)
	}
	if left, _ := s.Deliveries(ctx, ch.ID, 10); len(left) != 1 || left[0].Status != DeliveryPending {
		t.Errorf("left = %+v", left)
	}

	if err := s.DeleteNotifyChannel(ctx, ch.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteNotifyChannel(ctx, ch.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("double delete = %v", err)
	}
	if left, _ := s.Deliveries(ctx, 0, 10); len(left) != 0 {
		t.Error("deliveries survived channel deletion")
	}
	if list, _ := s.NotifyChannels(ctx); len(list) != 0 {
		t.Error("channel not deleted")
	}
}
