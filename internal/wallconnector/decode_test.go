// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package wallconnector

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const uwcFixtures = "../../testdata/fixtures/uwc/26.26.10"

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(uwcFixtures, name)) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDecodeUWCFixtures(t *testing.T) {
	t.Run("vitals idle", func(t *testing.T) {
		v, rep, err := DecodeVitals(readFixture(t, "vitals.json"))
		if err != nil || !rep.Clean() {
			t.Fatalf("err=%v report=%+v", err, rep)
		}
		if v.GridV != 240.1 || v.GridHz != 59.798 || v.HandleTempC != 20.1 || v.EVSEState != 1 || v.ConfigStatus != 5 {
			t.Errorf("unexpected values: %+v", v)
		}
		if v.RelayK1V == nil || v.RelayK2V == nil || v.RelayCoilV != nil {
			t.Errorf("UWC should report relay_k1_v/relay_k2_v but not relay_coil_v: %+v", v)
		}
		if !slices.Equal(v.EVSENotReadyReasons, UnpluggedNotReadyReasons) || len(v.CurrentAlerts) != 0 {
			t.Errorf("reasons=%v alerts=%v", v.EVSENotReadyReasons, v.CurrentAlerts)
		}
	})
	t.Run("vitals charging", func(t *testing.T) {
		v, rep, err := DecodeVitals(readFixture(t, "vitals.charging.json"))
		if err != nil || !rep.Clean() {
			t.Fatalf("err=%v report=%+v", err, rep)
		}
		if !v.ContactorClosed || !v.VehicleConnected || v.VehicleCurrentA != 47.4 || v.CurrentBA != 47.4 || v.EVSEState != 11 {
			t.Errorf("unexpected values: %+v", v)
		}
		if v.RelayK1V == nil || *v.RelayK1V != 5.8 || v.RelayK2V == nil || *v.RelayK2V != 0 {
			t.Errorf("relays = %v / %v", v.RelayK1V, v.RelayK2V)
		}
		if got := EVSEStateInfo(v.EVSEState); !got.Known || got.Label != "Charging" {
			t.Errorf("evse_state 11 = %+v", got)
		}
		if !slices.Equal(v.EVSENotReadyReasons, []int{1}) {
			t.Errorf("reasons=%v", v.EVSENotReadyReasons)
		}
	})
	t.Run("lifetime", func(t *testing.T) {
		l, rep, err := DecodeLifetime(readFixture(t, "lifetime.json"))
		if err != nil || !rep.Clean() {
			t.Fatalf("err=%v report=%+v", err, rep)
		}
		if l.EnergyWh != 433293 || l.AlertCount != 3 || l.ChargeStarts != 42 || l.ChargingTimeS != 137862 {
			t.Errorf("unexpected values: %+v", l)
		}
	})
	t.Run("wifi_status", func(t *testing.T) {
		w, rep, err := DecodeWifiStatus(readFixture(t, "wifi_status.json"))
		if err != nil || !rep.Clean() {
			t.Fatalf("err=%v report=%+v", err, rep)
		}
		if ssid, err := w.SSID(); err != nil || ssid != "REDACTED" {
			t.Errorf("SSID() = %q, %v", ssid, err)
		}
		if w.WifiRSSI != -47 || !w.Internet {
			t.Errorf("unexpected values: %+v", w)
		}
	})
	t.Run("version", func(t *testing.T) {
		v, rep, err := DecodeVersion(readFixture(t, "version.json"))
		if err != nil || !rep.Clean() {
			t.Fatalf("err=%v report=%+v", err, rep)
		}
		fw, err := v.Firmware()
		if err != nil || fw.Short() != "26.26.10" || fw.Build != "g42855ec9b9cd1" {
			t.Errorf("firmware = %+v, %v", fw, err)
		}
		if gp := v.GridProfile(); gp.IsZero() || gp.VfTrips != "BB5EABC5" {
			t.Errorf("grid profile = %+v", gp)
		}
	})
}

// Every fixture in the repository must decode without errors (new firmware
// captures are picked up automatically).
func TestAllFixturesDecode(t *testing.T) {
	files, err := filepath.Glob("../../testdata/fixtures/*/*/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	for _, f := range files {
		t.Run(filepath.ToSlash(f), func(t *testing.T) {
			b, err := os.ReadFile(f) //nolint:gosec // test fixture path
			if err != nil {
				t.Fatal(err)
			}
			base := filepath.Base(f)
			var rep Report
			switch {
			case strings.HasPrefix(base, "vitals"):
				_, rep, err = DecodeVitals(b)
			case base == "lifetime.json":
				_, rep, err = DecodeLifetime(b)
			case base == "wifi_status.json":
				_, rep, err = DecodeWifiStatus(b)
			case base == "version.json":
				_, rep, err = DecodeVersion(b)
			default:
				t.Skip("not an endpoint fixture")
			}
			if err != nil || len(rep.Invalid) > 0 || len(rep.Missing) > 0 {
				t.Fatalf("err=%v report=%+v", err, rep)
			}
			if len(rep.Unknown) > 0 {
				t.Logf("new fields seen (add them to models.go): %v", rep.Unknown)
			}
		})
	}
}

func TestDecodeTolerance(t *testing.T) {
	t.Run("unknown missing and invalid fields are reported", func(t *testing.T) {
		v, rep, err := DecodeVitals([]byte(`{"grid_v":"high","handle_temp_c":999,"pcba_temp_c":30.5,"brand_new_field":1,"relay_k1_v":null}`))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(rep.Unknown, []string{"brand_new_field"}) {
			t.Errorf("Unknown = %v", rep.Unknown)
		}
		if !rep.IsInvalid("grid_v") || !rep.IsInvalid("handle_temp_c") {
			t.Errorf("Invalid = %v", rep.Invalid)
		}
		if v.HandleTempC != 999 {
			t.Errorf("out-of-range value should be kept for the caller to judge, got %v", v.HandleTempC)
		}
		if v.PCBATempC != 30.5 {
			t.Errorf("valid fields must still decode, got %v", v.PCBATempC)
		}
		if !rep.IsMissing("mcu_temp_c") || rep.IsMissing("relay_k1_v") || rep.IsMissing("relay_coil_v") {
			t.Errorf("Missing = %v", rep.Missing)
		}
		if rep.Clean() {
			t.Error("report should not be clean")
		}
	})
	t.Run("non-objects are rejected", func(t *testing.T) {
		for _, in := range []string{``, `null`, `[]`, `"x"`, `{`, `<html>`} {
			if _, _, err := DecodeVitals([]byte(in)); err == nil {
				t.Errorf("%q: expected error", in)
			}
		}
	})
	t.Run("unknown keys are capped and truncated", func(t *testing.T) {
		var sb strings.Builder
		sb.WriteString("{")
		for i := range 100 {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(`"` + strings.Repeat("k", 100) + string(rune('A'+i%26)) + string(rune('a'+i/26)) + `":1`)
		}
		sb.WriteString("}")
		_, rep, err := DecodeLifetime([]byte(sb.String()))
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Unknown) != maxReportedUnknown+1 {
			t.Errorf("len(Unknown) = %d", len(rep.Unknown))
		}
		if len([]rune(rep.Unknown[0])) > maxReportedKeyLen+1 {
			t.Errorf("key not truncated: %q", rep.Unknown[0])
		}
	})
}

func TestSSID(t *testing.T) {
	if _, err := (WifiStatus{WifiSSIDBase64: "!!!"}).SSID(); err == nil {
		t.Error("invalid base64 accepted")
	}
	long := strings.Repeat("QUFB", 20) // 60 bytes decoded
	if _, err := (WifiStatus{WifiSSIDBase64: long}).SSID(); err == nil {
		t.Error("over-long SSID accepted")
	}
	if s, err := (WifiStatus{WifiSSIDBase64: "PHNjcmlwdD4="}).SSID(); err != nil || s != "<script>" {
		t.Errorf("SSID decoding changed text: %q %v (escaping is the renderer's job)", s, err)
	}
}

func TestMaskSerial(t *testing.T) {
	tests := map[string]string{"B7S26197J00390": "••••••••••0390", "ab": "••••", "": "••••"}
	for in, want := range tests {
		if got := MaskSerial(in); got != want {
			t.Errorf("MaskSerial(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCodes(t *testing.T) {
	if c := EVSEStateInfo(1); !c.Known || c.Label != "Idle (no vehicle)" {
		t.Errorf("EVSEStateInfo(1) = %+v", c)
	}
	if c := EVSEStateInfo(42); c.Known || c.Label != "Unknown (code 42)" {
		t.Errorf("EVSEStateInfo(42) = %+v", c)
	}
	if c := EVSEStateInfo(4); !c.Known || c.Label != "Connected, not charging" {
		t.Errorf("EVSEStateInfo(4) = %+v", c)
	}
	if c := NotReadyReasonInfo(1); c.Known {
		t.Error("not-ready reason meanings are not yet confirmed and must not be guessed")
	}
	if c := NotReadyReasonInfo(2); c.Known {
		t.Error("not-ready reason meanings are not yet confirmed and must not be guessed")
	}
	if c := ConfigStatusInfo(5); !c.Known || c.String() != "Configured" {
		t.Errorf("ConfigStatusInfo(5) = %+v", c)
	}
	if c := AlertInfo(7); c.Known {
		t.Errorf("AlertInfo(7) = %+v", c)
	}
}
