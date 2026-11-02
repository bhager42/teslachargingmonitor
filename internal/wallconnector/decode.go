// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package wallconnector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// ErrNotObject means the payload was not a JSON object.
var ErrNotObject = errors.New("wallconnector: payload is not a JSON object")

// Limits on what a Report will echo back from an untrusted payload.
const (
	maxReportedUnknown = 64
	maxReportedKeyLen  = 64
	maxReasonLen       = 160
)

// Report describes how well a payload matched the expected schema. A field
// listed in Invalid still holds the decoded value when the problem was its
// range; callers must treat such values as untrusted.
type Report struct {
	Endpoint Endpoint
	Unknown  []string // keys present in the payload but not modeled (sorted)
	Missing  []string // expected keys that were absent or null
	Invalid  []FieldError
}

// FieldError describes a problem with a single field.
type FieldError struct {
	Field  string
	Reason string
}

func (e FieldError) String() string { return e.Field + ": " + e.Reason }

// Clean reports whether the payload matched the schema exactly.
func (r Report) Clean() bool {
	return len(r.Unknown) == 0 && len(r.Missing) == 0 && len(r.Invalid) == 0
}

// IsInvalid reports whether field has a recorded problem.
func (r Report) IsInvalid(field string) bool {
	return slices.ContainsFunc(r.Invalid, func(e FieldError) bool { return e.Field == field })
}

// IsMissing reports whether field was expected but absent.
func (r Report) IsMissing(field string) bool { return slices.Contains(r.Missing, field) }

// DecodeVitals decodes a /api/1/vitals payload.
func DecodeVitals(data []byte) (Vitals, Report, error) {
	var v Vitals
	rep, err := decodeInto(EndpointVitals, data, &v)
	return v, rep, err
}

// DecodeLifetime decodes a /api/1/lifetime payload.
func DecodeLifetime(data []byte) (Lifetime, Report, error) {
	var v Lifetime
	rep, err := decodeInto(EndpointLifetime, data, &v)
	return v, rep, err
}

// DecodeWifiStatus decodes a /api/1/wifi_status payload.
func DecodeWifiStatus(data []byte) (WifiStatus, Report, error) {
	var v WifiStatus
	rep, err := decodeInto(EndpointWifiStatus, data, &v)
	return v, rep, err
}

// DecodeVersion decodes a /api/1/version payload.
func DecodeVersion(data []byte) (Version, Report, error) {
	var v Version
	rep, err := decodeInto(EndpointVersion, data, &v)
	return v, rep, err
}

type fieldSpec struct {
	index    int
	name     string
	optional bool
	hasRange bool
	min, max float64
}

var specCache sync.Map // reflect.Type -> []fieldSpec

func specsFor(t reflect.Type) []fieldSpec {
	if s, ok := specCache.Load(t); ok {
		return s.([]fieldSpec) //nolint:forcetypeassert // only this function stores values
	}
	var specs []fieldSpec
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		spec := fieldSpec{index: i, name: name}
		if tag := f.Tag.Get("wc"); tag != "" {
			for opt := range strings.SplitSeq(tag, ",") {
				switch {
				case opt == "optional":
					spec.optional = true
				case strings.HasPrefix(opt, "range="):
					lo, hi, ok := strings.Cut(strings.TrimPrefix(opt, "range="), ":")
					minV, err1 := strconv.ParseFloat(lo, 64)
					maxV, err2 := strconv.ParseFloat(hi, 64)
					if !ok || err1 != nil || err2 != nil || minV > maxV {
						panic(fmt.Sprintf("wallconnector: bad range tag on %s.%s", t.Name(), f.Name))
					}
					spec.hasRange, spec.min, spec.max = true, minV, maxV
				default:
					panic(fmt.Sprintf("wallconnector: unknown wc tag option %q on %s.%s", opt, t.Name(), f.Name))
				}
			}
		}
		specs = append(specs, spec)
	}
	specCache.Store(t, specs)
	return specs
}

var jsonNull = []byte("null")

func decodeInto(endpoint Endpoint, data []byte, dst any) (Report, error) {
	rep := Report{Endpoint: endpoint}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return rep, fmt.Errorf("%w: %s", ErrNotObject, truncate(err.Error(), maxReasonLen))
	}
	if raw == nil {
		return rep, ErrNotObject
	}

	v := reflect.ValueOf(dst).Elem()
	specs := specsFor(v.Type())
	known := make(map[string]struct{}, len(specs))
	for _, s := range specs {
		known[s.name] = struct{}{}
		msg, ok := raw[s.name]
		if !ok || bytes.Equal(bytes.TrimSpace(msg), jsonNull) {
			if !s.optional {
				rep.Missing = append(rep.Missing, s.name)
			}
			continue
		}
		field := v.Field(s.index)
		tmp := reflect.New(field.Type())
		if err := json.Unmarshal(msg, tmp.Interface()); err != nil {
			rep.Invalid = append(rep.Invalid, FieldError{Field: s.name, Reason: typeReason(err)})
			continue
		}
		field.Set(tmp.Elem())
		if s.hasRange {
			if n, ok := numeric(field); ok && (n < s.min || n > s.max) {
				rep.Invalid = append(rep.Invalid, FieldError{
					Field:  s.name,
					Reason: fmt.Sprintf("value %g outside plausible range [%g, %g]", n, s.min, s.max),
				})
			}
		}
	}

	for k := range raw {
		if _, ok := known[k]; !ok {
			rep.Unknown = append(rep.Unknown, truncate(k, maxReportedKeyLen))
		}
	}
	slices.Sort(rep.Unknown)
	if len(rep.Unknown) > maxReportedUnknown {
		rep.Unknown = append(rep.Unknown[:maxReportedUnknown], fmt.Sprintf("… and %d more", len(rep.Unknown)-maxReportedUnknown))
	}
	return rep, nil
}

func typeReason(err error) string {
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		return fmt.Sprintf("expected %s, got JSON %s", te.Type, te.Value)
	}
	return truncate(err.Error(), maxReasonLen)
}

func numeric(v reflect.Value) (float64, bool) {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return 0, false
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Float32, reflect.Float64:
		return v.Float(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(v.Int()), true
	default:
		return 0, false
	}
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
