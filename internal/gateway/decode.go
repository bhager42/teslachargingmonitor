// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package gateway

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

// Errors returned by the decoders.
var (
	ErrNotObject = errors.New("gateway: payload is not a JSON object")
	ErrNotArray  = errors.New("gateway: payload is not a JSON array")
)

// Limits on what a Report echoes back from an untrusted payload, and on how
// much nesting the decoder follows.
const (
	maxReportedUnknown = 64
	maxReportedKeyLen  = 64
	maxReasonLen       = 160
	maxArrayItems      = 64
)

// Report describes how well a payload matched the expected schema, like
// wallconnector.Report. Field names are dotted paths. A field listed in
// Invalid still holds the decoded value when the problem was its range;
// callers must treat such values as untrusted.
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

// Untrusted reports whether field is missing or invalid.
func (r Report) Untrusted(field string) bool { return r.IsMissing(field) || r.IsInvalid(field) }

// DecodeStatus decodes /api/status.
func DecodeStatus(data []byte) (Status, Report, error) {
	return decodeObj[Status](EndpointStatus, data)
}

// DecodeAggregates decodes /api/meters/aggregates.
func DecodeAggregates(data []byte) (Aggregates, Report, error) {
	return decodeObj[Aggregates](EndpointAggregates, data)
}

// DecodeSOE decodes /api/system_status/soe.
func DecodeSOE(data []byte) (SOE, Report, error) { return decodeObj[SOE](EndpointSOE, data) }

// DecodeGridStatus decodes /api/system_status/grid_status.
func DecodeGridStatus(data []byte) (GridStatus, Report, error) {
	return decodeObj[GridStatus](EndpointGridStatus, data)
}

// DecodeSystemStatus decodes /api/system_status.
func DecodeSystemStatus(data []byte) (SystemStatus, Report, error) {
	return decodeObj[SystemStatus](EndpointSystemStatus, data)
}

// DecodeOperation decodes /api/operation.
func DecodeOperation(data []byte) (Operation, Report, error) {
	return decodeObj[Operation](EndpointOperation, data)
}

// DecodeSitemaster decodes /api/sitemaster.
func DecodeSitemaster(data []byte) (Sitemaster, Report, error) {
	return decodeObj[Sitemaster](EndpointSitemaster, data)
}

// DecodeSiteInfo decodes /api/site_info.
func DecodeSiteInfo(data []byte) (SiteInfo, Report, error) {
	return decodeObj[SiteInfo](EndpointSiteInfo, data)
}

// DecodeSolars decodes /api/solars, a JSON array.
func DecodeSolars(data []byte) ([]Solar, Report, error) {
	rep := Report{Endpoint: EndpointSolars}
	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, rep, fmt.Errorf("%w: %s", ErrNotArray, truncate(err.Error(), maxReasonLen))
	}
	if items == nil {
		return nil, rep, ErrNotArray
	}
	v := reflect.ValueOf(&[]Solar{}).Elem()
	decodeSlice("", items, v, &rep)
	finish(&rep)
	return v.Interface().([]Solar), rep, nil //nolint:forcetypeassert // v was made from []Solar
}

func decodeObj[T any](ep Endpoint, data []byte) (T, Report, error) {
	var out T
	rep := Report{Endpoint: ep}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return out, rep, fmt.Errorf("%w: %s", ErrNotObject, truncate(err.Error(), maxReasonLen))
	}
	if raw == nil {
		return out, rep, ErrNotObject
	}
	decodeStruct("", raw, reflect.ValueOf(&out).Elem(), &rep)
	finish(&rep)
	return out, rep, nil
}

type fieldSpec struct {
	index    int
	name     string
	optional bool
	hasRange bool
	min, max float64
}

type typeSpec struct {
	fields  []fieldSpec
	ignored map[string]bool
}

type ignorer interface{ ignoredKeys() []string }

var specCache sync.Map // reflect.Type -> *typeSpec

func specFor(t reflect.Type) *typeSpec {
	if s, ok := specCache.Load(t); ok {
		return s.(*typeSpec) //nolint:forcetypeassert // only this function stores values
	}
	ts := &typeSpec{ignored: map[string]bool{}}
	if ig, ok := reflect.Zero(t).Interface().(ignorer); ok {
		for _, k := range ig.ignoredKeys() {
			ts.ignored[k] = true
		}
	}
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		spec := fieldSpec{index: i, name: name}
		if tag := f.Tag.Get("gw"); tag != "" {
			for opt := range strings.SplitSeq(tag, ",") {
				switch {
				case opt == "optional":
					spec.optional = true
				case strings.HasPrefix(opt, "range="):
					lo, hi, ok := strings.Cut(strings.TrimPrefix(opt, "range="), ":")
					minV, err1 := strconv.ParseFloat(lo, 64)
					maxV, err2 := strconv.ParseFloat(hi, 64)
					if !ok || err1 != nil || err2 != nil || minV > maxV {
						panic(fmt.Sprintf("gateway: bad range tag on %s.%s", t.Name(), f.Name))
					}
					spec.hasRange, spec.min, spec.max = true, minV, maxV
				default:
					panic(fmt.Sprintf("gateway: unknown gw tag option %q on %s.%s", opt, t.Name(), f.Name))
				}
			}
		}
		ts.fields = append(ts.fields, spec)
	}
	specCache.Store(t, ts)
	return ts
}

var (
	jsonNull = []byte("null")
	rawType  = reflect.TypeFor[json.RawMessage]()
)

// isRecord reports whether t is decoded field by field (a model struct)
// rather than with json.Unmarshal.
func isRecord(t reflect.Type) bool { return t.Kind() == reflect.Struct }

func decodeStruct(prefix string, raw map[string]json.RawMessage, v reflect.Value, rep *Report) {
	ts := specFor(v.Type())
	known := make(map[string]bool, len(ts.fields))
	for _, s := range ts.fields {
		known[s.name] = true
		path := prefix + s.name
		msg, ok := raw[s.name]
		if !ok || bytes.Equal(bytes.TrimSpace(msg), jsonNull) {
			if !s.optional {
				rep.Missing = append(rep.Missing, path)
			}
			continue
		}
		field := v.Field(s.index)
		switch ft := field.Type(); {
		case isRecord(ft):
			var sub map[string]json.RawMessage
			if err := json.Unmarshal(msg, &sub); err != nil || sub == nil {
				rep.Invalid = append(rep.Invalid, FieldError{Field: path, Reason: "expected a JSON object"})
				continue
			}
			decodeStruct(path+".", sub, field, rep)
			continue
		case ft.Kind() == reflect.Slice && isRecord(ft.Elem()):
			var items []json.RawMessage
			if err := json.Unmarshal(msg, &items); err != nil {
				rep.Invalid = append(rep.Invalid, FieldError{Field: path, Reason: "expected a JSON array"})
				continue
			}
			decodeSlice(path, items, field, rep)
			continue
		case ft.Kind() == reflect.Slice && ft.Elem() == rawType:
			var items []json.RawMessage
			if err := json.Unmarshal(msg, &items); err != nil {
				rep.Invalid = append(rep.Invalid, FieldError{Field: path, Reason: "expected a JSON array"})
				continue
			}
			if len(items) > maxArrayItems {
				items = items[:maxArrayItems]
			}
			field.Set(reflect.ValueOf(items))
			continue
		}
		tmp := reflect.New(field.Type())
		if err := json.Unmarshal(msg, tmp.Interface()); err != nil {
			rep.Invalid = append(rep.Invalid, FieldError{Field: path, Reason: typeReason(err)})
			continue
		}
		field.Set(tmp.Elem())
		if s.hasRange {
			if n, ok := numeric(field); ok && (n < s.min || n > s.max) {
				rep.Invalid = append(rep.Invalid, FieldError{
					Field:  path,
					Reason: fmt.Sprintf("value %g outside plausible range [%g, %g]", n, s.min, s.max),
				})
			}
		}
	}
	for k := range raw {
		if !known[k] && !ts.ignored[k] {
			rep.Unknown = append(rep.Unknown, prefix+truncate(k, maxReportedKeyLen))
		}
	}
}

// decodeSlice decodes items into v (a slice of model structs). Items that
// are not objects are reported and skipped; at most maxArrayItems are kept.
func decodeSlice(path string, items []json.RawMessage, v reflect.Value, rep *Report) {
	if len(items) > maxArrayItems {
		rep.Invalid = append(rep.Invalid, FieldError{Field: path, Reason: fmt.Sprintf("more than %d items; the rest are ignored", maxArrayItems)})
		items = items[:maxArrayItems]
	}
	out := reflect.MakeSlice(v.Type(), 0, len(items))
	for i, it := range items {
		ip := fmt.Sprintf("%s[%d]", path, i)
		var sub map[string]json.RawMessage
		if err := json.Unmarshal(it, &sub); err != nil || sub == nil {
			rep.Invalid = append(rep.Invalid, FieldError{Field: ip, Reason: "expected a JSON object"})
			continue
		}
		elem := reflect.New(v.Type().Elem()).Elem()
		decodeStruct(ip+".", sub, elem, rep)
		out = reflect.Append(out, elem)
	}
	v.Set(out)
}

func finish(rep *Report) {
	slices.Sort(rep.Unknown)
	if len(rep.Unknown) > maxReportedUnknown {
		rep.Unknown = append(rep.Unknown[:maxReportedUnknown], fmt.Sprintf("… and %d more", len(rep.Unknown)-maxReportedUnknown))
	}
	if len(rep.Invalid) > maxReportedUnknown {
		rep.Invalid = rep.Invalid[:maxReportedUnknown]
	}
	if len(rep.Missing) > maxReportedUnknown {
		rep.Missing = rep.Missing[:maxReportedUnknown]
	}
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
