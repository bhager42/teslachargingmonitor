// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package auth implements the single-password login: Argon2id hashing,
// a NIST SP 800-63B-aligned password policy, the first-run setup token,
// sessions and login throttling.
package auth

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	_ "embed" // common password list
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// Params are Argon2id cost parameters.
type Params struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

// DefaultParams exceed the OWASP minimum (m=19 MiB, t=2, p=1).
var DefaultParams = Params{MemoryKiB: 64 * 1024, Time: 3, Threads: 1}

const (
	saltLen = 16
	keyLen  = 32
)

// ErrInvalidHash means a stored hash could not be parsed.
var ErrInvalidHash = errors.New("auth: invalid password hash")

func prepare(password string) []byte { return []byte(norm.NFKC.String(password)) }

// Hash returns a PHC-format Argon2id hash of password.
func Hash(password string, p Params) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey(prepare(password), salt, p.Time, p.MemoryKiB, p.Threads, keyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.MemoryKiB, p.Time, p.Threads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

func parse(hash string) (Params, []byte, []byte, error) {
	var p Params
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return p, nil, nil, ErrInvalidHash
	}
	var v int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return p, nil, nil, ErrInvalidHash
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Time, &p.Threads); err != nil ||
		p.MemoryKiB < 8*1024 || p.MemoryKiB > 4*1024*1024 || p.Time < 1 || p.Time > 64 || p.Threads < 1 {
		return p, nil, nil, ErrInvalidHash
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	key, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(key) < 16 || len(key) > 64 {
		return p, nil, nil, ErrInvalidHash
	}
	return p, salt, key, nil
}

// ValidHash reports whether hash is a well-formed Argon2id PHC string.
func ValidHash(hash string) bool {
	_, _, _, err := parse(hash)
	return err == nil
}

// Verify checks password against hash in constant time. needsRehash is true
// when the hash uses weaker parameters than want.
func Verify(hash, password string, want Params) (ok, needsRehash bool, err error) {
	p, salt, key, err := parse(hash)
	if err != nil {
		return false, false, err
	}
	got := argon2.IDKey(prepare(password), salt, p.Time, p.MemoryKiB, p.Threads, uint32(len(key))) //nolint:gosec // len ≤ 64
	ok = subtle.ConstantTimeCompare(got, key) == 1
	needsRehash = p.MemoryKiB < want.MemoryKiB || p.Time < want.Time || p.Threads < want.Threads
	return ok, needsRehash, nil
}

var (
	dummyOnce sync.Once
	dummyHash string
)

// VerifyDummy spends the same time as Verify when no password is set, so
// response timing does not reveal setup state.
func VerifyDummy(password string, p Params) {
	dummyOnce.Do(func() { dummyHash, _ = Hash("dummy-password-for-timing", p) })
	_, _, _ = Verify(dummyHash, password, p)
}

// Password policy (NIST SP 800-63B-4): length only, no composition rules,
// block common/breached passwords and context words.
const (
	MinPasswordLength = 12
	MaxPasswordLength = 128
)

//go:embed data/common-passwords.txt
var commonPasswordsTxt []byte

var (
	commonOnce      sync.Once
	commonPasswords map[string]struct{}
)

func isCommon(pw string) bool {
	commonOnce.Do(func() {
		commonPasswords = make(map[string]struct{}, 50000)
		sc := bufio.NewScanner(bytes.NewReader(commonPasswordsTxt))
		for sc.Scan() {
			commonPasswords[sc.Text()] = struct{}{}
		}
	})
	_, ok := commonPasswords[strings.ToLower(pw)]
	return ok
}

var contextWords = []string{"tcmon", "tesla", "wallconnector", "wall connector", "charger", "password", "passw0rd"}

// PolicyError explains why a password was rejected (safe to show).
type PolicyError struct{ Reason string }

func (e *PolicyError) Error() string { return e.Reason }

// CheckPolicy returns a *PolicyError when password is not acceptable.
func CheckPolicy(password string) error {
	if reason := policyReason(password); reason != "" {
		return &PolicyError{Reason: reason}
	}
	return nil
}

func policyReason(password string) string {
	pw := norm.NFKC.String(password)
	n := utf8.RuneCountInString(pw)
	switch {
	case !utf8.ValidString(password):
		return "password contains invalid characters"
	case n < MinPasswordLength:
		return fmt.Sprintf("use at least %d characters (a few unrelated words work well)", MinPasswordLength)
	case n > MaxPasswordLength:
		return fmt.Sprintf("use at most %d characters", MaxPasswordLength)
	case isCommon(pw):
		return "this password appears in lists of commonly used passwords; choose another"
	}
	lower := strings.ToLower(pw)
	for _, w := range contextWords {
		if strings.Contains(lower, w) && utf8.RuneCountInString(strings.ReplaceAll(lower, w, "")) < MinPasswordLength {
			return fmt.Sprintf("avoid building the password around %q", w)
		}
	}
	if strings.Count(pw, string([]rune(pw)[0])) == n {
		return "a password of one repeated character is too easy to guess"
	}
	return ""
}
