// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package secrets encrypts credentials at rest (AES-256-GCM) with a key
// kept in a separate file, and provides a Secret string type that never
// prints, logs or serializes its value by accident.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

// KeySize is the AES-256 key length.
const KeySize = 32

const formatV1 = 1

// ErrDecrypt means a ciphertext could not be authenticated with the key.
var ErrDecrypt = errors.New("secrets: cannot decrypt (wrong or rotated key, or corrupted data)")

// LoadOrCreateKey reads the key file at path, creating it with a random key
// and mode 0600 if it does not exist. It refuses keys of the wrong length.
// warn is called if the file is readable by group or others.
func LoadOrCreateKey(path string, warn func(msg string)) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("secrets: creating key directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // operator-configured path
	if err == nil {
		key := make([]byte, KeySize)
		if _, err := rand.Read(key); err != nil {
			_ = f.Close()
			return nil, err
		}
		if _, err := f.Write(key); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("secrets: writing key: %w", err)
		}
		return key, f.Close()
	}
	if !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("secrets: creating key file: %w", err)
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 && warn != nil {
		warn(fmt.Sprintf("secret key file %s is accessible by other users (mode %o); run chmod 600", path, fi.Mode().Perm()))
	}
	key, err := os.ReadFile(path) //nolint:gosec // operator-configured path
	if err != nil {
		return nil, fmt.Errorf("secrets: reading key file: %w", err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("secrets: key file %s must contain exactly %d bytes, has %d", path, KeySize, len(key))
	}
	return key, nil
}

// Box seals and opens small secrets.
type Box struct{ aead cipher.AEAD }

// NewBox returns a Box for a 32-byte key.
func NewBox(key []byte) (*Box, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("secrets: key must be %d bytes", KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts plaintext bound to aad: version byte | nonce | ciphertext.
func (b *Box) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := append([]byte{formatV1}, nonce...)
	return b.aead.Seal(out, nonce, plaintext, aad), nil
}

// Open decrypts a value produced by Seal with the same aad.
func (b *Box) Open(sealed, aad []byte) ([]byte, error) {
	ns := b.aead.NonceSize()
	if len(sealed) < 1+ns+b.aead.Overhead() || sealed[0] != formatV1 {
		return nil, ErrDecrypt
	}
	pt, err := b.aead.Open(nil, sealed[1:1+ns], sealed[1+ns:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// Secret holds a credential. Its String, GoString, LogValue, Format and
// MarshalJSON forms are redacted; use Reveal where the value is needed.
type Secret string

const redacted = "[redacted]"

// Reveal returns the actual value.
func (s Secret) Reveal() string { return string(s) }

// IsSet reports whether a value is present.
func (s Secret) IsSet() bool { return s != "" }

// String returns a redacted placeholder.
func (s Secret) String() string { return redacted }

// GoString returns a redacted placeholder (for %#v).
func (s Secret) GoString() string { return redacted }

// LogValue implements slog.LogValuer.
func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// Format implements fmt.Formatter so %v, %s, %q, %#v and %x are all redacted.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// MarshalJSON prevents a Secret from reaching an API response or log.
func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
