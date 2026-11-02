// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Self-signed certificate lifetime and renewal margin.
const (
	certValidity = 825 * 24 * time.Hour
	certRenewal  = 30 * 24 * time.Hour
)

// CertSource provides the serving certificate. In auto mode it creates
// and renews a self-signed ECDSA P-256 certificate under dir.
type CertSource struct {
	auto      bool
	certPath  string
	keyPath   string
	hostnames []string
	now       func() time.Time

	mu   sync.RWMutex
	cert *tls.Certificate
}

// NewAutoCert loads or creates a self-signed certificate in dir with SANs
// for hostnames (DNS names or IPs) plus localhost and 127.0.0.1.
func NewAutoCert(dir string, hostnames []string, now func() time.Time) (*CertSource, error) {
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	c := &CertSource{auto: true, certPath: filepath.Join(dir, "cert.pem"), keyPath: filepath.Join(dir, "key.pem"),
		hostnames: hostnames, now: now}
	return c, c.ensure()
}

// NewFileCert loads a user-provided certificate and key.
func NewFileCert(certPath, keyPath string) (*CertSource, error) {
	c := &CertSource{certPath: certPath, keyPath: keyPath, now: time.Now}
	return c, c.load()
}

func (c *CertSource) load() error {
	pair, err := tls.LoadX509KeyPair(c.certPath, c.keyPath)
	if err != nil {
		return fmt.Errorf("web: loading TLS certificate: %w", err)
	}
	if pair.Leaf == nil {
		if pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return err
		}
	}
	c.mu.Lock()
	c.cert = &pair
	c.mu.Unlock()
	return nil
}

func (c *CertSource) wantSANs() (dns []string, ips []net.IP) {
	dns = []string{"localhost"}
	ips = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	for _, h := range c.hostnames {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, strings.ToLower(h))
		}
	}
	return dns, ips
}

// ensure loads the auto certificate, (re)generating it when missing,
// close to expiry, or lacking a configured hostname.
func (c *CertSource) ensure() error {
	if err := c.load(); err == nil {
		leaf := c.Leaf()
		fresh := c.now().Add(certRenewal).Before(leaf.NotAfter)
		dns, ips := c.wantSANs()
		covers := true
		for _, d := range dns {
			covers = covers && leaf.VerifyHostname(d) == nil
		}
		for _, ip := range ips {
			covers = covers && leaf.VerifyHostname(ip.String()) == nil
		}
		if fresh && covers {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "no such file") {
		return err
	}
	return c.generate()
}

func (c *CertSource) generate() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	dns, ips := c.wantSANs()
	now := c.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Tesla Charger Monitoring (self-signed)"},
		DNSNames:              dns,
		IPAddresses:           ips,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // lets users import it as a trust anchor
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := writeFile(c.keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})); err != nil {
		return err
	}
	if err := writeFile(c.certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		return err
	}
	return c.load()
}

func writeFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Renew regenerates an auto certificate when it is close to expiry.
func (c *CertSource) Renew() error {
	if !c.auto {
		return c.load() // pick up a replaced user certificate
	}
	return c.ensure()
}

// GetCertificate implements tls.Config.GetCertificate.
func (c *CertSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cert, nil
}

// Leaf returns the parsed certificate.
func (c *CertSource) Leaf() *x509.Certificate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cert.Leaf
}

// Fingerprint is the SHA-256 of the certificate, colon-separated.
func (c *CertSource) Fingerprint() string {
	sum := sha256.Sum256(c.Leaf().Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// PEM returns the certificate (never the key) for download.
func (c *CertSource) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Leaf().Raw})
}

// SelfSigned reports whether the certificate was generated by the app.
func (c *CertSource) SelfSigned() bool { return c.auto }
