package config

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// TrustBundle holds certificate bundle configuration with lazy loading and verification.
type TrustBundle struct {
	Name   string `json:"name" yaml:"name"`
	Path   string `json:"path" yaml:"path"`
	Inline string `json:"inline" yaml:"inline"`
	SHA256 string `json:"sha256" yaml:"sha256"`
	cached []byte
	poolMu sync.Mutex
	pool   *x509.CertPool
}

// Materialise returns the PEM-encoded contents for the bundle.
func (b *TrustBundle) Materialise() ([]byte, error) {
	if len(b.cached) > 0 {
		return append([]byte(nil), b.cached...), nil
	}

	var data []byte
	var err error
	switch {
	case strings.TrimSpace(b.Inline) != "":
		data = []byte(b.Inline)
	case strings.TrimSpace(b.Path) != "":
		path := filepath.Clean(b.Path)
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("trust bundle %s: read: %w", b.Name, err)
		}
	default:
		return nil, fmt.Errorf("trust bundle %s: no path or inline data provided", b.Name)
	}

	if err := b.verifyChecksum(data); err != nil {
		return nil, err
	}

	b.cached = append([]byte(nil), data...)
	return append([]byte(nil), data...), nil
}

func (b *TrustBundle) verifyChecksum(data []byte) error {
	if b.SHA256 == "" {
		return nil
	}

	expected := strings.TrimSpace(strings.ToLower(b.SHA256))
	expected = strings.TrimPrefix(expected, "sha256:")
	digest := sha256.Sum256(data)
	actual := hex.EncodeToString(digest[:])
	if actual != expected {
		return fmt.Errorf("trust bundle %s: checksum mismatch", b.Name)
	}
	return nil
}

// CertPool parses the bundle into an x509.CertPool (cached per instance).
func (b *TrustBundle) CertPool() (*x509.CertPool, error) {
	b.poolMu.Lock()
	defer b.poolMu.Unlock()
	if b.pool != nil {
		return b.pool, nil
	}

	data, err := b.Materialise()
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("trust bundle %s: no certificates found", b.Name)
	}
	b.pool = pool
	return pool, nil
}
