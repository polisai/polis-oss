package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
)

// Config contains shared TLS settings for both client and server contexts.
type Config struct {
	CertFile           string
	KeyFile            string
	ClientCAFile       string
	ServerName         string
	InsecureSkipVerify bool
}

// BuildServer constructs a TLS configuration for downstream listeners.
func BuildServer(cfg Config) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}

	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	}

	if cfg.ClientCAFile != "" {
		caPool, err := loadCertPool(cfg.ClientCAFile)
		if err != nil {
			return nil, err
		}
		serverConfig.ClientCAs = caPool
		serverConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return serverConfig, nil
}

// BuildClient constructs a TLS configuration for upstream clients.
func BuildClient(cfg Config) (*tls.Config, error) {
	if cfg.InsecureSkipVerify {
		return nil, fmt.Errorf("insecure skip verify is not permitted")
	}

	clientConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: cfg.ServerName,
	}

	if cfg.CertFile != "" || cfg.KeyFile != "" {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, fmt.Errorf("both CertFile and KeyFile are required when supplying client certificates")
		}
		certificate, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		clientConfig.Certificates = []tls.Certificate{certificate}
	}

	if cfg.ClientCAFile != "" {
		caPool, err := loadCertPool(cfg.ClientCAFile)
		if err != nil {
			return nil, err
		}
		clientConfig.RootCAs = caPool
	}

	return clientConfig, nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	cleanPath := filepath.Clean(path)
	if !filepath.IsAbs(cleanPath) {
		return nil, fmt.Errorf("ca bundle path must be absolute: %q", path)
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no certificates found in %s", cleanPath)
	}
	return pool, nil
}
