package tls

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/polisai/polis-oss/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultTLSTerminator_BuildServerConfig(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "terminator_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Generate test certificates
	err = GenerateTestCertificates(tempDir)
	require.NoError(t, err)

	// Create TLS terminator
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	terminator := NewTLSTerminator(logger)
	defer terminator.Close()

	// Test basic TLS configuration
	tlsConfig := config.TLSConfig{
		Enabled:    true,
		CertFile:   filepath.Join(tempDir, "server.crt"),
		KeyFile:    filepath.Join(tempDir, "server.key"),
		MinVersion: "1.2",
	}

	serverConfig, err := terminator.BuildServerConfig(tlsConfig)
	assert.NoError(t, err)
	assert.NotNil(t, serverConfig)
	assert.NotEmpty(t, serverConfig.Certificates)
	assert.NotNil(t, serverConfig.GetCertificate)

	// Test with SNI configuration
	tlsConfigWithSNI := config.TLSConfig{
		Enabled:    true,
		CertFile:   filepath.Join(tempDir, "server.crt"),
		KeyFile:    filepath.Join(tempDir, "server.key"),
		MinVersion: "1.2",
		SNI: map[string]config.TLSCertConfig{
			"api.example.com": {
				CertFile: filepath.Join(tempDir, "api.crt"),
				KeyFile:  filepath.Join(tempDir, "api.key"),
			},
		},
	}

	serverConfigSNI, err := terminator.BuildServerConfig(tlsConfigWithSNI)
	assert.NoError(t, err)
	assert.NotNil(t, serverConfigSNI)
	assert.NotNil(t, serverConfigSNI.GetCertificate)

	// Test with client authentication
	tlsConfigWithClientAuth := config.TLSConfig{
		Enabled:    true,
		CertFile:   filepath.Join(tempDir, "server.crt"),
		KeyFile:    filepath.Join(tempDir, "server.key"),
		MinVersion: "1.2",
		ClientAuth: config.TLSClientAuthConfig{
			Required: true,
			CAFile:   filepath.Join(tempDir, "ca.crt"),
		},
	}

	serverConfigClientAuth, err := terminator.BuildServerConfig(tlsConfigWithClientAuth)
	assert.NoError(t, err)
	assert.NotNil(t, serverConfigClientAuth)
	assert.NotNil(t, serverConfigClientAuth.ClientCAs)

	// Test disabled TLS
	disabledConfig := config.TLSConfig{Enabled: false}
	_, err = terminator.BuildServerConfig(disabledConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "TLS is not enabled")
}

func TestDefaultTLSTerminator_BuildClientConfig(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "terminator_client_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Generate test certificates
	err = GenerateTestCertificates(tempDir)
	require.NoError(t, err)

	// Create TLS terminator
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	terminator := NewTLSTerminator(logger)
	defer terminator.Close()

	// Test basic upstream TLS configuration
	upstreamConfig := config.UpstreamTLSConfig{
		Enabled:    true,
		ServerName: "api.example.com",
		MinVersion: "1.2",
	}

	clientConfig, err := terminator.BuildClientConfig(upstreamConfig)
	assert.NoError(t, err)
	assert.NotNil(t, clientConfig)
	assert.Equal(t, "api.example.com", clientConfig.ServerName)

	// Test with client certificate
	upstreamConfigWithCert := config.UpstreamTLSConfig{
		Enabled:    true,
		ServerName: "api.example.com",
		CertFile:   filepath.Join(tempDir, "client.crt"),
		KeyFile:    filepath.Join(tempDir, "client.key"),
		MinVersion: "1.2",
	}

	clientConfigWithCert, err := terminator.BuildClientConfig(upstreamConfigWithCert)
	assert.NoError(t, err)
	assert.NotNil(t, clientConfigWithCert)
	assert.NotEmpty(t, clientConfigWithCert.Certificates)

	// Test with custom CA
	upstreamConfigWithCA := config.UpstreamTLSConfig{
		Enabled:    true,
		ServerName: "api.example.com",
		CAFile:     filepath.Join(tempDir, "ca.crt"),
		MinVersion: "1.2",
	}

	clientConfigWithCA, err := terminator.BuildClientConfig(upstreamConfigWithCA)
	assert.NoError(t, err)
	assert.NotNil(t, clientConfigWithCA)
	assert.NotNil(t, clientConfigWithCA.RootCAs)

	// Test disabled upstream TLS
	disabledUpstreamConfig := config.UpstreamTLSConfig{Enabled: false}
	clientConfigDisabled, err := terminator.BuildClientConfig(disabledUpstreamConfig)
	assert.NoError(t, err)
	assert.Nil(t, clientConfigDisabled)
}

func TestDefaultTLSTerminator_ParseTLSVersion(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	terminator := NewTLSTerminator(logger)
	defer terminator.Close()

	tests := []struct {
		input    string
		expected uint16
		name     string
	}{
		{"1.0", 0x0301, "TLS 1.0"},
		{"1.1", 0x0302, "TLS 1.1"},
		{"1.2", 0x0303, "TLS 1.2"},
		{"1.3", 0x0304, "TLS 1.3"},
		{"", 0x0303, "Default (empty)"},
		{"invalid", 0x0303, "Invalid version"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := terminator.parseTLSVersion(test.input, 0x0303)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestDefaultTLSTerminator_ParseCipherSuites(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	terminator := NewTLSTerminator(logger)
	defer terminator.Close()

	// Test empty cipher suites (should return nil for defaults)
	result := terminator.parseCipherSuites([]string{})
	assert.Nil(t, result)

	// Test valid cipher suites
	validSuites := []string{
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	}
	result = terminator.parseCipherSuites(validSuites)
	assert.NotNil(t, result)
	assert.Len(t, result, 2)

	// Test with invalid cipher suite (should be ignored)
	mixedSuites := []string{
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"INVALID_CIPHER_SUITE",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	}
	result = terminator.parseCipherSuites(mixedSuites)
	assert.NotNil(t, result)
	assert.Len(t, result, 2) // Invalid suite should be ignored
}
