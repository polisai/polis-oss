package tls

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileCertificateManager_LoadCertificate(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "cert_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Generate test certificates
	err = GenerateTestCertificates(tempDir)
	require.NoError(t, err)

	// Create certificate manager
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := NewFileCertificateManager(logger)
	defer manager.Close()

	// Test loading valid certificate
	certFile := filepath.Join(tempDir, "server.crt")
	keyFile := filepath.Join(tempDir, "server.key")

	cert, err := manager.LoadCertificate(certFile, keyFile)
	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.NotEmpty(t, cert.Certificate)

	// Test loading non-existent certificate
	_, err = manager.LoadCertificate("nonexistent.crt", "nonexistent.key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate file path must be absolute")
}

func TestFileCertificateManager_SNI(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "cert_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Generate test certificates
	err = GenerateTestCertificates(tempDir)
	require.NoError(t, err)

	// Create certificate manager
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := NewFileCertificateManager(logger)
	defer manager.Close()

	// Add default certificate
	err = manager.AddCertificate("", filepath.Join(tempDir, "server.crt"), filepath.Join(tempDir, "server.key"))
	require.NoError(t, err)

	// Add SNI certificate
	err = manager.AddCertificate("api.example.com", filepath.Join(tempDir, "api.crt"), filepath.Join(tempDir, "api.key"))
	require.NoError(t, err)

	// Test SNI certificate selection
	cert, err := manager.GetCertificateForSNI("api.example.com")
	assert.NoError(t, err)
	assert.NotNil(t, cert)

	// Test default certificate fallback
	cert, err = manager.GetCertificateForSNI("unknown.example.com")
	assert.NoError(t, err)
	assert.NotNil(t, cert)

	// Test wildcard matching
	err = manager.AddCertificate("*.example.com", filepath.Join(tempDir, "server.crt"), filepath.Join(tempDir, "server.key"))
	require.NoError(t, err)

	cert, err = manager.GetCertificateForSNI("test.example.com")
	assert.NoError(t, err)
	assert.NotNil(t, cert)
}

func TestFileCertificateManager_ValidateCertificate(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "cert_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Generate test certificates
	err = GenerateTestCertificates(tempDir)
	require.NoError(t, err)

	// Create certificate manager
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := NewFileCertificateManager(logger)
	defer manager.Close()

	// Load and validate certificate
	certFile := filepath.Join(tempDir, "server.crt")
	keyFile := filepath.Join(tempDir, "server.key")

	cert, err := manager.LoadCertificate(certFile, keyFile)
	require.NoError(t, err)

	err = manager.ValidateCertificate(cert)
	assert.NoError(t, err)

	// Test validation of nil certificate
	err = manager.ValidateCertificate(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate is nil")
}

func TestFileCertificateManager_ReloadCertificates(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "cert_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Generate test certificates
	err = GenerateTestCertificates(tempDir)
	require.NoError(t, err)

	// Create certificate manager
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := NewFileCertificateManager(logger)
	defer manager.Close()

	// Add certificate
	err = manager.AddCertificate("", filepath.Join(tempDir, "server.crt"), filepath.Join(tempDir, "server.key"))
	require.NoError(t, err)

	// Test reload
	err = manager.ReloadCertificates()
	assert.NoError(t, err)

	// Verify certificate is still accessible
	cert, err := manager.GetCertificateForSNI("")
	assert.NoError(t, err)
	assert.NotNil(t, cert)
}

func TestFileCertificateManager_GetCertificateInfo(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "cert_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Generate test certificates
	err = GenerateTestCertificates(tempDir)
	require.NoError(t, err)

	// Create certificate manager
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := NewFileCertificateManager(logger)
	defer manager.Close()

	// Add certificate
	certFile := filepath.Join(tempDir, "server.crt")
	keyFile := filepath.Join(tempDir, "server.key")
	err = manager.AddCertificate("localhost", certFile, keyFile)
	require.NoError(t, err)

	// Get certificate info
	info, err := manager.GetCertificateInfo("localhost")
	assert.NoError(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, "localhost", info.ServerName)
	assert.Contains(t, info.Subject, "localhost")
	assert.NotEmpty(t, info.DNSNames)
	assert.Equal(t, certFile, info.CertFile)
	assert.Equal(t, keyFile, info.KeyFile)
	assert.True(t, time.Now().Before(info.NotAfter))
}

func TestGenerateTestCertificates(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "cert_gen_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Generate certificates
	err = GenerateTestCertificates(tempDir)
	assert.NoError(t, err)

	// Verify files were created
	expectedFiles := []string{
		"ca.crt", "ca.key",
		"server.crt", "server.key",
		"client.crt", "client.key",
		"api.crt", "api.key",
	}

	for _, filename := range expectedFiles {
		filePath := filepath.Join(tempDir, filename)
		_, err := os.Stat(filePath)
		assert.NoError(t, err, "File %s should exist", filename)
	}

	// Validate certificate files
	certFiles := []string{"ca.crt", "server.crt", "client.crt", "api.crt"}
	for _, certFile := range certFiles {
		filePath := filepath.Join(tempDir, certFile)
		err := ValidateCertificateFile(filePath)
		assert.NoError(t, err, "Certificate %s should be valid", certFile)
	}
}

func TestGetCertificateFileInfo(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "cert_info_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Generate certificates
	err = GenerateTestCertificates(tempDir)
	require.NoError(t, err)

	// Get certificate info
	certFile := filepath.Join(tempDir, "server.crt")
	info, err := GetCertificateFileInfo(certFile)
	assert.NoError(t, err)
	assert.NotNil(t, info)
	assert.Contains(t, info.Subject, "localhost")
	assert.NotEmpty(t, info.DNSNames)
	assert.Contains(t, info.DNSNames, "localhost")
	assert.True(t, time.Now().Before(info.NotAfter))
}
