package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// CertificateManager handles certificate loading and validation
type CertificateManager interface {
	// LoadCertificate loads and validates a certificate/key pair
	LoadCertificate(certFile, keyFile string) (*tls.Certificate, error)

	// ValidateCertificate validates a loaded certificate
	ValidateCertificate(cert *tls.Certificate) error

	// GetCertificateForSNI returns the appropriate certificate for SNI
	GetCertificateForSNI(serverName string) (*tls.Certificate, error)

	// ReloadCertificates reloads all managed certificates
	ReloadCertificates() error

	// WatchCertificateFiles starts watching certificate files for changes
	WatchCertificateFiles(callback func()) error

	// Close stops file watching and cleans up resources
	Close() error
}

// FileCertificateManager implements certificate loading from files
type FileCertificateManager struct {
	certificates     map[string]*tls.Certificate // serverName -> certificate
	certFiles        map[string]string           // serverName -> certFile path
	keyFiles         map[string]string           // serverName -> keyFile path
	watchers         []*fsnotify.Watcher
	reloadChan       chan struct{}
	mutex            sync.RWMutex
	logger           *slog.Logger
	metricsCollector *TLSMetricsCollector
	closed           bool
}

// NewFileCertificateManager creates a new file-based certificate manager
func NewFileCertificateManager(logger *slog.Logger) *FileCertificateManager {
	if logger == nil {
		logger = slog.Default()
	}

	// Get metrics collector (ignore error for now, it's optional)
	metricsCollector, _ := GetTLSMetricsCollector(logger)

	return &FileCertificateManager{
		certificates:     make(map[string]*tls.Certificate),
		certFiles:        make(map[string]string),
		keyFiles:         make(map[string]string),
		watchers:         make([]*fsnotify.Watcher, 0),
		reloadChan:       make(chan struct{}, 1),
		logger:           logger,
		metricsCollector: metricsCollector,
	}
}

// LoadCertificate loads and validates a certificate/key pair with comprehensive error handling
func (m *FileCertificateManager) LoadCertificate(certFile, keyFile string) (*tls.Certificate, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.closed {
		return nil, NewTLSError(ErrorTypeServerShutdown, "certificate manager is closed").
			WithSuggestion("Ensure the certificate manager is properly initialized").
			WithSuggestion("Check server startup sequence")
	}

	// Validate input parameters
	if strings.TrimSpace(certFile) == "" {
		return nil, NewConfigMissingError("cert_file").
			WithSuggestion("Provide a valid certificate file path")
	}
	if strings.TrimSpace(keyFile) == "" {
		return nil, NewConfigMissingError("key_file").
			WithSuggestion("Provide a valid private key file path")
	}

	// Clean and validate file paths
	certPath := filepath.Clean(certFile)
	keyPath := filepath.Clean(keyFile)

	// Validate paths are absolute for security
	if !filepath.IsAbs(certPath) {
		return nil, NewTLSError(ErrorTypeConfigValidation, "certificate file path must be absolute").
			WithContext("cert_file", certPath).
			WithSuggestion("Use an absolute path for the certificate file").
			WithSuggestion("Example: /etc/ssl/certs/server.crt")
	}
	if !filepath.IsAbs(keyPath) {
		return nil, NewTLSError(ErrorTypeConfigValidation, "private key file path must be absolute").
			WithContext("key_file", keyPath).
			WithSuggestion("Use an absolute path for the private key file").
			WithSuggestion("Example: /etc/ssl/private/server.key")
	}

	// Check file permissions and existence
	if err := m.validateFileAccess(certPath); err != nil {
		return nil, err
	}
	if err := m.validateFileAccess(keyPath); err != nil {
		return nil, err
	}

	// Load the certificate with detailed error handling
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		// Categorize the loading error
		errorMsg := err.Error()
		if strings.Contains(errorMsg, "no such file") {
			return nil, NewFileNotFoundError(certPath)
		}
		if strings.Contains(errorMsg, "permission denied") {
			return nil, NewFilePermissionError(certPath, "read")
		}
		if strings.Contains(errorMsg, "failed to find certificate PEM data") {
			return nil, NewTLSError(ErrorTypeCertificateParsing, "certificate file does not contain valid PEM data").
				WithContext("cert_file", certPath).
				WithSuggestion("Ensure the certificate file is in PEM format").
				WithSuggestion("Check that the file contains -----BEGIN CERTIFICATE----- markers")
		}
		if strings.Contains(errorMsg, "failed to find private key PEM data") {
			return nil, NewTLSError(ErrorTypeCertificateParsing, "private key file does not contain valid PEM data").
				WithContext("key_file", keyPath).
				WithSuggestion("Ensure the private key file is in PEM format").
				WithSuggestion("Check that the file contains -----BEGIN PRIVATE KEY----- or similar markers")
		}
		if strings.Contains(errorMsg, "private key does not match public key") {
			return nil, NewTLSError(ErrorTypeCertificateValidation, "private key does not match certificate").
				WithContext("cert_file", certPath).
				WithContext("key_file", keyPath).
				WithSuggestion("Ensure the private key corresponds to the certificate").
				WithSuggestion("Verify both files are from the same certificate generation process")
		}

		return nil, NewCertificateLoadError(certPath, keyPath, err)
	}

	// Validate the certificate
	if err := m.ValidateCertificate(&cert); err != nil {
		return nil, err
	}

	// Log successful loading with certificate details
	subject := m.getCertificateSubject(&cert)
	if len(cert.Certificate) > 0 {
		if leafCert, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			m.logger.Info("Certificate loaded successfully",
				"cert_file", certPath,
				"key_file", keyPath,
				"subject", subject,
				"dns_names", leafCert.DNSNames,
				"not_before", leafCert.NotBefore,
				"not_after", leafCert.NotAfter,
				"serial_number", leafCert.SerialNumber.String())
		}
	}

	return &cert, nil
}

// ValidateCertificate validates a loaded certificate with comprehensive checks
func (m *FileCertificateManager) ValidateCertificate(cert *tls.Certificate) error {
	ctx := context.Background()

	if cert == nil {
		err := NewTLSError(ErrorTypeCertificateValidation, "certificate is nil")
		if m.metricsCollector != nil {
			m.metricsCollector.RecordCertificateError(ctx, "", "validation_error", err.Error())
		}
		return err
	}

	if len(cert.Certificate) == 0 {
		err := NewTLSError(ErrorTypeCertificateValidation, "certificate chain is empty").
			WithSuggestion("Ensure the certificate file contains valid certificate data").
			WithSuggestion("Check that the certificate was loaded correctly")
		if m.metricsCollector != nil {
			m.metricsCollector.RecordCertificateError(ctx, "", "validation_error", err.Error())
		}
		return err
	}

	// Parse the leaf certificate
	leafCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		tlsErr := NewTLSErrorWithCause(ErrorTypeCertificateParsing, "failed to parse leaf certificate", err).
			WithSuggestion("Verify the certificate file is not corrupted").
			WithSuggestion("Ensure the certificate is in valid X.509 format")
		if m.metricsCollector != nil {
			m.metricsCollector.RecordCertificateError(ctx, "", "parse_error", err.Error())
		}
		return tlsErr
	}

	serverName := m.getServerNameFromCert(leafCert)

	// Check certificate validity period
	now := time.Now()
	if now.Before(leafCert.NotBefore) {
		err := NewCertificateNotYetValidError("", leafCert.NotBefore.String()).
			WithContext("not_before", leafCert.NotBefore).
			WithContext("current_time", now)
		if m.metricsCollector != nil {
			m.metricsCollector.RecordCertificateError(ctx, serverName, "not_yet_valid", err.Error())
		}
		return err
	}

	if now.After(leafCert.NotAfter) {
		err := NewCertificateExpiredError("", leafCert.NotAfter.String()).
			WithContext("not_after", leafCert.NotAfter).
			WithContext("current_time", now)
		if m.metricsCollector != nil {
			m.metricsCollector.RecordCertificateError(ctx, serverName, "expired", err.Error())
		}
		return err
	}

	// Check if certificate is expiring soon (within 30 days)
	daysUntilExpiry := int(time.Until(leafCert.NotAfter).Hours() / 24)
	if daysUntilExpiry <= 30 {
		m.logger.Warn("Certificate expires soon",
			"server_name", serverName,
			"days_until_expiry", daysUntilExpiry,
			"expiry_date", leafCert.NotAfter)
	}

	// Validate certificate key usage
	if err := m.validateKeyUsage(leafCert); err != nil {
		tlsErr := NewCertificateValidationError("invalid key usage", err).
			WithContext("server_name", serverName)
		if m.metricsCollector != nil {
			m.metricsCollector.RecordCertificateError(ctx, serverName, "key_usage", err.Error())
		}
		return tlsErr
	}

	// Validate certificate algorithms
	if err := m.validateCertificateAlgorithms(leafCert); err != nil {
		tlsErr := NewCertificateValidationError("weak cryptographic algorithms", err).
			WithContext("server_name", serverName)
		if m.metricsCollector != nil {
			m.metricsCollector.RecordCertificateError(ctx, serverName, "weak_algorithms", err.Error())
		}
		return tlsErr
	}

	// Record certificate expiry metrics
	if m.metricsCollector != nil {
		m.metricsCollector.RecordCertificateExpiry(ctx, serverName, leafCert.Subject.String(), leafCert.NotAfter)
		m.metricsCollector.RecordCertificateValidation(ctx, serverName, true, "expiry_check")
	}

	// Validate certificate chain if present
	if len(cert.Certificate) > 1 {
		if err := m.validateCertificateChain(cert.Certificate); err != nil {
			tlsErr := NewCertificateValidationError("certificate chain validation failed", err).
				WithContext("server_name", serverName).
				WithContext("chain_length", len(cert.Certificate))
			if m.metricsCollector != nil {
				m.metricsCollector.RecordCertificateError(ctx, serverName, "chain_validation", err.Error())
			}
			return tlsErr
		}

		if m.metricsCollector != nil {
			m.metricsCollector.RecordCertificateValidation(ctx, serverName, true, "chain_validation")
		}
	}

	return nil
}

// validateKeyUsage checks if the certificate has appropriate key usage for TLS
func (m *FileCertificateManager) validateKeyUsage(cert *x509.Certificate) error {
	// Check key usage
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 &&
		cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("certificate lacks required key usage (KeyEncipherment or DigitalSignature)")
	}

	// Check extended key usage for server certificates
	hasServerAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}

	if !hasServerAuth && len(cert.ExtKeyUsage) > 0 {
		m.logger.Warn("Certificate does not have ServerAuth extended key usage",
			"subject", cert.Subject.String(),
			"ext_key_usage", cert.ExtKeyUsage)
	}

	return nil
}

// validateCertificateAlgorithms checks for weak cryptographic algorithms
func (m *FileCertificateManager) validateCertificateAlgorithms(cert *x509.Certificate) error {
	// Check signature algorithm
	switch cert.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA:
		return fmt.Errorf("certificate uses weak signature algorithm: %s", cert.SignatureAlgorithm)
	}

	// Check public key algorithm and size
	switch pubKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if pubKey.N.BitLen() < 2048 {
			return fmt.Errorf("RSA key size too small: %d bits (minimum 2048)", pubKey.N.BitLen())
		}
	case *ecdsa.PublicKey:
		if pubKey.Curve.Params().BitSize < 256 {
			return fmt.Errorf("ECDSA key size too small: %d bits (minimum 256)", pubKey.Curve.Params().BitSize)
		}
	}

	return nil
}

// GetCertificateForSNI returns the appropriate certificate for SNI
func (m *FileCertificateManager) GetCertificateForSNI(serverName string) (*tls.Certificate, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if m.closed {
		return nil, fmt.Errorf("certificate manager is closed")
	}

	ctx := context.Background()
	found := false
	var cert *tls.Certificate

	// Try exact match first
	if c, exists := m.certificates[serverName]; exists {
		cert = c
		found = true
	} else {
		// Try wildcard match
		if serverName != "" {
			parts := strings.Split(serverName, ".")
			if len(parts) > 1 {
				wildcardName := "*." + strings.Join(parts[1:], ".")
				if c, exists := m.certificates[wildcardName]; exists {
					cert = c
					found = true
				}
			}
		}

		// Try default certificate (empty server name)
		if !found {
			if c, exists := m.certificates[""]; exists {
				cert = c
				found = true
			}
		}
	}

	// Record SNI metrics
	if m.metricsCollector != nil {
		m.metricsCollector.RecordSNIRequest(ctx, serverName, found)
	}

	if !found {
		return nil, fmt.Errorf("no certificate found for server name %q", serverName)
	}

	return cert, nil
}

// AddCertificate adds a certificate for a specific server name
func (m *FileCertificateManager) AddCertificate(serverName, certFile, keyFile string) error {
	cert, err := m.LoadCertificate(certFile, keyFile)
	if err != nil {
		return err
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.closed {
		return fmt.Errorf("certificate manager is closed")
	}

	m.certificates[serverName] = cert
	m.certFiles[serverName] = certFile
	m.keyFiles[serverName] = keyFile

	m.logger.Info("Certificate added for server name",
		"server_name", serverName,
		"cert_file", certFile,
		"key_file", keyFile)

	return nil
}

// ReloadCertificates reloads all managed certificates
func (m *FileCertificateManager) ReloadCertificates() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.closed {
		return fmt.Errorf("certificate manager is closed")
	}

	ctx := context.Background()
	m.logger.Info("Reloading certificates")

	errors := make([]error, 0)
	reloadedCount := 0

	for serverName := range m.certificates {
		certFile := m.certFiles[serverName]
		keyFile := m.keyFiles[serverName]

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			errorMsg := fmt.Sprintf("failed to reload certificate for %q: %v", serverName, err)
			errors = append(errors, fmt.Errorf("%s", errorMsg))

			// Record reload failure
			if m.metricsCollector != nil {
				m.metricsCollector.RecordCertificateReload(ctx, serverName, false, errorMsg)
			}
			continue
		}

		if err := m.ValidateCertificate(&cert); err != nil {
			errorMsg := fmt.Sprintf("validation failed for reloaded certificate %q: %v", serverName, err)
			errors = append(errors, fmt.Errorf("%s", errorMsg))

			// Record reload failure
			if m.metricsCollector != nil {
				m.metricsCollector.RecordCertificateReload(ctx, serverName, false, errorMsg)
			}
			continue
		}

		m.certificates[serverName] = &cert
		reloadedCount++

		// Record successful reload
		if m.metricsCollector != nil {
			m.metricsCollector.RecordCertificateReload(ctx, serverName, true, "")
		}
	}

	m.logger.Info("Certificate reload completed",
		"reloaded_count", reloadedCount,
		"error_count", len(errors))

	if len(errors) > 0 {
		return fmt.Errorf("certificate reload errors: %v", errors)
	}

	return nil
}

// WatchCertificateFiles starts watching certificate files for changes
func (m *FileCertificateManager) WatchCertificateFiles(callback func()) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.closed {
		return fmt.Errorf("certificate manager is closed")
	}

	// Create a new watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	// Add all certificate and key files to the watcher
	watchedFiles := make(map[string]bool)
	for serverName := range m.certificates {
		certFile := m.certFiles[serverName]
		keyFile := m.keyFiles[serverName]

		// Watch certificate file
		if !watchedFiles[certFile] {
			if err := watcher.Add(certFile); err != nil {
				watcher.Close()
				return fmt.Errorf("failed to watch certificate file %q: %w", certFile, err)
			}
			watchedFiles[certFile] = true
		}

		// Watch key file
		if !watchedFiles[keyFile] {
			if err := watcher.Add(keyFile); err != nil {
				watcher.Close()
				return fmt.Errorf("failed to watch key file %q: %w", keyFile, err)
			}
			watchedFiles[keyFile] = true
		}
	}

	m.watchers = append(m.watchers, watcher)

	// Start watching in a goroutine
	go m.watchFiles(watcher, callback)

	m.logger.Info("Started watching certificate files", "file_count", len(watchedFiles))
	return nil
}

// watchFiles handles file system events
func (m *FileCertificateManager) watchFiles(watcher *fsnotify.Watcher, callback func()) {
	defer watcher.Close()

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				m.logger.Info("Certificate file changed", "file", event.Name, "operation", event.Op.String())

				// Trigger reload with a small delay to handle multiple rapid writes
				go func() {
					time.Sleep(100 * time.Millisecond)
					select {
					case m.reloadChan <- struct{}{}:
						if err := m.ReloadCertificates(); err != nil {
							m.logger.Error("Failed to reload certificates after file change", "error", err)
						} else if callback != nil {
							callback()
						}
					default:
						// Channel is full, reload already pending
					}
				}()
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			m.logger.Error("Certificate file watcher error", "error", err)
		}
	}
}

// Close stops file watching and cleans up resources
func (m *FileCertificateManager) Close() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true

	// Close all watchers
	for _, watcher := range m.watchers {
		if err := watcher.Close(); err != nil {
			m.logger.Error("Failed to close file watcher", "error", err)
		}
	}

	// Close reload channel
	close(m.reloadChan)

	m.logger.Info("Certificate manager closed")
	return nil
}

// validateFileAccess checks if a file exists and is readable with detailed error reporting
func (m *FileCertificateManager) validateFileAccess(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return NewFileNotFoundError(filePath)
		}
		if os.IsPermission(err) {
			return NewFilePermissionError(filePath, "stat")
		}
		return NewTLSErrorWithCause(ErrorTypeFileAccess, "file access error", err).
			WithContext("file_path", filePath).
			WithSuggestion("Check that the file path is correct").
			WithSuggestion("Verify file system permissions")
	}

	if info.IsDir() {
		return NewTLSError(ErrorTypeFileAccess, "path is a directory, not a file").
			WithContext("file_path", filePath).
			WithSuggestion("Provide a path to a file, not a directory").
			WithSuggestion("Check the file path configuration")
	}

	// Check file size (warn if too large for a certificate)
	if info.Size() > 1024*1024 { // 1MB
		m.logger.Warn("Certificate file is unusually large",
			"file_path", filePath,
			"size_bytes", info.Size())
	}

	// Check if file is readable
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsPermission(err) {
			return NewFilePermissionError(filePath, "read")
		}
		return NewTLSErrorWithCause(ErrorTypeFileAccess, "cannot open file", err).
			WithContext("file_path", filePath).
			WithSuggestion("Check file permissions").
			WithSuggestion("Ensure the process has read access to the file")
	}
	file.Close()

	// Check file permissions for security (warn if too permissive)
	mode := info.Mode()
	if strings.Contains(filePath, "key") && mode.Perm()&0077 != 0 {
		m.logger.Warn("Private key file has overly permissive permissions",
			"file_path", filePath,
			"permissions", mode.Perm().String(),
			"recommendation", "chmod 600")
	}

	return nil
}

// getCertificateSubject extracts the subject from a certificate
func (m *FileCertificateManager) getCertificateSubject(cert *tls.Certificate) string {
	if cert == nil || len(cert.Certificate) == 0 {
		return "unknown"
	}

	leafCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "parse error"
	}

	return leafCert.Subject.String()
}

// validateCertificateChain validates a certificate chain
func (m *FileCertificateManager) validateCertificateChain(certChain [][]byte) error {
	if len(certChain) < 2 {
		return nil // Single certificate, no chain to validate
	}

	// Parse all certificates in the chain
	certs := make([]*x509.Certificate, len(certChain))
	for i, certData := range certChain {
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return fmt.Errorf("failed to parse certificate %d in chain: %w", i, err)
		}
		certs[i] = cert
	}

	// Validate chain: each certificate should be signed by the next one
	for i := 0; i < len(certs)-1; i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return fmt.Errorf("certificate %d is not signed by certificate %d: %w", i, i+1, err)
		}
	}

	return nil
}

// GetCertificateInfo returns information about a managed certificate
func (m *FileCertificateManager) GetCertificateInfo(serverName string) (*CertificateInfo, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	cert, exists := m.certificates[serverName]
	if !exists {
		return nil, fmt.Errorf("no certificate found for server name %q", serverName)
	}

	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("certificate chain is empty")
	}

	leafCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &CertificateInfo{
		ServerName:  serverName,
		Subject:     leafCert.Subject.String(),
		Issuer:      leafCert.Issuer.String(),
		NotBefore:   leafCert.NotBefore,
		NotAfter:    leafCert.NotAfter,
		DNSNames:    leafCert.DNSNames,
		IPAddresses: leafCert.IPAddresses,
		CertFile:    m.certFiles[serverName],
		KeyFile:     m.keyFiles[serverName],
	}, nil
}

// CertificateInfo contains information about a certificate
type CertificateInfo struct {
	ServerName  string
	Subject     string
	Issuer      string
	NotBefore   time.Time
	NotAfter    time.Time
	DNSNames    []string
	IPAddresses []net.IP
	CertFile    string
	KeyFile     string
}

// getServerNameFromCert extracts a server name from a certificate for metrics
func (m *FileCertificateManager) getServerNameFromCert(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}

	// Try DNS names first
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}

	// Try common name
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}

	// Try IP addresses
	if len(cert.IPAddresses) > 0 {
		return cert.IPAddresses[0].String()
	}

	return "unknown"
}
