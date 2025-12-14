package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// CertificateGenerationOptions contains options for generating certificates
type CertificateGenerationOptions struct {
	CommonName   string
	Organization []string
	Country      []string
	Province     []string
	Locality     []string
	DNSNames     []string
	IPAddresses  []net.IP
	ValidFor     time.Duration
	IsCA         bool
	IsClientCert bool
	KeySize      int
	SerialNumber *big.Int
	ParentCert   *x509.Certificate
	ParentKey    interface{}
}

// GenerateSelfSignedCertificate generates a self-signed certificate for testing
func GenerateSelfSignedCertificate(opts CertificateGenerationOptions) (certPEM, keyPEM []byte, err error) {
	// Set defaults
	if opts.ValidFor == 0 {
		opts.ValidFor = 365 * 24 * time.Hour // 1 year
	}
	if opts.KeySize == 0 {
		opts.KeySize = 2048
	}
	if opts.SerialNumber == nil {
		opts.SerialNumber = big.NewInt(1)
	}
	if opts.CommonName == "" {
		opts.CommonName = "localhost"
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, opts.KeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: opts.SerialNumber,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: opts.Organization,
			Country:      opts.Country,
			Province:     opts.Province,
			Locality:     opts.Locality,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(opts.ValidFor),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              opts.DNSNames,
		IPAddresses:           opts.IPAddresses,
	}

	// Add default DNS names and IP addresses if none provided
	if len(template.DNSNames) == 0 && len(template.IPAddresses) == 0 {
		template.DNSNames = []string{"localhost"}
		template.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	}

	// Configure for CA if requested
	if opts.IsCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	} else if opts.IsClientCert {
		// Configure for client certificate
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	// Determine parent certificate and key for signing
	parentCert := &template
	var parentKey interface{} = privateKey
	if opts.ParentCert != nil && opts.ParentKey != nil {
		parentCert = opts.ParentCert
		parentKey = opts.ParentKey
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, parentCert, &privateKey.PublicKey, parentKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})

	return certPEM, keyPEM, nil
}

// WriteCertificateFiles writes certificate and key to files
func WriteCertificateFiles(certPEM, keyPEM []byte, certFile, keyFile string) error {
	// Write certificate file
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}

	// Write key file with restricted permissions
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// GenerateTestCertificates generates a set of test certificates for development
func GenerateTestCertificates(baseDir string) error {
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	// Generate CA certificate
	caCertPEM, caKeyPEM, err := GenerateSelfSignedCertificate(CertificateGenerationOptions{
		CommonName:   "Test CA",
		Organization: []string{"Test Organization"},
		Country:      []string{"US"},
		IsCA:         true,
		ValidFor:     10 * 365 * 24 * time.Hour, // 10 years
		SerialNumber: big.NewInt(1),
	})
	if err != nil {
		return fmt.Errorf("failed to generate CA certificate: %w", err)
	}

	caFile := baseDir + "/ca.crt"
	caKeyFile := baseDir + "/ca.key"
	if err := WriteCertificateFiles(caCertPEM, caKeyPEM, caFile, caKeyFile); err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	// Parse CA certificate for signing
	caCertBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA key: %w", err)
	}

	// Generate server certificate signed by CA
	serverCertPEM, serverKeyPEM, err := GenerateSelfSignedCertificate(CertificateGenerationOptions{
		CommonName:   "localhost",
		Organization: []string{"Test Server"},
		Country:      []string{"US"},
		DNSNames:     []string{"localhost", "example.com", "*.example.com"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		ValidFor:     365 * 24 * time.Hour, // 1 year
		SerialNumber: big.NewInt(2),
		ParentCert:   caCert,
		ParentKey:    caKey,
	})
	if err != nil {
		return fmt.Errorf("failed to generate server certificate: %w", err)
	}

	serverCertFile := baseDir + "/server.crt"
	serverKeyFile := baseDir + "/server.key"
	if err := WriteCertificateFiles(serverCertPEM, serverKeyPEM, serverCertFile, serverKeyFile); err != nil {
		return fmt.Errorf("failed to write server certificate: %w", err)
	}

	// Generate client certificate signed by CA
	clientCertPEM, clientKeyPEM, err := GenerateSelfSignedCertificate(CertificateGenerationOptions{
		CommonName:   "Test Client",
		Organization: []string{"Test Client Org"},
		Country:      []string{"US"},
		ValidFor:     365 * 24 * time.Hour, // 1 year
		SerialNumber: big.NewInt(3),
		ParentCert:   caCert,
		ParentKey:    caKey,
		IsClientCert: true, // Add flag for client certificate
	})
	if err != nil {
		return fmt.Errorf("failed to generate client certificate: %w", err)
	}

	clientCertFile := baseDir + "/client.crt"
	clientKeyFile := baseDir + "/client.key"
	if err := WriteCertificateFiles(clientCertPEM, clientKeyPEM, clientCertFile, clientKeyFile); err != nil {
		return fmt.Errorf("failed to write client certificate: %w", err)
	}

	// Generate SNI certificate for api.example.com
	sniCertPEM, sniKeyPEM, err := GenerateSelfSignedCertificate(CertificateGenerationOptions{
		CommonName:   "api.example.com",
		Organization: []string{"Test API"},
		Country:      []string{"US"},
		DNSNames:     []string{"api.example.com", "api-staging.example.com"},
		ValidFor:     365 * 24 * time.Hour, // 1 year
		SerialNumber: big.NewInt(4),
		ParentCert:   caCert,
		ParentKey:    caKey,
	})
	if err != nil {
		return fmt.Errorf("failed to generate SNI certificate: %w", err)
	}

	sniCertFile := baseDir + "/api.crt"
	sniKeyFile := baseDir + "/api.key"
	if err := WriteCertificateFiles(sniCertPEM, sniKeyPEM, sniCertFile, sniKeyFile); err != nil {
		return fmt.Errorf("failed to write SNI certificate: %w", err)
	}

	return nil
}

// ValidateCertificateFile validates a certificate file without loading it into memory
func ValidateCertificateFile(certFile string) error {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return fmt.Errorf("PEM block is not a certificate (type: %s)", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Basic validation
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid (valid from %v)", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired (expired on %v)", cert.NotAfter)
	}

	return nil
}

// GetCertificateInfo extracts information from a certificate file
func GetCertificateFileInfo(certFile string) (*CertificateInfo, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &CertificateInfo{
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		DNSNames:    cert.DNSNames,
		IPAddresses: cert.IPAddresses,
		CertFile:    certFile,
	}, nil
}
