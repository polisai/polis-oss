package tls

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
)

// CertificateInspector provides detailed certificate inspection capabilities
type CertificateInspector struct{}

// NewCertificateInspector creates a new certificate inspector
func NewCertificateInspector() *CertificateInspector {
	return &CertificateInspector{}
}

// DetailedCertificateInfo contains comprehensive certificate information
type DetailedCertificateInfo struct {
	*CertificateInfo
	Version            int
	SerialNumber       string
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	KeySize            int
	IsCA               bool
	KeyUsage           []string
	ExtKeyUsage        []string
	Extensions         []CertificateExtension
	Chain              []CertificateChainInfo
	ValidationStatus   ValidationStatus
}

// CertificateExtension represents a certificate extension
type CertificateExtension struct {
	OID      string
	Critical bool
	Value    string
}

// CertificateChainInfo contains information about certificates in the chain
type CertificateChainInfo struct {
	Subject            string
	Issuer             string
	SerialNumber       string
	NotBefore          time.Time
	NotAfter           time.Time
	SignatureAlgorithm string
}

// ValidationStatus contains certificate validation results
type ValidationStatus struct {
	Valid            bool
	Expired          bool
	NotYetValid      bool
	SelfSigned       bool
	ChainValid       bool
	Warnings         []string
	Errors           []string
	ExpiresInDays    int
	TrustChainLength int
}

// InspectCertificateFile performs detailed inspection of a certificate file
func (ci *CertificateInspector) InspectCertificateFile(certFile string) (*DetailedCertificateInfo, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	return ci.InspectCertificateData(data, certFile)
}

// InspectCertificateData performs detailed inspection of certificate data
func (ci *CertificateInspector) InspectCertificateData(data []byte, filename string) (*DetailedCertificateInfo, error) {
	// Parse all certificates in the file (could be a chain)
	var certs []*x509.Certificate
	rest := data

	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}

		rest = remaining
		if len(rest) == 0 {
			break
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificates found in file")
	}

	// Use the first certificate as the primary certificate
	primaryCert := certs[0]

	// Build basic certificate info
	basicInfo := &CertificateInfo{
		CertFile:    filename,
		Subject:     primaryCert.Subject.String(),
		Issuer:      primaryCert.Issuer.String(),
		NotBefore:   primaryCert.NotBefore,
		NotAfter:    primaryCert.NotAfter,
		DNSNames:    primaryCert.DNSNames,
		IPAddresses: primaryCert.IPAddresses,
	}

	// Build detailed info
	detailedInfo := &DetailedCertificateInfo{
		CertificateInfo:    basicInfo,
		Version:            primaryCert.Version,
		SerialNumber:       primaryCert.SerialNumber.String(),
		SignatureAlgorithm: primaryCert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: primaryCert.PublicKeyAlgorithm.String(),
		IsCA:               primaryCert.IsCA,
		KeyUsage:           ci.parseKeyUsage(primaryCert.KeyUsage),
		ExtKeyUsage:        ci.parseExtKeyUsage(primaryCert.ExtKeyUsage),
		Extensions:         ci.parseExtensions(primaryCert.Extensions),
		ValidationStatus:   ci.validateCertificate(primaryCert),
	}

	// Determine key size
	detailedInfo.KeySize = ci.getKeySize(primaryCert.PublicKey)

	// Build chain information
	if len(certs) > 1 {
		detailedInfo.Chain = ci.buildChainInfo(certs[1:])
		detailedInfo.ValidationStatus.TrustChainLength = len(certs)
		detailedInfo.ValidationStatus.ChainValid = ci.validateChain(certs)
	} else {
		detailedInfo.ValidationStatus.TrustChainLength = 1
		detailedInfo.ValidationStatus.SelfSigned = ci.isSelfSigned(primaryCert)
	}

	return detailedInfo, nil
}

// parseKeyUsage converts key usage flags to string descriptions
func (ci *CertificateInspector) parseKeyUsage(keyUsage x509.KeyUsage) []string {
	var usages []string

	if keyUsage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if keyUsage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if keyUsage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if keyUsage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if keyUsage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if keyUsage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if keyUsage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if keyUsage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if keyUsage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}

	return usages
}

// parseExtKeyUsage converts extended key usage to string descriptions
func (ci *CertificateInspector) parseExtKeyUsage(extKeyUsage []x509.ExtKeyUsage) []string {
	var usages []string

	for _, usage := range extKeyUsage {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "Email Protection")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSP Signing")
		default:
			usages = append(usages, fmt.Sprintf("Unknown (%v)", usage))
		}
	}

	return usages
}

// parseExtensions extracts certificate extensions
func (ci *CertificateInspector) parseExtensions(extensions []pkix.Extension) []CertificateExtension {
	var exts []CertificateExtension

	for _, ext := range extensions {
		certExt := CertificateExtension{
			OID:      ext.Id.String(),
			Critical: ext.Critical,
			Value:    fmt.Sprintf("%x", ext.Value),
		}

		// Add human-readable names for common extensions
		switch ext.Id.String() {
		case "2.5.29.15":
			certExt.OID = "2.5.29.15 (Key Usage)"
		case "2.5.29.37":
			certExt.OID = "2.5.29.37 (Extended Key Usage)"
		case "2.5.29.17":
			certExt.OID = "2.5.29.17 (Subject Alternative Name)"
		case "2.5.29.19":
			certExt.OID = "2.5.29.19 (Basic Constraints)"
		case "2.5.29.14":
			certExt.OID = "2.5.29.14 (Subject Key Identifier)"
		case "2.5.29.35":
			certExt.OID = "2.5.29.35 (Authority Key Identifier)"
		}

		exts = append(exts, certExt)
	}

	return exts
}

// validateCertificate performs comprehensive certificate validation
func (ci *CertificateInspector) validateCertificate(cert *x509.Certificate) ValidationStatus {
	status := ValidationStatus{
		Valid:    true,
		Warnings: make([]string, 0),
		Errors:   make([]string, 0),
	}

	now := time.Now()

	// Check expiration
	if now.After(cert.NotAfter) {
		status.Expired = true
		status.Valid = false
		status.Errors = append(status.Errors, fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format(time.RFC3339)))
	} else {
		daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
		status.ExpiresInDays = daysUntilExpiry

		if daysUntilExpiry <= 30 {
			status.Warnings = append(status.Warnings, fmt.Sprintf("Certificate expires in %d days", daysUntilExpiry))
		}
	}

	// Check not yet valid
	if now.Before(cert.NotBefore) {
		status.NotYetValid = true
		status.Valid = false
		status.Errors = append(status.Errors, fmt.Sprintf("Certificate is not yet valid (valid from %s)", cert.NotBefore.Format(time.RFC3339)))
	}

	// Check for weak key sizes
	keySize := ci.getKeySize(cert.PublicKey)
	if keySize > 0 && keySize < 2048 {
		status.Warnings = append(status.Warnings, fmt.Sprintf("Weak key size: %d bits (recommended: 2048+ bits)", keySize))
	}

	// Check signature algorithm
	if strings.Contains(strings.ToLower(cert.SignatureAlgorithm.String()), "sha1") {
		status.Warnings = append(status.Warnings, "Uses SHA-1 signature algorithm (deprecated)")
	}

	// Check for missing SAN if CN is an IP or hostname
	if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 {
		cn := cert.Subject.CommonName
		if cn != "" && (strings.Contains(cn, ".") || strings.Contains(cn, ":")) {
			status.Warnings = append(status.Warnings, "No Subject Alternative Names (SAN) present")
		}
	}

	return status
}

// getKeySize determines the key size from the public key
func (ci *CertificateInspector) getKeySize(publicKey interface{}) int {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	default:
		return 0
	}
}

// buildChainInfo creates chain information for intermediate/root certificates
func (ci *CertificateInspector) buildChainInfo(certs []*x509.Certificate) []CertificateChainInfo {
	var chainInfo []CertificateChainInfo

	for _, cert := range certs {
		info := CertificateChainInfo{
			Subject:            cert.Subject.String(),
			Issuer:             cert.Issuer.String(),
			SerialNumber:       cert.SerialNumber.String(),
			NotBefore:          cert.NotBefore,
			NotAfter:           cert.NotAfter,
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		}
		chainInfo = append(chainInfo, info)
	}

	return chainInfo
}

// validateChain validates the certificate chain
func (ci *CertificateInspector) validateChain(certs []*x509.Certificate) bool {
	if len(certs) < 2 {
		return true // Single certificate, no chain to validate
	}

	// Validate each certificate is signed by the next one
	for i := 0; i < len(certs)-1; i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return false
		}
	}

	return true
}

// isSelfSigned checks if a certificate is self-signed
func (ci *CertificateInspector) isSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

// CompareCertificates compares two certificates and returns differences
func (ci *CertificateInspector) CompareCertificates(cert1Path, cert2Path string) (*CertificateComparison, error) {
	info1, err := ci.InspectCertificateFile(cert1Path)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect first certificate: %w", err)
	}

	info2, err := ci.InspectCertificateFile(cert2Path)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect second certificate: %w", err)
	}

	comparison := &CertificateComparison{
		Certificate1: info1,
		Certificate2: info2,
		Differences:  make([]string, 0),
		Identical:    true,
	}

	// Compare key fields
	if info1.Subject != info2.Subject {
		comparison.Differences = append(comparison.Differences, fmt.Sprintf("Subject differs: %s vs %s", info1.Subject, info2.Subject))
		comparison.Identical = false
	}

	if info1.Issuer != info2.Issuer {
		comparison.Differences = append(comparison.Differences, fmt.Sprintf("Issuer differs: %s vs %s", info1.Issuer, info2.Issuer))
		comparison.Identical = false
	}

	if !info1.NotBefore.Equal(info2.NotBefore) {
		comparison.Differences = append(comparison.Differences, fmt.Sprintf("NotBefore differs: %s vs %s", info1.NotBefore, info2.NotBefore))
		comparison.Identical = false
	}

	if !info1.NotAfter.Equal(info2.NotAfter) {
		comparison.Differences = append(comparison.Differences, fmt.Sprintf("NotAfter differs: %s vs %s", info1.NotAfter, info2.NotAfter))
		comparison.Identical = false
	}

	if info1.SerialNumber != info2.SerialNumber {
		comparison.Differences = append(comparison.Differences, fmt.Sprintf("Serial number differs: %s vs %s", info1.SerialNumber, info2.SerialNumber))
		comparison.Identical = false
	}

	// Compare DNS names
	if !ci.slicesEqual(info1.DNSNames, info2.DNSNames) {
		comparison.Differences = append(comparison.Differences, fmt.Sprintf("DNS names differ: %v vs %v", info1.DNSNames, info2.DNSNames))
		comparison.Identical = false
	}

	return comparison, nil
}

// CertificateComparison contains the results of comparing two certificates
type CertificateComparison struct {
	Certificate1 *DetailedCertificateInfo
	Certificate2 *DetailedCertificateInfo
	Differences  []string
	Identical    bool
}

// slicesEqual compares two string slices for equality
func (ci *CertificateInspector) slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i, v := range a {
		if v != b[i] {
			return false
		}
	}

	return true
}
