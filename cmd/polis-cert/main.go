package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	poliscert "github.com/polisai/polis-oss/internal/tls"
)

const (
	version = "1.0.0"
)

// CertificateInfo contains information about a certificate
// Duplicated here to avoid circular dependencies and because it's used by the CLI tool
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

func main() {
	var (
		generateCmd = flag.NewFlagSet("generate", flag.ExitOnError)
		inspectCmd  = flag.NewFlagSet("inspect", flag.ExitOnError)
		validateCmd = flag.NewFlagSet("validate", flag.ExitOnError)
		versionCmd  = flag.NewFlagSet("version", flag.ExitOnError)
	)

	// Generate command flags
	var (
		genCommonName  = generateCmd.String("cn", "localhost", "Common name for the certificate")
		genOrg         = generateCmd.String("org", "Test Organization", "Organization name")
		genCountry     = generateCmd.String("country", "US", "Country code")
		genDNSNames    = generateCmd.String("dns", "", "Comma-separated list of DNS names (SANs)")
		genIPAddresses = generateCmd.String("ips", "", "Comma-separated list of IP addresses")
		genValidFor    = generateCmd.Duration("valid-for", 365*24*time.Hour, "Certificate validity duration")
		genKeySize     = generateCmd.Int("key-size", 2048, "RSA key size in bits")
		genIsCA        = generateCmd.Bool("ca", false, "Generate a CA certificate")
		genCertFile    = generateCmd.String("cert", "cert.pem", "Output certificate file")
		genKeyFile     = generateCmd.String("key", "key.pem", "Output private key file")
		genOutputDir   = generateCmd.String("output-dir", ".", "Output directory for certificates")
		genTestSuite   = generateCmd.Bool("test-suite", false, "Generate a complete test certificate suite")
	)

	// Inspect command flags
	var (
		inspectCertFile = inspectCmd.String("cert", "", "Certificate file to inspect")
		inspectFormat   = inspectCmd.String("format", "text", "Output format: text, json")
	)

	// Validate command flags
	var (
		validateCertFile = validateCmd.String("cert", "", "Certificate file to validate")
		validateKeyFile  = validateCmd.String("key", "", "Private key file to validate (optional)")
		validateVerbose  = validateCmd.Bool("verbose", false, "Verbose validation output")
	)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "generate":
		generateCmd.Parse(os.Args[2:])
		handleGenerate(generateOptions{
			commonName:   *genCommonName,
			organization: *genOrg,
			country:      *genCountry,
			dnsNames:     parseDNSNames(*genDNSNames),
			ipAddresses:  parseIPAddresses(*genIPAddresses),
			validFor:     *genValidFor,
			keySize:      *genKeySize,
			isCA:         *genIsCA,
			certFile:     *genCertFile,
			keyFile:      *genKeyFile,
			outputDir:    *genOutputDir,
			testSuite:    *genTestSuite,
		})

	case "inspect":
		inspectCmd.Parse(os.Args[2:])
		if *inspectCertFile == "" {
			fmt.Fprintf(os.Stderr, "Error: -cert flag is required\n")
			inspectCmd.Usage()
			os.Exit(1)
		}
		handleInspect(*inspectCertFile, *inspectFormat)

	case "validate":
		validateCmd.Parse(os.Args[2:])
		if *validateCertFile == "" {
			fmt.Fprintf(os.Stderr, "Error: -cert flag is required\n")
			validateCmd.Usage()
			os.Exit(1)
		}
		handleValidate(*validateCertFile, *validateKeyFile, *validateVerbose)

	case "version":
		versionCmd.Parse(os.Args[2:])
		fmt.Printf("polis-cert version %s\n", version)

	default:
		printUsage()
		os.Exit(1)
	}
}

type generateOptions struct {
	commonName   string
	organization string
	country      string
	dnsNames     []string
	ipAddresses  []net.IP
	validFor     time.Duration
	keySize      int
	isCA         bool
	certFile     string
	keyFile      string
	outputDir    string
	testSuite    bool
}

func printUsage() {
	fmt.Printf(`polis-cert - Certificate generation and inspection utility for Polis TLS termination

Usage:
  polis-cert <command> [options]

Commands:
  generate    Generate self-signed certificates for testing
  inspect     Inspect certificate files and display information
  validate    Validate certificate files and key pairs
  version     Show version information

Examples:
  # Generate a basic self-signed certificate
  polis-cert generate -cn localhost -dns localhost,example.com

  # Generate a CA certificate
  polis-cert generate -ca -cn "Test CA" -cert ca.pem -key ca-key.pem

  # Generate a complete test certificate suite
  polis-cert generate -test-suite -output-dir ./certs

  # Inspect a certificate file
  polis-cert inspect -cert server.pem

  # Validate a certificate and key pair
  polis-cert validate -cert server.pem -key server-key.pem

Use "polis-cert <command> -h" for more information about a command.
`)
}

func handleGenerate(opts generateOptions) {
	if opts.testSuite {
		if err := generateTestSuite(opts.outputDir); err != nil {
			log.Fatalf("Failed to generate test suite: %v", err)
		}
		fmt.Printf("Test certificate suite generated in %s\n", opts.outputDir)
		return
	}

	// Ensure output directory exists
	if err := os.MkdirAll(opts.outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Prepare certificate generation options
	certOpts := poliscert.CertificateGenerationOptions{
		CommonName:   opts.commonName,
		Organization: []string{opts.organization},
		Country:      []string{opts.country},
		DNSNames:     opts.dnsNames,
		IPAddresses:  opts.ipAddresses,
		ValidFor:     opts.validFor,
		IsCA:         opts.isCA,
		KeySize:      opts.keySize,
		SerialNumber: big.NewInt(1),
	}

	// Generate certificate
	certPEM, keyPEM, err := poliscert.GenerateSelfSignedCertificate(certOpts)
	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	// Write certificate files
	certPath := filepath.Join(opts.outputDir, opts.certFile)
	keyPath := filepath.Join(opts.outputDir, opts.keyFile)

	if err := poliscert.WriteCertificateFiles(certPEM, keyPEM, certPath, keyPath); err != nil {
		log.Fatalf("Failed to write certificate files: %v", err)
	}

	fmt.Printf("Certificate generated successfully:\n")
	fmt.Printf("  Certificate: %s\n", certPath)
	fmt.Printf("  Private Key: %s\n", keyPath)
	fmt.Printf("  Common Name: %s\n", opts.commonName)
	fmt.Printf("  Valid For: %v\n", opts.validFor)
	if len(opts.dnsNames) > 0 {
		fmt.Printf("  DNS Names: %s\n", strings.Join(opts.dnsNames, ", "))
	}
	if len(opts.ipAddresses) > 0 {
		var ips []string
		for _, ip := range opts.ipAddresses {
			ips = append(ips, ip.String())
		}
		fmt.Printf("  IP Addresses: %s\n", strings.Join(ips, ", "))
	}
}

func generateTestSuite(outputDir string) error {
	fmt.Printf("Generating test certificate suite in %s...\n", outputDir)

	if err := poliscert.GenerateTestCertificates(outputDir); err != nil {
		return fmt.Errorf("failed to generate test certificates: %w", err)
	}

	// Create a README file explaining the generated certificates
	readmePath := filepath.Join(outputDir, "README.md")
	readmeContent := `# Test Certificate Suite

This directory contains a complete set of test certificates generated by polis-cert.

## Generated Files

- **ca.crt / ca.key**: Certificate Authority (CA) certificate and private key
- **server.crt / server.key**: Server certificate signed by the CA (for localhost, example.com, *.example.com)
- **client.crt / client.key**: Client certificate signed by the CA (for mutual TLS testing)
- **api.crt / api.key**: SNI certificate for api.example.com and api-staging.example.com

## Usage Examples

### Basic TLS Termination
` + "```yaml" + `
server:
  tls:
    enabled: true
    cert_file: "` + outputDir + `/server.crt"
    key_file: "` + outputDir + `/server.key"
` + "```" + `

### Mutual TLS (mTLS)
` + "```yaml" + `
server:
  tls:
    enabled: true
    cert_file: "` + outputDir + `/server.crt"
    key_file: "` + outputDir + `/server.key"
    client_auth:
      required: true
      ca_file: "` + outputDir + `/ca.crt"
` + "```" + `

### SNI Configuration
` + "```yaml" + `
server:
  tls:
    enabled: true
    cert_file: "` + outputDir + `/server.crt"
    key_file: "` + outputDir + `/server.key"
    sni:
      "api.example.com":
        cert_file: "` + outputDir + `/api.crt"
        key_file: "` + outputDir + `/api.key"
` + "```" + `

## Security Notice

⚠️ **These certificates are for testing purposes only!**

- Do not use these certificates in production environments
- The private keys are not password protected
- The CA certificate should not be trusted in production systems

## Certificate Validity

All certificates are valid for 1 year from generation (except CA which is valid for 10 years).
Use ` + "`polis-cert inspect -cert <file>`" + ` to check certificate details and expiration dates.
`

	if err := os.WriteFile(readmePath, []byte(readmeContent), 0644); err != nil {
		return fmt.Errorf("failed to write README: %w", err)
	}

	return nil
}

func handleInspect(certFile, format string) {
	inspector := NewCertificateInspector()
	info, err := inspector.InspectCertificateFile(certFile)
	if err != nil {
		log.Fatalf("Failed to inspect certificate: %v", err)
	}

	// Convert DetailedCertificateInfo to CertificateInfo for simple output if needed
	// Or use full info
	basicInfo := info.CertificateInfo

	switch format {
	case "text":
		printCertificateInfoText(basicInfo)
	case "json":
		printCertificateInfoJSON(basicInfo)
	default:
		log.Fatalf("Unknown format: %s (supported: text, json)", format)
	}
}

func printCertificateInfoText(info *CertificateInfo) {
	fmt.Printf("Certificate Information:\n")
	fmt.Printf("  File: %s\n", info.CertFile)
	fmt.Printf("  Subject: %s\n", info.Subject)
	fmt.Printf("  Issuer: %s\n", info.Issuer)
	fmt.Printf("  Valid From: %s\n", info.NotBefore.Format(time.RFC3339))
	fmt.Printf("  Valid Until: %s\n", info.NotAfter.Format(time.RFC3339))

	now := time.Now()
	if now.After(info.NotAfter) {
		fmt.Printf("  Status: ❌ EXPIRED (%v ago)\n", now.Sub(info.NotAfter).Truncate(time.Hour))
	} else if now.Before(info.NotBefore) {
		fmt.Printf("  Status: ⏳ NOT YET VALID (valid in %v)\n", info.NotBefore.Sub(now).Truncate(time.Hour))
	} else {
		remaining := info.NotAfter.Sub(now)
		if remaining < 30*24*time.Hour {
			fmt.Printf("  Status: ⚠️  EXPIRES SOON (in %v)\n", remaining.Truncate(time.Hour))
		} else {
			fmt.Printf("  Status: ✅ VALID (expires in %v)\n", remaining.Truncate(time.Hour))
		}
	}

	if len(info.DNSNames) > 0 {
		fmt.Printf("  DNS Names: %s\n", strings.Join(info.DNSNames, ", "))
	}

	if len(info.IPAddresses) > 0 {
		var ips []string
		for _, ip := range info.IPAddresses {
			ips = append(ips, ip.String())
		}
		fmt.Printf("  IP Addresses: %s\n", strings.Join(ips, ", "))
	}
}

func printCertificateInfoJSON(info *CertificateInfo) {
	// Simple JSON output without external dependencies
	fmt.Printf("{\n")
	fmt.Printf("  \"file\": \"%s\",\n", info.CertFile)
	fmt.Printf("  \"subject\": \"%s\",\n", info.Subject)
	fmt.Printf("  \"issuer\": \"%s\",\n", info.Issuer)
	fmt.Printf("  \"not_before\": \"%s\",\n", info.NotBefore.Format(time.RFC3339))
	fmt.Printf("  \"not_after\": \"%s\",\n", info.NotAfter.Format(time.RFC3339))

	now := time.Now()
	expired := now.After(info.NotAfter)
	notYetValid := now.Before(info.NotBefore)
	fmt.Printf("  \"expired\": %t,\n", expired)
	fmt.Printf("  \"not_yet_valid\": %t,\n", notYetValid)
	fmt.Printf("  \"valid\": %t,\n", !expired && !notYetValid)

	if len(info.DNSNames) > 0 {
		fmt.Printf("  \"dns_names\": [")
		for i, name := range info.DNSNames {
			if i > 0 {
				fmt.Printf(", ")
			}
			fmt.Printf("\"%s\"", name)
		}
		fmt.Printf("],\n")
	} else {
		fmt.Printf("  \"dns_names\": [],\n")
	}

	if len(info.IPAddresses) > 0 {
		fmt.Printf("  \"ip_addresses\": [")
		for i, ip := range info.IPAddresses {
			if i > 0 {
				fmt.Printf(", ")
			}
			fmt.Printf("\"%s\"", ip.String())
		}
		fmt.Printf("]\n")
	} else {
		fmt.Printf("  \"ip_addresses\": []\n")
	}
	fmt.Printf("}\n")
}

func handleValidate(certFile, keyFile string, verbose bool) {
	// Validate certificate file
	if err := poliscert.ValidateCertificateFile(certFile); err != nil {
		fmt.Printf("❌ Certificate validation failed: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("✅ Certificate file is valid: %s\n", certFile)
	}

	// If key file is provided, validate the key pair
	if keyFile != "" {
		if err := validateKeyPair(certFile, keyFile, verbose); err != nil {
			fmt.Printf("❌ Key pair validation failed: %v\n", err)
			os.Exit(1)
		}
	}

	// Get and display certificate info if verbose
	if verbose {
		inspector := NewCertificateInspector()
		info, err := inspector.InspectCertificateFile(certFile)
		if err != nil {
			fmt.Printf("⚠️  Could not read certificate details: %v\n", err)
		} else {
			fmt.Printf("\nCertificate Details:\n")
			printCertificateInfoText(info.CertificateInfo)
		}
	}

	if !verbose {
		fmt.Printf("✅ Certificate is valid\n")
	}
}

func validateKeyPair(certFile, keyFile string, verbose bool) error {
	// Load the certificate and key pair
	_, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate/key pair: %w", err)
	}

	if verbose {
		fmt.Printf("✅ Private key matches certificate: %s\n", keyFile)
	}

	return nil
}

func parseDNSNames(dnsStr string) []string {
	if dnsStr == "" {
		return nil
	}

	names := strings.Split(dnsStr, ",")
	for i, name := range names {
		names[i] = strings.TrimSpace(name)
	}
	return names
}

func parseIPAddresses(ipStr string) []net.IP {
	if ipStr == "" {
		return nil
	}

	ipStrs := strings.Split(ipStr, ",")
	var ips []net.IP

	for _, ipStr := range ipStrs {
		ipStr = strings.TrimSpace(ipStr)
		if ip := net.ParseIP(ipStr); ip != nil {
			ips = append(ips, ip)
		} else {
			log.Printf("Warning: invalid IP address: %s", ipStr)
		}
	}

	return ips
}
