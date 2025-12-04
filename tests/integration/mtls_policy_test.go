package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	tlspkg "github.com/polisai/polis-oss/internal/tls"
	"github.com/polisai/polis-oss/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateMTLSCert generates a certificate suitable for both client and server mTLS authentication.
func generateMTLSCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test-cert",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth, // Critical for mTLS
		},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return certPEM, keyPEM
}

// TestMTLSPolicyDownstreamRequired verifies that downstream mTLS enforcement
// correctly requires and validates client certificates when enabled.
func TestMTLSPolicyDownstreamRequired(t *testing.T) {
	// Generate test certificates
	serverCertPEM, serverKeyPEM := generateMTLSCert(t)
	clientCertPEM, clientKeyPEM := generateMTLSCert(t)

	// Parse certificates
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	require.NoError(t, err)

	// Create trust pool with client cert for server validation
	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(clientCertPEM)

	// Setup certificate provider
	certProvider := &mockCertProvider{
		downstreamCert: serverCert,
	}

	// Create trust bundle with client cert
	trustBundle := &config.TrustBundle{
		Name:   "client-bundle",
		Inline: string(clientCertPEM),
	}

	// Setup PolicyMTLS
	policyMTLS, err := tlspkg.NewPolicyMTLS(certProvider)
	require.NoError(t, err)

	policyMTLS.UpdateTrustBundles(map[string]*config.TrustBundle{
		"client-bundle": trustBundle,
	})

	// Create policy spec with downstream mTLS required
	policy := config.PolicySpec{
		ID: "test-policy",
		MTLS: config.EffectiveMTLS{
			Downstream: config.DirectionMTLS{
				Require:          true,
				TrustBundle:      "client-bundle",
				PeerVerification: config.PeerVerificationTrustBundleOnly,
			},
		},
	}

	// Build downstream TLS config
	tlsConfig, err := policyMTLS.DownstreamConfig(policy)
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	// Verify TLS config settings
	assert.Equal(t, tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth)
	assert.NotNil(t, tlsConfig.ClientCAs)
	assert.GreaterOrEqual(t, tlsConfig.MinVersion, uint16(tls.VersionTLS12))

	// Create test server with mTLS
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify client certificate was presented and validated
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Error("Expected client certificate in request")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("authenticated"))
	})

	server := httptest.NewUnstartedServer(handler)
	server.TLS = tlsConfig
	server.StartTLS()
	defer server.Close()

	t.Run("Valid client certificate accepted", func(t *testing.T) {
		// Create client with valid certificate
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates:       []tls.Certificate{clientCert},
					InsecureSkipVerify: true, // #nosec G402 - Test environment only
				},
			},
		}

		resp, err := client.Get(server.URL)
		require.NoError(t, err)
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.Logf("Failed to close response body: %v", err)
			}
		}()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "authenticated", string(body))
	})

	t.Run("No client certificate rejected", func(t *testing.T) {
		// Create client without certificate
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // #nosec G402 - Test environment only
				},
			},
		}

		_, err := client.Get(server.URL)
		// Should fail during TLS handshake due to missing client cert
		assert.Error(t, err, "Request without client certificate should fail")
	})
}

// TestMTLSPolicyDownstreamOptional verifies that when downstream mTLS is not
// required, connections succeed without client certificates.
func TestMTLSPolicyDownstreamOptional(t *testing.T) {
	serverCertPEM, serverKeyPEM := generateMTLSCert(t)
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	certProvider := &mockCertProvider{
		downstreamCert: serverCert,
	}

	policyMTLS, err := tlspkg.NewPolicyMTLS(certProvider)
	require.NoError(t, err)

	// Policy with downstream mTLS NOT required
	policy := config.PolicySpec{
		ID: "test-policy",
		MTLS: config.EffectiveMTLS{
			Downstream: config.DirectionMTLS{
				Require: false, // mTLS optional
			},
		},
	}

	// Build downstream TLS config
	tlsConfig, err := policyMTLS.DownstreamConfig(policy)
	require.NoError(t, err)

	// Should return nil when mTLS not required
	assert.Nil(t, tlsConfig, "DownstreamConfig should return nil when mTLS not required")
}

// TestMTLSPolicyUpstreamRequired verifies that upstream mTLS correctly
// presents client certificates to upstream services.
func TestMTLSPolicyUpstreamRequired(t *testing.T) {
	// Generate certificates
	upstreamServerCertPEM, upstreamServerKeyPEM := generateMTLSCert(t)
	proxyClientCertPEM, proxyClientKeyPEM := generateMTLSCert(t)

	upstreamServerCert, err := tls.X509KeyPair(upstreamServerCertPEM, upstreamServerKeyPEM)
	require.NoError(t, err)

	proxyClientCert, err := tls.X509KeyPair(proxyClientCertPEM, proxyClientKeyPEM)
	require.NoError(t, err)

	// Create trust pool with proxy client cert for upstream server validation
	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(proxyClientCertPEM)

	// Setup certificate provider for proxy
	certProvider := &mockCertProvider{
		upstreamCert: proxyClientCert,
	}

	// Create trust bundle with upstream server cert
	trustBundle := &config.TrustBundle{
		Name:   "upstream-bundle",
		Inline: string(upstreamServerCertPEM),
	}

	// Setup PolicyMTLS
	policyMTLS, err := tlspkg.NewPolicyMTLS(certProvider)
	require.NoError(t, err)

	policyMTLS.UpdateTrustBundles(map[string]*config.TrustBundle{
		"upstream-bundle": trustBundle,
	})

	// Create policy spec with upstream mTLS required
	policy := config.PolicySpec{
		ID: "test-policy",
		MTLS: config.EffectiveMTLS{
			Upstream: config.DirectionMTLS{
				Require:          true,
				TrustBundle:      "upstream-bundle",
				PeerVerification: config.PeerVerificationTrustBundleOnly,
			},
		},
	}

	// Build upstream TLS config
	tlsConfig, err := policyMTLS.UpstreamConfig(policy, "test-service")
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	// Verify TLS config settings
	assert.NotNil(t, tlsConfig.RootCAs)
	assert.Len(t, tlsConfig.Certificates, 1)
	assert.GreaterOrEqual(t, tlsConfig.MinVersion, uint16(tls.VersionTLS12))

	// Create upstream server requiring client certificates
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify proxy presented client certificate
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Error("Expected proxy client certificate in upstream request")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-authenticated"))
	})

	upstream := httptest.NewUnstartedServer(handler)
	upstream.TLS = &tls.Config{
		Certificates: []tls.Certificate{upstreamServerCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCertPool,
		MinVersion:   tls.VersionTLS12, // #nosec G402 - TLS 1.2 is acceptable for test environment
	}
	upstream.StartTLS()
	defer upstream.Close()

	t.Run("Proxy presents client certificate to upstream", func(t *testing.T) {
		// Create HTTP client using the proxy's TLS config
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}

		resp, err := client.Get(upstream.URL)
		require.NoError(t, err)
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.Logf("Failed to close response body: %v", err)
			}
		}()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "upstream-authenticated", string(body))
	})
}

// TestMTLSPolicyUpstreamOptional verifies that when upstream mTLS is not
// required, the proxy connects without presenting client certificates.
func TestMTLSPolicyUpstreamOptional(t *testing.T) {
	proxyClientCertPEM, proxyClientKeyPEM := generateMTLSCert(t)
	proxyClientCert, err := tls.X509KeyPair(proxyClientCertPEM, proxyClientKeyPEM)
	require.NoError(t, err)

	certProvider := &mockCertProvider{
		upstreamCert: proxyClientCert,
	}

	policyMTLS, err := tlspkg.NewPolicyMTLS(certProvider)
	require.NoError(t, err)

	// Policy with upstream mTLS NOT required
	policy := config.PolicySpec{
		ID: "test-policy",
		MTLS: config.EffectiveMTLS{
			Upstream: config.DirectionMTLS{
				Require: false, // mTLS optional
			},
		},
	}

	// Build upstream TLS config
	tlsConfig, err := policyMTLS.UpstreamConfig(policy, "test-service")
	require.NoError(t, err)

	// Should return nil when mTLS not required
	assert.Nil(t, tlsConfig, "UpstreamConfig should return nil when mTLS not required")
}

// TestMTLSPolicyPerRouteToggle verifies that different routes can have
// different mTLS requirements enforced independently.
func TestMTLSPolicyPerRouteToggle(t *testing.T) {
	// Generate certificates
	serverCertPEM, serverKeyPEM := generateMTLSCert(t)
	clientCertPEM, clientKeyPEM := generateMTLSCert(t)

	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	require.NoError(t, err)
	_ = clientCert // Will be used in future test scenarios

	// Setup trust bundle
	trustBundle := &config.TrustBundle{
		Name:   "client-bundle",
		Inline: string(clientCertPEM),
	}

	certProvider := &mockCertProvider{
		downstreamCert: serverCert,
	}

	policyMTLS, err := tlspkg.NewPolicyMTLS(certProvider)
	require.NoError(t, err)

	policyMTLS.UpdateTrustBundles(map[string]*config.TrustBundle{
		"client-bundle": trustBundle,
	})

	// Policy 1: mTLS required (for /secure route)
	securePolicy := config.PolicySpec{
		ID: "secure-policy",
		MTLS: config.EffectiveMTLS{
			Downstream: config.DirectionMTLS{
				Require:          true,
				TrustBundle:      "client-bundle",
				PeerVerification: config.PeerVerificationTrustBundleOnly,
			},
		},
	}

	// Policy 2: mTLS NOT required (for /public route)
	publicPolicy := config.PolicySpec{
		ID: "public-policy",
		MTLS: config.EffectiveMTLS{
			Downstream: config.DirectionMTLS{
				Require: false,
			},
		},
	}

	t.Run("Secure route requires mTLS", func(t *testing.T) {
		tlsConfig, err := policyMTLS.DownstreamConfig(securePolicy)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)

		assert.Equal(t, tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth,
			"Secure route should require client certificates")
	})

	t.Run("Public route does not require mTLS", func(t *testing.T) {
		tlsConfig, err := policyMTLS.DownstreamConfig(publicPolicy)
		require.NoError(t, err)

		assert.Nil(t, tlsConfig,
			"Public route should not require mTLS")
	})
}

// TestMTLSPolicyTrustBundleSelection verifies that different trust bundles
// can be selected per policy for certificate validation.
func TestMTLSPolicyTrustBundleSelection(t *testing.T) {
	// Generate multiple CA certificates
	ca1CertPEM, ca1KeyPEM := generateMTLSCert(t)
	ca2CertPEM, ca2KeyPEM := generateMTLSCert(t)
	serverCertPEM, serverKeyPEM := generateMTLSCert(t)

	_, _ = ca1KeyPEM, ca2KeyPEM // Keys not needed for trust validation

	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	// Create separate trust bundles
	bundle1 := &config.TrustBundle{
		Name:   "bundle-1",
		Inline: string(ca1CertPEM),
	}

	bundle2 := &config.TrustBundle{
		Name:   "bundle-2",
		Inline: string(ca2CertPEM),
	}

	certProvider := &mockCertProvider{
		upstreamCert: serverCert,
	}

	policyMTLS, err := tlspkg.NewPolicyMTLS(certProvider)
	require.NoError(t, err)

	policyMTLS.UpdateTrustBundles(map[string]*config.TrustBundle{
		"bundle-1": bundle1,
		"bundle-2": bundle2,
	})

	t.Run("Policy selects bundle-1", func(t *testing.T) {
		policy := config.PolicySpec{
			ID: "policy-1",
			MTLS: config.EffectiveMTLS{
				Upstream: config.DirectionMTLS{
					Require:          true,
					TrustBundle:      "bundle-1",
					PeerVerification: config.PeerVerificationTrustBundleOnly,
				},
			},
		}

		tlsConfig, err := policyMTLS.UpstreamConfig(policy, "service-1")
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		assert.NotNil(t, tlsConfig.RootCAs, "Should use bundle-1 roots")
	})

	t.Run("Policy selects bundle-2", func(t *testing.T) {
		policy := config.PolicySpec{
			ID: "policy-2",
			MTLS: config.EffectiveMTLS{
				Upstream: config.DirectionMTLS{
					Require:          true,
					TrustBundle:      "bundle-2",
					PeerVerification: config.PeerVerificationTrustBundleOnly,
				},
			},
		}

		tlsConfig, err := policyMTLS.UpstreamConfig(policy, "service-2")
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		assert.NotNil(t, tlsConfig.RootCAs, "Should use bundle-2 roots")
	})

	t.Run("Unknown trust bundle returns error", func(t *testing.T) {
		policy := config.PolicySpec{
			ID: "policy-3",
			MTLS: config.EffectiveMTLS{
				Upstream: config.DirectionMTLS{
					Require:          true,
					TrustBundle:      "unknown-bundle",
					PeerVerification: config.PeerVerificationTrustBundleOnly,
				},
			},
		}

		_, err := policyMTLS.UpstreamConfig(policy, "service-3")
		assert.Error(t, err, "Should fail for unknown trust bundle")
		assert.Contains(t, err.Error(), "trust bundle unknown-bundle not found")
	})
}

// TestMTLSPolicyPeerVerificationModes verifies that different peer verification
// modes (strict vs trust-bundle-only) are correctly applied.
func TestMTLSPolicyPeerVerificationModes(t *testing.T) {
	serverCertPEM, serverKeyPEM := generateMTLSCert(t)
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	trustBundle := &config.TrustBundle{
		Name:   "test-bundle",
		Inline: string(serverCertPEM),
	}

	certProvider := &mockCertProvider{
		upstreamCert: serverCert,
	}

	policyMTLS, err := tlspkg.NewPolicyMTLS(certProvider)
	require.NoError(t, err)

	policyMTLS.UpdateTrustBundles(map[string]*config.TrustBundle{
		"test-bundle": trustBundle,
	})

	t.Run("Strict peer verification requires ServerName", func(t *testing.T) {
		policy := config.PolicySpec{
			ID: "strict-policy",
			MTLS: config.EffectiveMTLS{
				Upstream: config.DirectionMTLS{
					Require:          true,
					TrustBundle:      "test-bundle",
					PeerVerification: config.PeerVerificationStrict,
				},
			},
		}

		// With valid server name
		tlsConfig, err := policyMTLS.UpstreamConfig(policy, "test-service.example.com")
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		assert.Equal(t, "test-service.example.com", tlsConfig.ServerName,
			"Strict mode should set ServerName")

		// Without server name (empty string)
		_, err = policyMTLS.UpstreamConfig(policy, "")
		assert.Error(t, err, "Strict mode should require ServerName")
		assert.Contains(t, err.Error(), "peer verification requires server name")
	})

	t.Run("Trust-bundle-only mode does not require ServerName", func(t *testing.T) {
		policy := config.PolicySpec{
			ID: "trust-bundle-policy",
			MTLS: config.EffectiveMTLS{
				Upstream: config.DirectionMTLS{
					Require:          true,
					TrustBundle:      "test-bundle",
					PeerVerification: config.PeerVerificationTrustBundleOnly,
				},
			},
		}

		// Without server name should succeed
		tlsConfig, err := policyMTLS.UpstreamConfig(policy, "")
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		assert.Empty(t, tlsConfig.ServerName,
			"Trust-bundle-only mode should not set ServerName")
	})
}

// TestMTLSPolicyUpdateTrustBundles verifies that trust bundles can be
// dynamically updated without disrupting existing connections.
func TestMTLSPolicyUpdateTrustBundles(t *testing.T) {
	serverCertPEM, serverKeyPEM := generateMTLSCert(t)
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	certProvider := &mockCertProvider{
		upstreamCert: serverCert,
	}

	policyMTLS, err := tlspkg.NewPolicyMTLS(certProvider)
	require.NoError(t, err)

	// Initial trust bundles
	bundle1 := &config.TrustBundle{
		Name:   "bundle-1",
		Inline: string(serverCertPEM),
	}

	policyMTLS.UpdateTrustBundles(map[string]*config.TrustBundle{
		"bundle-1": bundle1,
	})

	policy := config.PolicySpec{
		ID: "test-policy",
		MTLS: config.EffectiveMTLS{
			Upstream: config.DirectionMTLS{
				Require:          true,
				TrustBundle:      "bundle-1",
				PeerVerification: config.PeerVerificationTrustBundleOnly,
			},
		},
	}

	// Verify bundle-1 works
	tlsConfig, err := policyMTLS.UpstreamConfig(policy, "service")
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	// Update with new bundle
	newCertPEM, _ := generateMTLSCert(t)
	bundle2 := &config.TrustBundle{
		Name:   "bundle-2",
		Inline: string(newCertPEM),
	}

	policyMTLS.UpdateTrustBundles(map[string]*config.TrustBundle{
		"bundle-2": bundle2,
	})

	// Old bundle should no longer be available
	policy.MTLS.Upstream.TrustBundle = "bundle-1"
	_, err = policyMTLS.UpstreamConfig(policy, "service")
	assert.Error(t, err, "Old bundle should be removed after update")

	// New bundle should be available
	policy.MTLS.Upstream.TrustBundle = "bundle-2"
	tlsConfig, err = policyMTLS.UpstreamConfig(policy, "service")
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
}

// mockCertProvider is a test implementation of CertificateProvider.
type mockCertProvider struct {
	downstreamCert tls.Certificate
	upstreamCert   tls.Certificate
	downstreamErr  error
	upstreamErr    error
}

func (m *mockCertProvider) DownstreamCertificate(_ string) (tls.Certificate, error) {
	if m.downstreamErr != nil {
		return tls.Certificate{}, m.downstreamErr
	}
	return m.downstreamCert, nil
}

func (m *mockCertProvider) UpstreamCertificate(_ string) (tls.Certificate, error) {
	if m.upstreamErr != nil {
		return tls.Certificate{}, m.upstreamErr
	}
	return m.upstreamCert, nil
}
