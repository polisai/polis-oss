package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/polisai/polis-oss/pkg/domain"
	pipelinepkg "github.com/polisai/polis-oss/pkg/engine"
)

func closeBody(t *testing.T, c io.Closer) {
	t.Helper()

	if c == nil {
		return
	}

	if err := c.Close(); err != nil {
		t.Fatalf("failed to close body: %v", err)
	}
}

// MockUpstream represents a test upstream server that tracks received requests.
type MockUpstream struct {
	server          *httptest.Server
	mu              sync.Mutex
	requests        []*http.Request
	headers         []http.Header
	responseCode    int
	responseBody    string
	responseHeaders http.Header
	delay           time.Duration
}

// NewMockUpstream creates a new mock upstream server.
func NewMockUpstream(t *testing.T) *MockUpstream {
	t.Helper()

	upstream := &MockUpstream{
		responseCode:    http.StatusOK,
		responseBody:    `{"status": "ok"}`,
		responseHeaders: make(http.Header),
	}

	upstream.server = httptest.NewServer(http.HandlerFunc(upstream.handler))
	return upstream
}

// Close shuts down the mock upstream server.
func (m *MockUpstream) Close() {
	if m.server != nil {
		m.server.Close()
	}
}

// URL returns the base URL of the mock upstream.
func (m *MockUpstream) URL() string {
	return m.server.URL
}

// SetResponse configures the response code and body.
func (m *MockUpstream) SetResponse(code int, body string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responseCode = code
	m.responseBody = body
}

// SetResponseHeader sets a header to include in the upstream response.
func (m *MockUpstream) SetResponseHeader(name, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.responseHeaders == nil {
		m.responseHeaders = make(http.Header)
	}
	m.responseHeaders.Set(name, value)
}

// ClearResponseHeaders removes configured response headers.
func (m *MockUpstream) ClearResponseHeaders() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.responseHeaders != nil {
		for k := range m.responseHeaders {
			delete(m.responseHeaders, k)
		}
	}
}

// SetDelay configures a delay before responding.
func (m *MockUpstream) SetDelay(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delay = d
}

// GetRequests returns a copy of all received requests.
func (m *MockUpstream) GetRequests() []*http.Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*http.Request(nil), m.requests...)
}

// GetHeaders returns a copy of all received request headers.
func (m *MockUpstream) GetHeaders() []http.Header {
	m.mu.Lock()
	defer m.mu.Unlock()
	headers := make([]http.Header, len(m.headers))
	for i, h := range m.headers {
		headers[i] = h.Clone()
	}
	return headers
}

// LastRequest returns the most recent request received.
func (m *MockUpstream) LastRequest() *http.Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.requests) == 0 {
		return nil
	}
	return m.requests[len(m.requests)-1]
}

// LastHeaders returns the headers of the most recent request.
func (m *MockUpstream) LastHeaders() http.Header {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.headers) == 0 {
		return nil
	}
	return m.headers[len(m.headers)-1].Clone()
}

// Reset clears all tracked requests and headers.
func (m *MockUpstream) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = nil
	m.headers = nil
}

// handler processes incoming requests and tracks them.
func (m *MockUpstream) handler(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.requests = append(m.requests, r)
	m.headers = append(m.headers, r.Header.Clone())
	delay := m.delay
	code := m.responseCode
	body := m.responseBody
	var respHeaders http.Header
	if m.responseHeaders != nil {
		respHeaders = m.responseHeaders.Clone()
	}
	m.mu.Unlock()

	// Apply delay if configured
	if delay > 0 {
		time.Sleep(delay)
	}

	for key, values := range respHeaders {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(code)
	if _, err := w.Write([]byte(body)); err != nil {
		http.Error(w, "failed to write response body", http.StatusInternalServerError)
	}
}

// StreamingMockUpstream provides a mock server that streams responses.
type StreamingMockUpstream struct {
	server      *httptest.Server
	chunks      []string
	chunkDelay  time.Duration
	contentType string
}

// NewStreamingMockUpstream creates a mock upstream that sends chunked responses.
func NewStreamingMockUpstream(t *testing.T, chunks []string, chunkDelay time.Duration) *StreamingMockUpstream {
	t.Helper()

	upstream := &StreamingMockUpstream{
		chunks:      chunks,
		chunkDelay:  chunkDelay,
		contentType: "text/plain",
	}

	upstream.server = httptest.NewServer(http.HandlerFunc(upstream.handler))
	return upstream
}

// Close shuts down the streaming mock upstream.
func (s *StreamingMockUpstream) Close() {
	if s.server != nil {
		s.server.Close()
	}
}

// URL returns the base URL of the streaming mock upstream.
func (s *StreamingMockUpstream) URL() string {
	return s.server.URL
}

// SetContentType configures the Content-Type header.
func (s *StreamingMockUpstream) SetContentType(contentType string) {
	s.contentType = contentType
}

// handler streams chunks with delays.
func (s *StreamingMockUpstream) handler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", s.contentType)
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	for _, chunk := range s.chunks {
		if _, err := w.Write([]byte(chunk)); err != nil {
			http.Error(w, "failed to write chunk", http.StatusInternalServerError)
			return
		}
		flusher.Flush()
		if s.chunkDelay > 0 {
			time.Sleep(s.chunkDelay)
		}
	}
}

// MockTokenProvider implements auth.TokenProvider for testing.
type MockTokenProvider struct {
	mu     sync.Mutex
	tokens map[string]string // upstream -> token
	calls  []string          // track which upstreams were called
	delay  time.Duration
	err    error
}

// NewMockTokenProvider creates a new mock token provider.
func NewMockTokenProvider() *MockTokenProvider {
	return &MockTokenProvider{
		tokens: make(map[string]string),
	}
}

// SetToken configures the token to return for a given upstream.
func (m *MockTokenProvider) SetToken(upstream, token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[upstream] = token
}

// SetError configures an error to return.
func (m *MockTokenProvider) SetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

// SetDelay configures a delay for token acquisition.
func (m *MockTokenProvider) SetDelay(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delay = d
}

// GetCalls returns the list of upstreams for which tokens were requested.
func (m *MockTokenProvider) GetCalls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.calls...)
}

// AcquireToken returns a configured token for the upstream.
func (m *MockTokenProvider) AcquireToken(upstream string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, upstream)

	if m.err != nil {
		return "", m.err
	}

	if m.delay > 0 {
		time.Sleep(m.delay)
	}

	token, ok := m.tokens[upstream]
	if !ok {
		return "", fmt.Errorf("no token configured for upstream: %s", upstream)
	}

	return token, nil
}

// Token implements the pipeline.TokenProvider interface.
func (m *MockTokenProvider) Token(_ context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.err != nil {
		return "", m.err
	}

	if m.delay > 0 {
		time.Sleep(m.delay)
	}

	// Return a default token for the Token() interface
	// In production, this would use the context to determine the upstream
	for _, token := range m.tokens {
		return token, nil
	}

	return "default-egress-token", nil
}

// GenerateSelfSignedCert generates a self-signed certificate for testing mTLS.
func GenerateSelfSignedCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return certPEM, keyPEM
}

// AssertNoCredentialLeak verifies that no inbound credentials were forwarded to upstream.
func AssertNoCredentialLeak(t *testing.T, headers http.Header, inboundToken string) {
	t.Helper()

	authHeader := headers.Get("Authorization")
	if authHeader != "" && authHeader == inboundToken {
		t.Errorf("SECURITY VIOLATION: Inbound Authorization token was leaked to upstream: %s", authHeader)
	}

	bannedHeaders := []string{
		"Cookie",
		"Proxy-Authorization",
		"X-Forwarded-Access-Token",
		"X-Forwarded-Authorization",
		"X-Identity-Token",
	}

	for _, header := range bannedHeaders {
		if val := headers.Get(header); val != "" {
			t.Errorf("SECURITY VIOLATION: Banned credential header %s was present in upstream request: %s", header, val)
		}
	}
}

// WaitForCondition polls a condition function until it returns true or times out.
func WaitForCondition(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("Condition not met within timeout %v", timeout)
}

// setupProxyPipeline creates a test proxy server using the DAG handler for integration testing.
// It configures routing in passthrough mode (no JWT validation).
// Requests must include X-Agent-ID header set to "test-route" to match the pipeline.
func setupProxyPipeline(t *testing.T, upstream *MockUpstream) *httptest.Server {
	t.Helper()

	// Get upstream URL
	upstreamURL := upstream.URL()

	// Create pipeline registry (no factory needed for basic tests)
	registry := pipelinepkg.NewPipelineRegistry(nil)

	// Register a simple pass-through pipeline for the test route
	// IMPORTANT: The egress node needs upstream_url in its Config
	pipeline := domain.Pipeline{
		ID:       "test-route",
		Version:  1,
		AgentID:  "test-route",
		Protocol: "http",
		Nodes: []domain.PipelineNode{
			{
				ID:   "start",
				Type: "auth",
				On: domain.NodeHandlers{
					Success: "egress",
				},
			},
			{
				ID:   "egress",
				Type: "egress",
				Config: map[string]interface{}{
					"upstream_url": upstreamURL,
				},
			},
		},
	}

	if err := registry.UpdatePipelines(context.Background(), []domain.Pipeline{pipeline}); err != nil {
		t.Fatalf("failed to register pipeline: %v", err)
	}

	// Create DAG handler
	handler := pipelinepkg.NewDAGHandler(pipelinepkg.DAGHandlerConfig{
		Registry: registry,
	})

	return httptest.NewServer(handler)
}
