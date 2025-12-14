package tls

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/polisai/polis-oss/pkg/config"
	"github.com/polisai/polis-oss/pkg/domain"
	pipelinepkg "github.com/polisai/polis-oss/pkg/engine"
)

// TLSServer handles TLS termination for incoming connections
type TLSServer struct {
	config           *config.TLSConfig
	certManager      CertificateManager
	terminator       TLSTerminator
	tlsConfig        *tls.Config
	listeners        []net.Listener
	pipelineHandler  *TLSPipelineHandler
	metrics          *TLSMetrics
	metricsCollector *TLSMetricsCollector
	certMonitor      *CertificateMonitor
	degradationMgr   *DegradationManager
	securityHeaders  *SecurityHeadersMiddleware
	connectionPool   *ConnectionPool
	logger           *slog.Logger

	// Server state
	mu       sync.RWMutex
	running  bool
	shutdown chan struct{}
	wg       sync.WaitGroup
}

// TLSPipelineHandler integrates TLS termination with pipeline processing
type TLSPipelineHandler struct {
	dagHandler *pipelinepkg.DAGHandler
	logger     *slog.Logger
}

// TLSMetrics tracks TLS termination metrics
type TLSMetrics struct {
	ConnectionsTotal        int64            `json:"connections_total"`
	ConnectionsActive       int64            `json:"connections_active"`
	HandshakeErrors         int64            `json:"handshake_errors"`
	CertificateErrors       int64            `json:"certificate_errors"`
	HandshakeDuration       time.Duration    `json:"avg_handshake_duration"`
	TLSVersionDistribution  map[string]int64 `json:"tls_version_distribution"`
	CipherSuiteDistribution map[string]int64 `json:"cipher_suite_distribution"`

	mu sync.RWMutex
}

// NewTLSServer creates a new TLS server with the given configuration
func NewTLSServer(cfg *config.TLSConfig, dagHandler *pipelinepkg.DAGHandler, logger *slog.Logger) (*TLSServer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("TLS configuration is required")
	}
	if !cfg.Enabled {
		return nil, fmt.Errorf("TLS is not enabled in configuration")
	}
	if dagHandler == nil {
		return nil, fmt.Errorf("DAG handler is required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	// Create TLS terminator and certificate manager
	terminator := NewTLSTerminator(logger)

	// Build TLS configuration
	tlsConfig, err := terminator.BuildServerConfig(*cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build TLS configuration: %w", err)
	}

	// Create pipeline handler
	pipelineHandler := &TLSPipelineHandler{
		dagHandler: dagHandler,
		logger:     logger,
	}

	// Initialize metrics
	metrics := &TLSMetrics{
		TLSVersionDistribution:  make(map[string]int64),
		CipherSuiteDistribution: make(map[string]int64),
	}

	// Initialize metrics collector
	metricsCollector, err := GetTLSMetricsCollector(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize TLS metrics collector: %w", err)
	}

	// Initialize certificate monitor
	certMonitor := NewCertificateMonitor(terminator.GetCertificateManager(), metricsCollector, logger)

	// Initialize degradation manager
	degradationMgr := NewDegradationManager(logger)

	// Initialize security headers middleware
	var securityHeaders *SecurityHeadersMiddleware
	securityHeaders = NewSecurityHeadersMiddleware(terminator.GetSecurityDefaults().SecurityHeaders)

	// Initialize connection pool for upstream connections
	connectionPool := NewConnectionPool(100, 5*time.Minute, logger)

	server := &TLSServer{
		config:           cfg,
		certManager:      terminator.GetCertificateManager(),
		terminator:       terminator,
		tlsConfig:        tlsConfig,
		pipelineHandler:  pipelineHandler,
		metrics:          metrics,
		metricsCollector: metricsCollector,
		certMonitor:      certMonitor,
		degradationMgr:   degradationMgr,
		securityHeaders:  securityHeaders,
		connectionPool:   connectionPool,
		logger:           logger,
		shutdown:         make(chan struct{}),
	}

	return server, nil
}

// Start initializes TLS listeners and begins accepting connections with comprehensive error handling
func (s *TLSServer) Start(ctx context.Context, addresses []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return NewServerStartupError("server already running", fmt.Errorf("TLS server is already running"))
	}

	if len(addresses) == 0 {
		return NewConfigMissingError("addresses").
			WithSuggestion("Provide at least one address to listen on").
			WithSuggestion("Example: :8443 for HTTPS on port 8443")
	}

	s.logger.Info("Starting TLS server", "addresses", addresses)

	// Validate TLS configuration before starting
	if err := s.validateStartupConfiguration(); err != nil {
		s.degradationMgr.RecordError(ctx, ReasonConfigurationErrors, err)
		return err
	}

	// Create listeners for each address with detailed error handling
	for i, addr := range addresses {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			// Clean up any listeners we've already created
			s.closeListeners()

			var tlsErr *TLSError
			if strings.Contains(err.Error(), "address already in use") {
				tlsErr = NewListenerCreateError(addr, err).
					WithSuggestion("Check if another process is using this port").
					WithSuggestion("Use 'netstat -tlnp' or 'ss -tlnp' to find the process").
					WithSuggestion("Consider using a different port")
			} else if strings.Contains(err.Error(), "permission denied") {
				tlsErr = NewListenerCreateError(addr, err).
					WithSuggestion("Run with appropriate privileges to bind to this port").
					WithSuggestion("Ports below 1024 typically require root privileges").
					WithSuggestion("Consider using a port above 1024")
			} else {
				tlsErr = NewListenerCreateError(addr, err).
					WithSuggestion("Check the address format is correct").
					WithSuggestion("Ensure the network interface is available")
			}

			s.degradationMgr.RecordError(ctx, ReasonConfigurationErrors, tlsErr)
			return tlsErr
		}

		// Wrap with TLS
		tlsListener := tls.NewListener(listener, s.tlsConfig)
		s.listeners = append(s.listeners, tlsListener)

		s.logger.Info("TLS listener created",
			"address", listener.Addr().String(),
			"listener_index", i,
			"total_listeners", len(s.listeners))
	}

	// Start certificate file watching with error handling
	if err := s.startCertificateWatching(); err != nil {
		s.logger.Warn("Failed to start certificate watching", "error", err)
		s.degradationMgr.RecordError(ctx, ReasonFileSystemErrors, err)
		// Don't fail startup for this - certificate watching is optional but degraded
	}

	// Start certificate monitoring with error handling
	if err := s.certMonitor.Start(ctx); err != nil {
		s.logger.Warn("Failed to start certificate monitoring", "error", err)
		s.degradationMgr.RecordError(ctx, ReasonConfigurationErrors, err)
		// Don't fail startup for this - certificate monitoring is optional but degraded
	}

	s.running = true

	// Start accepting connections on each listener
	for i, listener := range s.listeners {
		s.wg.Add(1)
		go s.acceptConnections(ctx, listener, i)
	}

	// Start periodic recovery checks
	s.wg.Add(1)
	go s.runPeriodicRecoveryChecks(ctx)

	s.logger.Info("TLS server started successfully",
		"listener_count", len(s.listeners),
		"addresses", addresses,
		"tls_version_min", s.config.MinVersion,
		"cipher_suites_count", len(s.config.CipherSuites))

	return nil
}

// validateStartupConfiguration validates the TLS configuration before starting
func (s *TLSServer) validateStartupConfiguration() error {
	// Validate TLS configuration
	if err := s.config.Validate(); err != nil {
		return NewConfigValidationError("tls_config", s.config, err.Error()).
			WithSuggestion("Fix the TLS configuration errors").
			WithSuggestion("Check certificate file paths and permissions")
	}

	// Validate certificate manager state
	if s.certManager == nil {
		return NewServerStartupError("certificate manager not initialized",
			fmt.Errorf("certificate manager is nil"))
	}

	// Validate TLS configuration object
	if s.tlsConfig == nil {
		return NewServerStartupError("TLS configuration not built",
			fmt.Errorf("TLS config is nil"))
	}

	// Check if certificates are accessible
	if len(s.tlsConfig.Certificates) == 0 && s.tlsConfig.GetCertificate == nil {
		return NewServerStartupError("no certificates available",
			fmt.Errorf("no certificates configured")).
			WithSuggestion("Configure at least one certificate").
			WithSuggestion("Check certificate file paths and permissions")
	}

	return nil
}

// runPeriodicRecoveryChecks runs periodic checks for service recovery
func (s *TLSServer) runPeriodicRecoveryChecks(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.shutdown:
			return
		case <-ticker.C:
			s.degradationMgr.CheckRecovery(ctx)
		}
	}
}

// acceptConnections handles incoming connections on a listener
func (s *TLSServer) acceptConnections(ctx context.Context, listener net.Listener, listenerIndex int) {
	defer s.wg.Done()

	s.logger.Info("Accepting TLS connections", "address", listener.Addr().String())

	for {
		select {
		case <-s.shutdown:
			return
		case <-ctx.Done():
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.shutdown:
				return
			case <-ctx.Done():
				return
			default:
			}

			s.logger.Error("Failed to accept connection", "error", err, "listener", listenerIndex)
			continue
		}

		// Handle connection in a goroutine
		s.wg.Add(1)
		go s.handleConnection(ctx, conn)
	}
}

// HandleConnection processes individual TLS connections
func (s *TLSServer) handleConnection(ctx context.Context, conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	connectionStart := time.Now()
	var serverName string
	remoteAddr := conn.RemoteAddr().String()

	// Perform TLS handshake if not already done
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		err := NewConnectionHandleError(remoteAddr, "invalid connection type",
			fmt.Errorf("connection is not a TLS connection"))
		s.logger.Error("Connection handling failed", "error", err.GetDetailedMessage())
		s.metricsCollector.RecordHandshakeError(ctx, serverName, "invalid_connection", err.Error())
		return
	}

	// Record connection start
	s.metricsCollector.RecordConnectionStart(ctx, serverName)
	defer func() {
		connectionDuration := time.Since(connectionStart)
		s.metricsCollector.RecordConnectionEnd(ctx, serverName, connectionDuration)
	}()

	s.updateConnectionMetrics(1, 0)        // Increment active connections for legacy metrics
	defer s.updateConnectionMetrics(-1, 0) // Ensure decrement happens

	handshakeStart := time.Now()

	// Set handshake timeout with error handling
	handshakeTimeout := 30 * time.Second
	if err := tlsConn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		tlsErr := NewConnectionHandleError(remoteAddr, "failed to set handshake timeout", err)
		s.logger.Error("Connection setup failed", "error", tlsErr.GetDetailedMessage())
		return
	}

	// Perform handshake with detailed error categorization
	if err := tlsConn.Handshake(); err != nil {
		handshakeError := err.Error()
		var tlsErr *TLSError

		// Categorize handshake errors for better diagnostics
		switch {
		case strings.Contains(handshakeError, "certificate"):
			if strings.Contains(handshakeError, "expired") {
				tlsErr = NewCertificateExpiredError("", "").
					WithContext("remote_addr", remoteAddr).
					WithContext("error_details", handshakeError)
			} else if strings.Contains(handshakeError, "unknown authority") {
				tlsErr = NewClientAuthError("certificate not trusted", err).
					WithContext("remote_addr", remoteAddr)
			} else {
				tlsErr = NewCertificateValidationError("handshake certificate error", err).
					WithContext("remote_addr", remoteAddr)
			}
		case strings.Contains(handshakeError, "timeout"):
			tlsErr = NewHandshakeTimeoutError(handshakeTimeout.String()).
				WithContext("remote_addr", remoteAddr)
		case strings.Contains(handshakeError, "protocol version"):
			tlsErr = NewProtocolMismatchError("unknown", s.config.MinVersion).
				WithContext("remote_addr", remoteAddr)
		case strings.Contains(handshakeError, "cipher"):
			tlsErr = NewCipherNegotiationError("unknown", strings.Join(s.config.CipherSuites, ",")).
				WithContext("remote_addr", remoteAddr)
		case strings.Contains(handshakeError, "bad certificate"):
			tlsErr = NewClientAuthError("bad certificate", err).
				WithContext("remote_addr", remoteAddr)
		default:
			tlsErr = NewHandshakeFailureError("unknown handshake error", err).
				WithContext("remote_addr", remoteAddr).
				WithContext("error_details", handshakeError)
		}

		// Log detailed error information
		s.logger.Error("TLS handshake failed",
			"error", tlsErr.GetDetailedMessage(),
			"remote_addr", remoteAddr,
			"duration", time.Since(handshakeStart))

		// Record metrics with categorized error type
		errorType := string(tlsErr.Type)
		s.metricsCollector.RecordHandshakeError(ctx, serverName, errorType, tlsErr.Error())
		s.updateConnectionMetrics(0, 1) // Increment error count

		// Report to degradation manager
		var degradationReason DegradationReason
		switch tlsErr.Type {
		case ErrorTypeCertificateExpired:
			degradationReason = ReasonCertificateExpired
		case ErrorTypeCertificateValidation, ErrorTypeCertificateLoad:
			degradationReason = ReasonCertificateInvalid
		case ErrorTypeHandshakeFailure, ErrorTypeHandshakeTimeout, ErrorTypeProtocolMismatch, ErrorTypeCipherNegotiation:
			degradationReason = ReasonHandshakeFailures
		case ErrorTypeClientAuth:
			degradationReason = ReasonHandshakeFailures
		default:
			degradationReason = ReasonHandshakeFailures
		}
		s.degradationMgr.RecordError(ctx, degradationReason, tlsErr)

		return
	}

	handshakeDuration := time.Since(handshakeStart)

	// Clear deadline after successful handshake
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		s.logger.Warn("Failed to clear connection deadline after handshake",
			"error", err, "remote_addr", remoteAddr)
		// Continue processing - this is not a fatal error
	}

	// Extract TLS context information
	tlsCtx := s.extractTLSContext(tlsConn, handshakeDuration)
	serverName = tlsCtx.ServerName

	// Record successful handshake with detailed metrics
	s.metricsCollector.RecordHandshakeSuccess(ctx, tlsCtx.Version, tlsCtx.CipherSuite,
		tlsCtx.ServerName, handshakeDuration, tlsCtx.ClientAuth)

	// Update legacy metrics
	s.updateHandshakeMetrics(tlsCtx)

	// Log successful handshake
	s.logger.Debug("TLS handshake completed successfully",
		"remote_addr", remoteAddr,
		"server_name", tlsCtx.ServerName,
		"tls_version", tlsCtx.Version,
		"cipher_suite", tlsCtx.CipherSuite,
		"client_auth", tlsCtx.ClientAuth,
		"handshake_duration", handshakeDuration)

	// Process HTTP requests over the TLS connection with error handling
	if err := s.processHTTPOverTLS(ctx, tlsConn, tlsCtx); err != nil {
		tlsErr := NewConnectionHandleError(remoteAddr, "HTTP processing failed", err)
		s.logger.Error("Failed to process HTTP over TLS",
			"error", tlsErr.GetDetailedMessage(),
			"remote_addr", remoteAddr,
			"server_name", tlsCtx.ServerName)

		// Record processing error metrics
		if s.metricsCollector != nil {
			s.metricsCollector.RecordHandshakeError(ctx, tlsCtx.ServerName, "http_processing", err.Error())
		}
	}
}

// processHTTPOverTLS handles HTTP requests over the established TLS connection
func (s *TLSServer) processHTTPOverTLS(ctx context.Context, tlsConn *tls.Conn, tlsCtx *domain.TLSContext) error {
	// Create HTTP handler with TLS context
	handler := &tlsHTTPHandler{
		pipelineHandler: s.pipelineHandler,
		tlsContext:      tlsCtx,
		logger:          s.logger,
	}

	// Use a buffered reader/writer for HTTP processing
	reader := bufio.NewReader(tlsConn)

	// Process HTTP requests in a loop
	for {
		// Set read timeout
		if err := tlsConn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			s.logger.Error("Failed to set read deadline", "error", err)
		}

		// Read HTTP request
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err == io.EOF {
				// Client closed connection - this is normal
				return nil
			}
			return fmt.Errorf("failed to read HTTP request: %w", err)
		}

		// Set the request URL scheme and host
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
		req.RequestURI = ""

		// Add TLS context to request
		req = req.WithContext(context.WithValue(ctx, "tls_context", tlsCtx))

		// Create response writer with security headers
		w := &tlsResponseWriter{
			conn:            tlsConn,
			header:          make(http.Header),
			securityHeaders: s.securityHeaders,
			logger:          s.logger,
		}

		// Process the request
		handler.ServeHTTP(w, req)

		// Check if connection should be closed
		if req.Header.Get("Connection") == "close" || (req.ProtoMajor == 1 && req.ProtoMinor == 0) {
			break
		}
	}

	return nil
}

// tlsHTTPHandler wraps the pipeline handler to inject TLS context
type tlsHTTPHandler struct {
	pipelineHandler *TLSPipelineHandler
	tlsContext      *domain.TLSContext
	logger          *slog.Logger
}

// ServeHTTP implements http.Handler
func (h *tlsHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Add TLS context to request
	r = h.addTLSContextToRequest(r)

	// Forward to pipeline handler
	h.pipelineHandler.ServeHTTP(w, r)
}

// addTLSContextToRequest adds TLS context information to the HTTP request
func (h *tlsHTTPHandler) addTLSContextToRequest(r *http.Request) *http.Request {
	// Add TLS context to request context
	ctx := context.WithValue(r.Context(), "tls_context", h.tlsContext)
	r = r.WithContext(ctx)

	// Add TLS information as headers for pipeline processing
	if h.tlsContext.Version != "" {
		r.Header.Set("X-TLS-Version", h.tlsContext.Version)
	}
	if h.tlsContext.CipherSuite != "" {
		r.Header.Set("X-TLS-Cipher-Suite", h.tlsContext.CipherSuite)
	}
	if h.tlsContext.ServerName != "" {
		r.Header.Set("X-TLS-Server-Name", h.tlsContext.ServerName)
	}
	if h.tlsContext.ClientAuth {
		r.Header.Set("X-TLS-Client-Auth", "true")
	}

	return r
}

// ServeHTTP implements http.Handler for TLSPipelineHandler
func (h *TLSPipelineHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract TLS context from request
	tlsCtx, _ := r.Context().Value("tls_context").(*domain.TLSContext)

	if tlsCtx != nil {
		h.logger.Debug("Processing TLS-terminated request",
			"method", r.Method,
			"path", r.URL.Path,
			"tls_version", tlsCtx.Version,
			"server_name", tlsCtx.ServerName,
		)
	}

	// Forward to DAG handler - it will handle the decrypted HTTP request
	// just like any other HTTP request, but with TLS context available
	h.dagHandler.ServeHTTP(w, r)
}

// extractTLSContext extracts TLS connection information
func (s *TLSServer) extractTLSContext(tlsConn *tls.Conn, handshakeDuration time.Duration) *domain.TLSContext {
	state := tlsConn.ConnectionState()

	ctx := &domain.TLSContext{
		Version:           s.tlsVersionString(state.Version),
		CipherSuite:       s.cipherSuiteString(state.CipherSuite),
		ServerName:        state.ServerName,
		HandshakeDuration: handshakeDuration,
		ClientAuth:        len(state.PeerCertificates) > 0,
	}

	// Extract peer certificate information
	if len(state.PeerCertificates) > 0 {
		ctx.PeerCertificates = make([]string, len(state.PeerCertificates))
		for i, cert := range state.PeerCertificates {
			ctx.PeerCertificates[i] = cert.Subject.String()
		}
	}

	// Extract negotiated protocol (ALPN)
	ctx.NegotiatedProtocol = state.NegotiatedProtocol

	return ctx
}

// tlsVersionString converts TLS version constant to string
func (s *TLSServer) tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("unknown(0x%04x)", version)
	}
}

// cipherSuiteString converts cipher suite constant to string
func (s *TLSServer) cipherSuiteString(suite uint16) string {
	switch suite {
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		return "TLS_RSA_WITH_RC4_128_SHA"
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	default:
		return fmt.Sprintf("unknown(0x%04x)", suite)
	}
}

// updateConnectionMetrics updates connection-related metrics
func (s *TLSServer) updateConnectionMetrics(activeDelta, errorDelta int64) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()

	if activeDelta > 0 {
		s.metrics.ConnectionsTotal += activeDelta
	}
	s.metrics.ConnectionsActive += activeDelta
	s.metrics.HandshakeErrors += errorDelta
}

// updateHandshakeMetrics updates handshake-related metrics
func (s *TLSServer) updateHandshakeMetrics(tlsCtx *domain.TLSContext) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()

	// Update TLS version distribution
	s.metrics.TLSVersionDistribution[tlsCtx.Version]++

	// Update cipher suite distribution
	s.metrics.CipherSuiteDistribution[tlsCtx.CipherSuite]++

	// Update average handshake duration (simple moving average)
	if s.metrics.HandshakeDuration == 0 {
		s.metrics.HandshakeDuration = tlsCtx.HandshakeDuration
	} else {
		s.metrics.HandshakeDuration = (s.metrics.HandshakeDuration + tlsCtx.HandshakeDuration) / 2
	}
}

// startCertificateWatching starts watching certificate files for changes
func (s *TLSServer) startCertificateWatching() error {
	return s.certManager.WatchCertificateFiles(func() {
		s.logger.Info("Certificate files changed, reloading TLS configuration")

		// Rebuild TLS configuration with new certificates
		newTLSConfig, err := s.terminator.BuildServerConfig(*s.config)
		if err != nil {
			s.logger.Error("Failed to rebuild TLS configuration after certificate reload", "error", err)
			return
		}

		// Update TLS configuration atomically
		s.mu.Lock()
		s.tlsConfig = newTLSConfig
		s.mu.Unlock()

		s.logger.Info("TLS configuration reloaded successfully")
	})
}

// Shutdown gracefully closes all listeners and connections
func (s *TLSServer) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.logger.Info("Shutting down TLS server")

	// Signal shutdown
	close(s.shutdown)

	// Close all listeners
	s.closeListeners()

	// Wait for all connections to finish with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("All TLS connections closed gracefully")
	case <-ctx.Done():
		s.logger.Warn("TLS server shutdown timeout exceeded")
	}

	// Stop certificate monitor
	if err := s.certMonitor.Stop(); err != nil {
		s.logger.Error("Failed to stop certificate monitor", "error", err)
	}

	// Close certificate manager
	if err := s.certManager.Close(); err != nil {
		s.logger.Error("Failed to close certificate manager", "error", err)
	}

	// Close connection pool
	if err := s.connectionPool.Close(); err != nil {
		s.logger.Error("Failed to close connection pool", "error", err)
	}

	// Close terminator if it has a Close method
	if closer, ok := s.terminator.(*DefaultTLSTerminator); ok {
		if err := closer.Close(); err != nil {
			s.logger.Error("Failed to close TLS terminator", "error", err)
		}
	}

	s.running = false
	s.logger.Info("TLS server shutdown complete")
	return nil
}

// closeListeners closes all listeners
func (s *TLSServer) closeListeners() {
	for i, listener := range s.listeners {
		if err := listener.Close(); err != nil {
			s.logger.Error("Failed to close listener", "error", err, "index", i)
		}
	}
	s.listeners = nil
}

// GetTLSMetrics returns current TLS metrics
func (s *TLSServer) GetTLSMetrics() *TLSMetrics {
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()

	// Create a copy to avoid race conditions
	metrics := &TLSMetrics{
		ConnectionsTotal:        s.metrics.ConnectionsTotal,
		ConnectionsActive:       s.metrics.ConnectionsActive,
		HandshakeErrors:         s.metrics.HandshakeErrors,
		CertificateErrors:       s.metrics.CertificateErrors,
		HandshakeDuration:       s.metrics.HandshakeDuration,
		TLSVersionDistribution:  make(map[string]int64),
		CipherSuiteDistribution: make(map[string]int64),
	}

	// Copy maps
	for k, v := range s.metrics.TLSVersionDistribution {
		metrics.TLSVersionDistribution[k] = v
	}
	for k, v := range s.metrics.CipherSuiteDistribution {
		metrics.CipherSuiteDistribution[k] = v
	}

	return metrics
}

// singleConnListener implements net.Listener for a single connection
type singleConnListener struct {
	conn   net.Conn
	once   sync.Once
	closed bool
	mu     sync.Mutex
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil, fmt.Errorf("listener closed")
	}

	var conn net.Conn
	l.once.Do(func() {
		conn = l.conn
	})

	if conn != nil {
		return conn, nil
	}

	return nil, fmt.Errorf("listener closed")
}

func (l *singleConnListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.closed = true
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// tlsResponseWriter implements http.ResponseWriter for writing responses over TLS connections
type tlsResponseWriter struct {
	conn            net.Conn
	header          http.Header
	statusCode      int
	written         bool
	securityHeaders *SecurityHeadersMiddleware
	logger          *slog.Logger
}

func (w *tlsResponseWriter) Header() http.Header {
	return w.header
}

func (w *tlsResponseWriter) Write(data []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.conn.Write(data)
}

func (w *tlsResponseWriter) WriteHeader(statusCode int) {
	if w.written {
		return
	}

	w.statusCode = statusCode
	w.written = true

	// Add security headers
	if w.securityHeaders != nil {
		w.securityHeaders.AddSecurityHeaders(w)
	}

	// Write HTTP response line
	statusText := http.StatusText(statusCode)
	if statusText == "" {
		statusText = "Unknown"
	}

	// Use strings.Builder for efficient string concatenation
	var response strings.Builder
	response.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, statusText))

	// Set default headers if not present
	if w.header.Get("Content-Length") == "" && w.header.Get("Transfer-Encoding") == "" {
		w.header.Set("Content-Length", "0")
	}
	if w.header.Get("Connection") == "" {
		w.header.Set("Connection", "close")
	}

	// Write headers efficiently
	for key, values := range w.header {
		for _, value := range values {
			response.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
		}
	}

	// End headers
	response.WriteString("\r\n")

	// Write to connection
	if _, err := w.conn.Write([]byte(response.String())); err != nil {
		w.logger.Error("Failed to write HTTP response headers", "error", err)
	}
}

// addTLSContextToRequest adds TLS context information to the HTTP request
func (s *TLSServer) addTLSContextToRequest(r *http.Request, tlsCtx *domain.TLSContext) *http.Request {
	// Add TLS information as headers for pipeline processing
	if tlsCtx.Version != "" {
		r.Header.Set("X-TLS-Version", tlsCtx.Version)
	}
	if tlsCtx.CipherSuite != "" {
		r.Header.Set("X-TLS-Cipher-Suite", tlsCtx.CipherSuite)
	}
	if tlsCtx.ServerName != "" {
		r.Header.Set("X-TLS-Server-Name", tlsCtx.ServerName)
	}
	if tlsCtx.ClientAuth {
		r.Header.Set("X-TLS-Client-Auth", "true")
	}

	return r
}

// GetCertificateStatuses returns the current status of all certificates
func (s *TLSServer) GetCertificateStatuses(ctx context.Context) ([]*CertificateStatus, error) {
	return s.certMonitor.GetCertificateStatuses(ctx)
}

// GetCertificateStatus returns the status of a specific certificate
func (s *TLSServer) GetCertificateStatus(ctx context.Context, serverName string) (*CertificateStatus, error) {
	return s.certMonitor.GetCertificateStatus(ctx, serverName)
}

// ForceCheckCertificates forces an immediate check of all certificates
func (s *TLSServer) ForceCheckCertificates(ctx context.Context) {
	s.certMonitor.ForceCheck(ctx)
}

// GetMetricsCollector returns the TLS metrics collector
func (s *TLSServer) GetMetricsCollector() *TLSMetricsCollector {
	return s.metricsCollector
}

// SetCertificateMonitorInterval sets the certificate monitoring check interval
func (s *TLSServer) SetCertificateMonitorInterval(interval time.Duration) {
	s.certMonitor.SetCheckInterval(interval)
}

// SetCertificateWarningDays sets the days before expiry to issue warnings
func (s *TLSServer) SetCertificateWarningDays(days []int) {
	s.certMonitor.SetWarningDays(days)
}

// GetConnectionPool returns the connection pool for upstream connections
func (s *TLSServer) GetConnectionPool() *ConnectionPool {
	return s.connectionPool
}

// GetSecurityHeaders returns the security headers middleware
func (s *TLSServer) GetSecurityHeaders() *SecurityHeadersMiddleware {
	return s.securityHeaders
}

// UpdateSecurityHeaders updates the security headers configuration
func (s *TLSServer) UpdateSecurityHeaders(headers map[string]string) {
	s.securityHeaders = NewSecurityHeadersMiddleware(headers)
	s.logger.Info("Updated security headers configuration")
}
