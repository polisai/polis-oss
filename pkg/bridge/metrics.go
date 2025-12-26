package bridge

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for the bridge
type Metrics struct {
	// Message metrics
	messagesTotal  *prometheus.CounterVec
	messageLatency *prometheus.HistogramVec
	messageErrors  *prometheus.CounterVec

	// Session metrics
	sessionsActive  prometheus.Gauge
	sessionsTotal   *prometheus.CounterVec
	sessionDuration *prometheus.HistogramVec

	// Buffer metrics
	bufferSize      *prometheus.GaugeVec
	bufferEvictions *prometheus.CounterVec

	// Process metrics
	processStatus   *prometheus.GaugeVec
	processRestarts prometheus.Counter

	// Stream inspector metrics
	streamInspectorEvents *prometheus.CounterVec

	// Session reconnection metrics
	sessionReconnections *prometheus.CounterVec

	// Configuration reload metrics
	configReloads *prometheus.CounterVec

	// HTTP metrics
	httpRequestsTotal   *prometheus.CounterVec
	httpRequestDuration *prometheus.HistogramVec

	registry *prometheus.Registry
}

// NewMetrics creates a new metrics instance with all bridge metrics
func NewMetrics() *Metrics {
	registry := prometheus.NewRegistry()

	m := &Metrics{
		messagesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bridge_messages_total",
				Help: "Total number of messages processed by direction and status",
			},
			[]string{"direction", "status", "method"},
		),

		messageLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "bridge_message_duration_seconds",
				Help:    "Message processing latency in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"direction", "method"},
		),

		messageErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bridge_message_errors_total",
				Help: "Total number of message processing errors",
			},
			[]string{"direction", "error_type", "method"},
		),

		sessionsActive: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "bridge_sessions_active",
				Help: "Number of currently active sessions",
			},
		),

		sessionsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bridge_sessions_total",
				Help: "Total number of sessions created",
			},
			[]string{"agent_id"},
		),

		sessionDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "bridge_session_duration_seconds",
				Help:    "Session duration in seconds",
				Buckets: []float64{1, 5, 10, 30, 60, 300, 600, 1800, 3600},
			},
			[]string{"agent_id"},
		),

		bufferSize: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "bridge_buffer_size_bytes",
				Help: "Current size of session event buffers",
			},
			[]string{"session_id"},
		),

		bufferEvictions: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bridge_buffer_evictions_total",
				Help: "Total number of buffer evictions",
			},
			[]string{"session_id", "reason"},
		),

		processStatus: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "bridge_process_status",
				Help: "Status of child process (1=running, 0=stopped)",
			},
			[]string{"command"},
		),

		processRestarts: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "bridge_process_restarts_total",
				Help: "Total number of child process restarts",
			},
		),

		httpRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bridge_http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "endpoint", "status_code"},
		),

		httpRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "bridge_http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "endpoint"},
		),

		streamInspectorEvents: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bridge_stream_inspector_events_total",
				Help: "Total number of SSE events inspected by action and method",
			},
			[]string{"action", "method"},
		),

		sessionReconnections: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bridge_session_reconnections_total",
				Help: "Total number of session reconnection attempts by status",
			},
			[]string{"status"},
		),

		configReloads: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "bridge_config_reloads_total",
				Help: "Total number of configuration reload attempts by status",
			},
			[]string{"status"},
		),

		registry: registry,
	}

	// Register all metrics
	registry.MustRegister(
		m.messagesTotal,
		m.messageLatency,
		m.messageErrors,
		m.sessionsActive,
		m.sessionsTotal,
		m.sessionDuration,
		m.bufferSize,
		m.bufferEvictions,
		m.processStatus,
		m.processRestarts,
		m.httpRequestsTotal,
		m.httpRequestDuration,
		m.streamInspectorEvents,
		m.sessionReconnections,
		m.configReloads,
	)

	return m
}

// RecordMessage records metrics for a processed message
func (m *Metrics) RecordMessage(direction, method, status string, duration time.Duration) {
	m.messagesTotal.WithLabelValues(direction, status, method).Inc()
	m.messageLatency.WithLabelValues(direction, method).Observe(duration.Seconds())
}

// RecordMessageError records a message processing error
func (m *Metrics) RecordMessageError(direction, errorType, method string) {
	m.messageErrors.WithLabelValues(direction, errorType, method).Inc()
}

// RecordSessionCreated records a new session creation
func (m *Metrics) RecordSessionCreated(agentID string) {
	m.sessionsTotal.WithLabelValues(agentID).Inc()
	m.sessionsActive.Inc()
}

// RecordSessionClosed records a session closure
func (m *Metrics) RecordSessionClosed(agentID string, duration time.Duration) {
	m.sessionsActive.Dec()
	m.sessionDuration.WithLabelValues(agentID).Observe(duration.Seconds())
}

// UpdateBufferSize updates the buffer size metric for a session
func (m *Metrics) UpdateBufferSize(sessionID string, size int) {
	m.bufferSize.WithLabelValues(sessionID).Set(float64(size))
}

// RecordBufferEviction records a buffer eviction event
func (m *Metrics) RecordBufferEviction(sessionID, reason string) {
	m.bufferEvictions.WithLabelValues(sessionID, reason).Inc()
}

// UpdateProcessStatus updates the process status metric
func (m *Metrics) UpdateProcessStatus(command string, running bool) {
	status := 0.0
	if running {
		status = 1.0
	}
	m.processStatus.WithLabelValues(command).Set(status)
}

// RecordProcessRestart records a process restart
func (m *Metrics) RecordProcessRestart() {
	m.processRestarts.Inc()
}

// RecordHTTPRequest records an HTTP request
func (m *Metrics) RecordHTTPRequest(method, endpoint, statusCode string, duration time.Duration) {
	m.httpRequestsTotal.WithLabelValues(method, endpoint, statusCode).Inc()
	m.httpRequestDuration.WithLabelValues(method, endpoint).Observe(duration.Seconds())
}

// RecordStreamInspectorEvent records a stream inspector event
func (m *Metrics) RecordStreamInspectorEvent(action, method string) {
	m.streamInspectorEvents.WithLabelValues(action, method).Inc()
}

// RecordSessionReconnection records a session reconnection attempt
func (m *Metrics) RecordSessionReconnection(status string) {
	m.sessionReconnections.WithLabelValues(status).Inc()
}

// RecordConfigReload records a configuration reload attempt
func (m *Metrics) RecordConfigReload(status string) {
	m.configReloads.WithLabelValues(status).Inc()
}

// Handler returns the Prometheus metrics HTTP handler
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Registry returns the Prometheus registry
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// MetricsMiddleware creates HTTP middleware that records request metrics
func (m *Metrics) MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Call next handler
		next.ServeHTTP(wrapped, r)

		// Record metrics
		duration := time.Since(start)
		endpoint := getEndpointName(r.URL.Path)
		statusCode := strconv.Itoa(wrapped.statusCode)

		m.RecordHTTPRequest(r.Method, endpoint, statusCode, duration)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not support http.Hijacker")
}

func (rw *responseWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := rw.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}

// getEndpointName extracts a normalized endpoint name from the path
func getEndpointName(path string) string {
	switch path {
	case "/health":
		return "health"
	case "/sse":
		return "sse"
	case "/message":
		return "message"
	case "/metrics":
		return "metrics"
	default:
		return "unknown"
	}
}

// MessageTimer helps measure message processing duration
type MessageTimer struct {
	start     time.Time
	metrics   *Metrics
	direction string
	method    string
}

// NewMessageTimer creates a new message timer
func (m *Metrics) NewMessageTimer(direction, method string) *MessageTimer {
	return &MessageTimer{
		start:     time.Now(),
		metrics:   m,
		direction: direction,
		method:    method,
	}
}

// Success records a successful message processing
func (mt *MessageTimer) Success() {
	duration := time.Since(mt.start)
	mt.metrics.RecordMessage(mt.direction, mt.method, "success", duration)
}

// Error records a failed message processing
func (mt *MessageTimer) Error(errorType string) {
	duration := time.Since(mt.start)
	mt.metrics.RecordMessage(mt.direction, mt.method, "error", duration)
	mt.metrics.RecordMessageError(mt.direction, errorType, mt.method)
}
