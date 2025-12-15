package tls

import (
	"context"
	"crypto/x509"
	"log/slog"
	"time"

	"github.com/polisai/polis-oss/pkg/domain"
)

// TLSLogger provides structured logging for TLS events
type TLSLogger struct {
	logger *slog.Logger
}

// NewTLSLogger creates a new TLS logger
func NewTLSLogger(logger *slog.Logger) *TLSLogger {
	if logger == nil {
		logger = slog.Default()
	}

	return &TLSLogger{
		logger: logger.With("component", "tls"),
	}
}

// LogConnectionStart logs the start of a TLS connection
func (l *TLSLogger) LogConnectionStart(ctx context.Context, remoteAddr, serverName string) {
	l.logger.LogAttrs(ctx, slog.LevelInfo, "TLS connection started",
		slog.String("event", "connection_start"),
		slog.String("remote_addr", remoteAddr),
		slog.String("server_name", serverName),
		slog.Time("timestamp", time.Now()),
	)
}

// LogConnectionEnd logs the end of a TLS connection
func (l *TLSLogger) LogConnectionEnd(ctx context.Context, remoteAddr, serverName string, duration time.Duration, bytesRead, bytesWritten int64) {
	l.logger.LogAttrs(ctx, slog.LevelInfo, "TLS connection ended",
		slog.String("event", "connection_end"),
		slog.String("remote_addr", remoteAddr),
		slog.String("server_name", serverName),
		slog.Duration("duration", duration),
		slog.Int64("bytes_read", bytesRead),
		slog.Int64("bytes_written", bytesWritten),
		slog.Time("timestamp", time.Now()),
	)
}

// LogHandshakeSuccess logs a successful TLS handshake
func (l *TLSLogger) LogHandshakeSuccess(ctx context.Context, tlsCtx *domain.TLSContext, remoteAddr string) {
	attrs := []slog.Attr{
		slog.String("event", "handshake_success"),
		slog.String("remote_addr", remoteAddr),
		slog.String("tls_version", tlsCtx.Version),
		slog.String("cipher_suite", tlsCtx.CipherSuite),
		slog.String("server_name", tlsCtx.ServerName),
		slog.Duration("handshake_duration", tlsCtx.HandshakeDuration),
		slog.Bool("client_auth", tlsCtx.ClientAuth),
		slog.String("negotiated_protocol", tlsCtx.NegotiatedProtocol),
		slog.Time("timestamp", time.Now()),
	}

	if len(tlsCtx.PeerCertificates) > 0 {
		attrs = append(attrs, slog.Int("peer_cert_count", len(tlsCtx.PeerCertificates)))
		attrs = append(attrs, slog.Any("peer_certificates", tlsCtx.PeerCertificates))
	}

	l.logger.LogAttrs(ctx, slog.LevelInfo, "TLS handshake completed successfully", attrs...)
}

// LogHandshakeFailure logs a failed TLS handshake
func (l *TLSLogger) LogHandshakeFailure(ctx context.Context, remoteAddr, serverName, errorType string, err error, duration time.Duration) {
	level := slog.LevelError
	if errorType == "timeout" || errorType == "client_disconnect" {
		level = slog.LevelWarn
	}

	l.logger.LogAttrs(ctx, level, "TLS handshake failed",
		slog.String("event", "handshake_failure"),
		slog.String("remote_addr", remoteAddr),
		slog.String("server_name", serverName),
		slog.String("error_type", errorType),
		slog.String("error", err.Error()),
		slog.Duration("handshake_duration", duration),
		slog.Time("timestamp", time.Now()),
	)
}

// LogCertificateLoad logs certificate loading events
func (l *TLSLogger) LogCertificateLoad(ctx context.Context, serverName, certFile, keyFile string, success bool, err error) {
	level := slog.LevelInfo
	message := "Certificate loaded successfully"

	if !success {
		level = slog.LevelError
		message = "Certificate loading failed"
	}

	attrs := []slog.Attr{
		slog.String("event", "certificate_load"),
		slog.String("server_name", serverName),
		slog.String("cert_file", certFile),
		slog.String("key_file", keyFile),
		slog.Bool("success", success),
		slog.Time("timestamp", time.Now()),
	}

	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}

	l.logger.LogAttrs(ctx, level, message, attrs...)
}

// LogCertificateValidation logs certificate validation events
func (l *TLSLogger) LogCertificateValidation(ctx context.Context, serverName string, cert *x509.Certificate, success bool, validationType string, err error) {
	level := slog.LevelDebug
	message := "Certificate validation successful"

	if !success {
		level = slog.LevelError
		message = "Certificate validation failed"
	}

	attrs := []slog.Attr{
		slog.String("event", "certificate_validation"),
		slog.String("server_name", serverName),
		slog.String("validation_type", validationType),
		slog.Bool("success", success),
		slog.Time("timestamp", time.Now()),
	}

	if cert != nil {
		attrs = append(attrs,
			slog.String("subject", cert.Subject.String()),
			slog.String("issuer", cert.Issuer.String()),
			slog.Time("not_before", cert.NotBefore),
			slog.Time("not_after", cert.NotAfter),
			slog.Any("dns_names", cert.DNSNames),
		)
	}

	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}

	l.logger.LogAttrs(ctx, level, message, attrs...)
}

// LogCertificateReload logs certificate reload events
func (l *TLSLogger) LogCertificateReload(ctx context.Context, serverName string, success bool, reloadedCount, errorCount int, err error) {
	level := slog.LevelInfo
	message := "Certificate reload completed"

	if !success {
		level = slog.LevelError
		message = "Certificate reload failed"
	}

	attrs := []slog.Attr{
		slog.String("event", "certificate_reload"),
		slog.String("server_name", serverName),
		slog.Bool("success", success),
		slog.Int("reloaded_count", reloadedCount),
		slog.Int("error_count", errorCount),
		slog.Time("timestamp", time.Now()),
	}

	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}

	l.logger.LogAttrs(ctx, level, message, attrs...)
}

// LogCertificateExpiry logs certificate expiry warnings
func (l *TLSLogger) LogCertificateExpiry(ctx context.Context, serverName, subject string, expiryTime time.Time, daysRemaining int, status string) {
	var level slog.Level
	var message string

	switch status {
	case "EXPIRED":
		level = slog.LevelError
		message = "Certificate has expired - immediate action required"
	case "CRITICAL":
		level = slog.LevelError
		message = "Certificate expires very soon - urgent action required"
	case "WARNING":
		level = slog.LevelWarn
		message = "Certificate expires soon - action recommended"
	default:
		level = slog.LevelInfo
		message = "Certificate expiry status"
	}

	l.logger.LogAttrs(ctx, level, message,
		slog.String("event", "certificate_expiry"),
		slog.String("server_name", serverName),
		slog.String("subject", subject),
		slog.Time("expires_on", expiryTime),
		slog.Int("days_remaining", daysRemaining),
		slog.String("status", status),
		slog.Time("timestamp", time.Now()),
	)
}

// LogSNIRequest logs SNI certificate selection events
func (l *TLSLogger) LogSNIRequest(ctx context.Context, serverName string, found bool, selectedCert string) {
	level := slog.LevelDebug
	message := "SNI certificate selected"

	if !found {
		level = slog.LevelWarn
		message = "SNI certificate not found, using default"
	}

	l.logger.LogAttrs(ctx, level, message,
		slog.String("event", "sni_request"),
		slog.String("requested_server_name", serverName),
		slog.Bool("found", found),
		slog.String("selected_cert", selectedCert),
		slog.Time("timestamp", time.Now()),
	)
}

// LogConfigurationChange logs TLS configuration changes
func (l *TLSLogger) LogConfigurationChange(ctx context.Context, changeType, description string, success bool, err error) {
	level := slog.LevelInfo
	message := "TLS configuration changed"

	if !success {
		level = slog.LevelError
		message = "TLS configuration change failed"
	}

	attrs := []slog.Attr{
		slog.String("event", "configuration_change"),
		slog.String("change_type", changeType),
		slog.String("description", description),
		slog.Bool("success", success),
		slog.Time("timestamp", time.Now()),
	}

	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}

	l.logger.LogAttrs(ctx, level, message, attrs...)
}

// LogSecurityEvent logs TLS security-related events
func (l *TLSLogger) LogSecurityEvent(ctx context.Context, eventType, description, remoteAddr, serverName string, severity string) {
	var level slog.Level
	switch severity {
	case "critical":
		level = slog.LevelError
	case "high":
		level = slog.LevelError
	case "medium":
		level = slog.LevelWarn
	case "low":
		level = slog.LevelInfo
	default:
		level = slog.LevelInfo
	}

	l.logger.LogAttrs(ctx, level, "TLS security event",
		slog.String("event", "security_event"),
		slog.String("event_type", eventType),
		slog.String("description", description),
		slog.String("remote_addr", remoteAddr),
		slog.String("server_name", serverName),
		slog.String("severity", severity),
		slog.Time("timestamp", time.Now()),
	)
}

// LogPerformanceMetrics logs TLS performance metrics
func (l *TLSLogger) LogPerformanceMetrics(ctx context.Context, metrics map[string]interface{}) {
	attrs := []slog.Attr{
		slog.String("event", "performance_metrics"),
		slog.Time("timestamp", time.Now()),
	}

	for key, value := range metrics {
		attrs = append(attrs, slog.Any(key, value))
	}

	l.logger.LogAttrs(ctx, slog.LevelInfo, "TLS performance metrics", attrs...)
}
