package tls

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	metricsOnce    sync.Once
	metricsInitErr error
	tlsMetricsInst *TLSMetricsCollector
)

// TLSMetricsCollector handles TLS-specific metrics collection
type TLSMetricsCollector struct {
	// Connection metrics
	connectionsTotal  metric.Int64Counter
	connectionsActive metric.Int64UpDownCounter
	handshakeErrors   metric.Int64Counter
	certificateErrors metric.Int64Counter

	// Performance metrics
	handshakeDuration  metric.Float64Histogram
	connectionDuration metric.Float64Histogram

	// Distribution metrics
	tlsVersionDistribution  metric.Int64Counter
	cipherSuiteDistribution metric.Int64Counter

	// Certificate metrics
	certificateExpiry     metric.Float64Gauge
	certificateReloads    metric.Int64Counter
	certificateValidation metric.Int64Counter

	// SNI metrics
	sniRequests metric.Int64Counter
	sniMisses   metric.Int64Counter

	logger *slog.Logger
}

// GetTLSMetricsCollector returns the singleton TLS metrics collector
func GetTLSMetricsCollector(logger *slog.Logger) (*TLSMetricsCollector, error) {
	metricsOnce.Do(func() {
		tlsMetricsInst, metricsInitErr = newTLSMetricsCollector(logger)
	})
	return tlsMetricsInst, metricsInitErr
}

// newTLSMetricsCollector creates a new TLS metrics collector
func newTLSMetricsCollector(logger *slog.Logger) (*TLSMetricsCollector, error) {
	if logger == nil {
		logger = slog.Default()
	}

	meter := otel.GetMeterProvider().Meter("proxy.tls")

	collector := &TLSMetricsCollector{
		logger: logger,
	}

	var err error

	// Connection metrics
	collector.connectionsTotal, err = meter.Int64Counter(
		"tls_connections_total",
		metric.WithDescription("Total number of TLS connections established"),
		metric.WithUnit("{connection}"),
	)
	if err != nil {
		return nil, err
	}

	collector.connectionsActive, err = meter.Int64UpDownCounter(
		"tls_connections_active",
		metric.WithDescription("Number of currently active TLS connections"),
		metric.WithUnit("{connection}"),
	)
	if err != nil {
		return nil, err
	}

	collector.handshakeErrors, err = meter.Int64Counter(
		"tls_handshake_errors_total",
		metric.WithDescription("Total number of TLS handshake errors"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, err
	}

	collector.certificateErrors, err = meter.Int64Counter(
		"tls_certificate_errors_total",
		metric.WithDescription("Total number of certificate-related errors"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, err
	}

	// Performance metrics
	collector.handshakeDuration, err = meter.Float64Histogram(
		"tls_handshake_duration_seconds",
		metric.WithDescription("TLS handshake duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	collector.connectionDuration, err = meter.Float64Histogram(
		"tls_connection_duration_seconds",
		metric.WithDescription("TLS connection duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	// Distribution metrics
	collector.tlsVersionDistribution, err = meter.Int64Counter(
		"tls_version_total",
		metric.WithDescription("TLS connections by version"),
		metric.WithUnit("{connection}"),
	)
	if err != nil {
		return nil, err
	}

	collector.cipherSuiteDistribution, err = meter.Int64Counter(
		"tls_cipher_suite_total",
		metric.WithDescription("TLS connections by cipher suite"),
		metric.WithUnit("{connection}"),
	)
	if err != nil {
		return nil, err
	}

	// Certificate metrics
	collector.certificateExpiry, err = meter.Float64Gauge(
		"tls_certificate_expiry_timestamp",
		metric.WithDescription("Certificate expiry timestamp in Unix seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	collector.certificateReloads, err = meter.Int64Counter(
		"tls_certificate_reloads_total",
		metric.WithDescription("Total number of certificate reloads"),
		metric.WithUnit("{reload}"),
	)
	if err != nil {
		return nil, err
	}

	collector.certificateValidation, err = meter.Int64Counter(
		"tls_certificate_validation_total",
		metric.WithDescription("Total number of certificate validations"),
		metric.WithUnit("{validation}"),
	)
	if err != nil {
		return nil, err
	}

	// SNI metrics
	collector.sniRequests, err = meter.Int64Counter(
		"tls_sni_requests_total",
		metric.WithDescription("Total number of SNI requests"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, err
	}

	collector.sniMisses, err = meter.Int64Counter(
		"tls_sni_misses_total",
		metric.WithDescription("Total number of SNI certificate misses"),
		metric.WithUnit("{miss}"),
	)
	if err != nil {
		return nil, err
	}

	return collector, nil
}

// RecordConnectionStart records the start of a TLS connection
func (c *TLSMetricsCollector) RecordConnectionStart(ctx context.Context, serverName string) {
	attrs := []attribute.KeyValue{
		attribute.String("server_name", serverName),
	}

	c.connectionsTotal.Add(ctx, 1, metric.WithAttributes(attrs...))
	c.connectionsActive.Add(ctx, 1, metric.WithAttributes(attrs...))

	c.logger.Debug("TLS connection started", "server_name", serverName)
}

// RecordConnectionEnd records the end of a TLS connection
func (c *TLSMetricsCollector) RecordConnectionEnd(ctx context.Context, serverName string, duration time.Duration) {
	attrs := []attribute.KeyValue{
		attribute.String("server_name", serverName),
	}

	c.connectionsActive.Add(ctx, -1, metric.WithAttributes(attrs...))

	if duration > 0 {
		c.connectionDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(attrs...))
	}

	c.logger.Debug("TLS connection ended",
		"server_name", serverName,
		"duration", duration)
}

// RecordHandshakeSuccess records a successful TLS handshake
func (c *TLSMetricsCollector) RecordHandshakeSuccess(ctx context.Context, version, cipherSuite, serverName string, duration time.Duration, clientAuth bool) {
	attrs := []attribute.KeyValue{
		attribute.String("tls_version", version),
		attribute.String("cipher_suite", cipherSuite),
		attribute.String("server_name", serverName),
		attribute.Bool("client_auth", clientAuth),
	}

	// Record handshake duration
	c.handshakeDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(attrs...))

	// Record version distribution
	c.tlsVersionDistribution.Add(ctx, 1, metric.WithAttributes(
		attribute.String("tls_version", version),
	))

	// Record cipher suite distribution
	c.cipherSuiteDistribution.Add(ctx, 1, metric.WithAttributes(
		attribute.String("cipher_suite", cipherSuite),
	))

	c.logger.Info("TLS handshake completed successfully",
		"tls_version", version,
		"cipher_suite", cipherSuite,
		"server_name", serverName,
		"client_auth", clientAuth,
		"handshake_duration", duration)
}

// RecordHandshakeError records a TLS handshake error
func (c *TLSMetricsCollector) RecordHandshakeError(ctx context.Context, serverName, errorType, errorMsg string) {
	attrs := []attribute.KeyValue{
		attribute.String("server_name", serverName),
		attribute.String("error_type", errorType),
	}

	c.handshakeErrors.Add(ctx, 1, metric.WithAttributes(attrs...))
	c.connectionsActive.Add(ctx, -1, metric.WithAttributes(
		attribute.String("server_name", serverName),
	))

	c.logger.Error("TLS handshake failed",
		"server_name", serverName,
		"error_type", errorType,
		"error", errorMsg)
}

// RecordCertificateError records a certificate-related error
func (c *TLSMetricsCollector) RecordCertificateError(ctx context.Context, serverName, errorType, errorMsg string) {
	attrs := []attribute.KeyValue{
		attribute.String("server_name", serverName),
		attribute.String("error_type", errorType),
	}

	c.certificateErrors.Add(ctx, 1, metric.WithAttributes(attrs...))

	c.logger.Error("Certificate error",
		"server_name", serverName,
		"error_type", errorType,
		"error", errorMsg)
}

// RecordCertificateValidation records a certificate validation attempt
func (c *TLSMetricsCollector) RecordCertificateValidation(ctx context.Context, serverName string, success bool, validationType string) {
	attrs := []attribute.KeyValue{
		attribute.String("server_name", serverName),
		attribute.String("validation_type", validationType),
		attribute.Bool("success", success),
	}

	c.certificateValidation.Add(ctx, 1, metric.WithAttributes(attrs...))

	if success {
		c.logger.Debug("Certificate validation successful",
			"server_name", serverName,
			"validation_type", validationType)
	} else {
		c.logger.Warn("Certificate validation failed",
			"server_name", serverName,
			"validation_type", validationType)
	}
}

// RecordCertificateExpiry records certificate expiry information
func (c *TLSMetricsCollector) RecordCertificateExpiry(ctx context.Context, serverName, subject string, expiryTime time.Time) {
	attrs := []attribute.KeyValue{
		attribute.String("server_name", serverName),
		attribute.String("subject", subject),
	}

	c.certificateExpiry.Record(ctx, float64(expiryTime.Unix()), metric.WithAttributes(attrs...))

	// Calculate days until expiry
	daysUntilExpiry := int(time.Until(expiryTime).Hours() / 24)

	if daysUntilExpiry <= 0 {
		c.logger.Error("Certificate has expired",
			"server_name", serverName,
			"subject", subject,
			"expired_on", expiryTime,
			"days_expired", -daysUntilExpiry)
	} else if daysUntilExpiry <= 7 {
		c.logger.Error("Certificate expires very soon",
			"server_name", serverName,
			"subject", subject,
			"expires_on", expiryTime,
			"days_remaining", daysUntilExpiry)
	} else if daysUntilExpiry <= 30 {
		c.logger.Warn("Certificate expires soon",
			"server_name", serverName,
			"subject", subject,
			"expires_on", expiryTime,
			"days_remaining", daysUntilExpiry)
	} else {
		c.logger.Debug("Certificate expiry recorded",
			"server_name", serverName,
			"subject", subject,
			"expires_on", expiryTime,
			"days_remaining", daysUntilExpiry)
	}
}

// RecordCertificateReload records a certificate reload event
func (c *TLSMetricsCollector) RecordCertificateReload(ctx context.Context, serverName string, success bool, errorMsg string) {
	attrs := []attribute.KeyValue{
		attribute.String("server_name", serverName),
		attribute.Bool("success", success),
	}

	c.certificateReloads.Add(ctx, 1, metric.WithAttributes(attrs...))

	if success {
		c.logger.Info("Certificate reloaded successfully",
			"server_name", serverName)
	} else {
		c.logger.Error("Certificate reload failed",
			"server_name", serverName,
			"error", errorMsg)
	}
}

// RecordSNIRequest records an SNI request
func (c *TLSMetricsCollector) RecordSNIRequest(ctx context.Context, serverName string, found bool) {
	attrs := []attribute.KeyValue{
		attribute.String("server_name", serverName),
		attribute.Bool("found", found),
	}

	c.sniRequests.Add(ctx, 1, metric.WithAttributes(attrs...))

	if !found {
		c.sniMisses.Add(ctx, 1, metric.WithAttributes(
			attribute.String("server_name", serverName),
		))

		c.logger.Warn("SNI certificate not found, using default",
			"server_name", serverName)
	} else {
		c.logger.Debug("SNI certificate found",
			"server_name", serverName)
	}
}

// LogTLSEvent logs a general TLS event with structured logging
func (c *TLSMetricsCollector) LogTLSEvent(level slog.Level, msg string, attrs ...slog.Attr) {
	c.logger.LogAttrs(context.Background(), level, msg, attrs...)
}

// LogCertificateStatus logs detailed certificate status information
func (c *TLSMetricsCollector) LogCertificateStatus(ctx context.Context, info *CertificateInfo) {
	if info == nil {
		return
	}

	daysUntilExpiry := int(time.Until(info.NotAfter).Hours() / 24)

	attrs := []slog.Attr{
		slog.String("server_name", info.ServerName),
		slog.String("subject", info.Subject),
		slog.String("issuer", info.Issuer),
		slog.Time("not_before", info.NotBefore),
		slog.Time("not_after", info.NotAfter),
		slog.Int("days_until_expiry", daysUntilExpiry),
		slog.Any("dns_names", info.DNSNames),
		slog.String("cert_file", info.CertFile),
		slog.String("key_file", info.KeyFile),
	}

	if daysUntilExpiry <= 0 {
		c.logger.LogAttrs(ctx, slog.LevelError, "Certificate status: EXPIRED", attrs...)
	} else if daysUntilExpiry <= 7 {
		c.logger.LogAttrs(ctx, slog.LevelError, "Certificate status: EXPIRES VERY SOON", attrs...)
	} else if daysUntilExpiry <= 30 {
		c.logger.LogAttrs(ctx, slog.LevelWarn, "Certificate status: EXPIRES SOON", attrs...)
	} else {
		c.logger.LogAttrs(ctx, slog.LevelInfo, "Certificate status: OK", attrs...)
	}
}
