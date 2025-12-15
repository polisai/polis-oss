package tls

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"
)

func TestTLSMetricsCollector(t *testing.T) {
	logger := slog.Default()
	collector, err := GetTLSMetricsCollector(logger)
	if err != nil {
		t.Fatalf("Failed to create TLS metrics collector: %v", err)
	}

	ctx := context.Background()

	// Test connection metrics
	collector.RecordConnectionStart(ctx, "example.com")
	collector.RecordConnectionEnd(ctx, "example.com", time.Second)

	// Test handshake metrics
	collector.RecordHandshakeSuccess(ctx, "1.3", "TLS_AES_256_GCM_SHA384", "example.com", 100*time.Millisecond, false)
	collector.RecordHandshakeError(ctx, "example.com", "timeout", "handshake timeout")

	// Test certificate metrics
	collector.RecordCertificateValidation(ctx, "example.com", true, "expiry_check")
	collector.RecordCertificateExpiry(ctx, "example.com", "CN=example.com", time.Now().Add(30*24*time.Hour))
	collector.RecordCertificateReload(ctx, "example.com", true, "")

	// Test SNI metrics
	collector.RecordSNIRequest(ctx, "example.com", true)
	collector.RecordSNIRequest(ctx, "unknown.com", false)

	// Test certificate error
	collector.RecordCertificateError(ctx, "example.com", "expired", "certificate has expired")

	t.Log("All metrics recorded successfully")
}

func TestCertificateMonitor(t *testing.T) {
	logger := slog.Default()

	// Create a mock certificate manager
	certManager := NewFileCertificateManager(logger)

	// Create metrics collector
	metricsCollector, err := GetTLSMetricsCollector(logger)
	if err != nil {
		t.Fatalf("Failed to create TLS metrics collector: %v", err)
	}

	// Create certificate monitor
	monitor := NewCertificateMonitor(certManager, metricsCollector, logger)

	// Set a short check interval for testing
	monitor.SetCheckInterval(100 * time.Millisecond)
	monitor.SetWarningDays([]int{30, 7, 1})

	ctx := context.Background()

	// Start monitoring
	err = monitor.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start certificate monitor: %v", err)
	}

	// Let it run for a short time
	time.Sleep(200 * time.Millisecond)

	// Stop monitoring
	err = monitor.Stop()
	if err != nil {
		t.Fatalf("Failed to stop certificate monitor: %v", err)
	}

	t.Log("Certificate monitor test completed successfully")
}

func TestTLSLogger(t *testing.T) {
	logger := slog.Default()
	tlsLogger := NewTLSLogger(logger)

	ctx := context.Background()

	// Test various logging methods
	tlsLogger.LogConnectionStart(ctx, "192.168.1.1:12345", "example.com")
	tlsLogger.LogConnectionEnd(ctx, "192.168.1.1:12345", "example.com", time.Second, 1024, 2048)

	tlsLogger.LogHandshakeFailure(ctx, "192.168.1.1:12345", "example.com", "timeout",
		fmt.Errorf("handshake timeout"), 5*time.Second)

	tlsLogger.LogCertificateLoad(ctx, "example.com", "/path/to/cert.pem", "/path/to/key.pem", true, nil)
	tlsLogger.LogCertificateLoad(ctx, "example.com", "/path/to/cert.pem", "/path/to/key.pem", false,
		fmt.Errorf("file not found"))

	tlsLogger.LogCertificateExpiry(ctx, "example.com", "CN=example.com",
		time.Now().Add(7*24*time.Hour), 7, "WARNING")

	tlsLogger.LogSNIRequest(ctx, "example.com", true, "example.com")
	tlsLogger.LogSNIRequest(ctx, "unknown.com", false, "default")

	tlsLogger.LogConfigurationChange(ctx, "certificate_reload", "Reloaded certificates", true, nil)

	tlsLogger.LogSecurityEvent(ctx, "weak_cipher", "Client attempted to use weak cipher",
		"192.168.1.1:12345", "example.com", "medium")

	metrics := map[string]interface{}{
		"connections_total":           100,
		"handshake_avg_duration_ms":   150.5,
		"certificate_expiry_warnings": 2,
	}
	tlsLogger.LogPerformanceMetrics(ctx, metrics)

	t.Log("TLS logger test completed successfully")
}
