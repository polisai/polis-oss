package tls

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// CertificateMonitor monitors certificate expiration and health
type CertificateMonitor struct {
	certManager      CertificateManager
	metricsCollector *TLSMetricsCollector
	logger           *slog.Logger

	// Monitoring configuration
	checkInterval time.Duration
	warningDays   []int // Days before expiry to warn at (e.g., [30, 7, 1])

	// State
	mu           sync.RWMutex
	running      bool
	stopChan     chan struct{}
	wg           sync.WaitGroup
	lastWarnings map[string]time.Time // serverName -> last warning time
}

// CertificateStatus represents the status of a certificate
type CertificateStatus struct {
	ServerName      string
	Subject         string
	Issuer          string
	NotBefore       time.Time
	NotAfter        time.Time
	DaysUntilExpiry int
	Status          string // "OK", "WARNING", "CRITICAL", "EXPIRED"
	LastChecked     time.Time
}

// NewCertificateMonitor creates a new certificate monitor
func NewCertificateMonitor(certManager CertificateManager, metricsCollector *TLSMetricsCollector, logger *slog.Logger) *CertificateMonitor {
	if logger == nil {
		logger = slog.Default()
	}

	return &CertificateMonitor{
		certManager:      certManager,
		metricsCollector: metricsCollector,
		logger:           logger,
		checkInterval:    time.Hour,       // Check every hour by default
		warningDays:      []int{30, 7, 1}, // Warn at 30, 7, and 1 days
		stopChan:         make(chan struct{}),
		lastWarnings:     make(map[string]time.Time),
	}
}

// SetCheckInterval sets the interval for certificate checks
func (m *CertificateMonitor) SetCheckInterval(interval time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checkInterval = interval
}

// SetWarningDays sets the days before expiry to issue warnings
func (m *CertificateMonitor) SetWarningDays(days []int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.warningDays = make([]int, len(days))
	copy(m.warningDays, days)
}

// Start begins certificate monitoring
func (m *CertificateMonitor) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return nil
	}

	m.logger.Info("Starting certificate monitor",
		"check_interval", m.checkInterval,
		"warning_days", m.warningDays)

	m.running = true
	m.wg.Add(1)
	go m.monitorLoop(ctx)

	return nil
}

// Stop stops certificate monitoring
func (m *CertificateMonitor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	m.logger.Info("Stopping certificate monitor")

	close(m.stopChan)
	m.running = false

	// Wait for monitor loop to finish
	m.wg.Wait()

	m.logger.Info("Certificate monitor stopped")
	return nil
}

// monitorLoop runs the main monitoring loop
func (m *CertificateMonitor) monitorLoop(ctx context.Context) {
	defer m.wg.Done()

	// Perform initial check
	m.checkAllCertificates(ctx)

	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.checkAllCertificates(ctx)
		}
	}
}

// checkAllCertificates checks all managed certificates
func (m *CertificateMonitor) checkAllCertificates(ctx context.Context) {
	m.logger.Debug("Starting certificate health check")

	// Get certificate manager as FileCertificateManager to access certificate info
	fileCertManager, ok := m.certManager.(*FileCertificateManager)
	if !ok {
		m.logger.Error("Certificate manager is not a FileCertificateManager, cannot monitor certificates")
		return
	}

	// Get all server names from the certificate manager
	serverNames := m.getServerNames(fileCertManager)

	checkedCount := 0
	warningCount := 0
	criticalCount := 0
	expiredCount := 0

	for _, serverName := range serverNames {
		status := m.checkCertificate(ctx, fileCertManager, serverName)
		if status == nil {
			continue
		}

		checkedCount++

		switch status.Status {
		case "WARNING":
			warningCount++
		case "CRITICAL":
			criticalCount++
		case "EXPIRED":
			expiredCount++
		}

		// Record metrics
		if m.metricsCollector != nil {
			m.metricsCollector.RecordCertificateExpiry(ctx, status.ServerName, status.Subject, status.NotAfter)
		}
	}

	m.logger.Info("Certificate health check completed",
		"checked_count", checkedCount,
		"warning_count", warningCount,
		"critical_count", criticalCount,
		"expired_count", expiredCount)
}

// checkCertificate checks a single certificate
func (m *CertificateMonitor) checkCertificate(ctx context.Context, fileCertManager *FileCertificateManager, serverName string) *CertificateStatus {
	info, err := fileCertManager.GetCertificateInfo(serverName)
	if err != nil {
		m.logger.Error("Failed to get certificate info",
			"server_name", serverName,
			"error", err)
		return nil
	}

	now := time.Now()
	daysUntilExpiry := int(info.NotAfter.Sub(now).Hours() / 24)

	status := &CertificateStatus{
		ServerName:      info.ServerName,
		Subject:         info.Subject,
		Issuer:          info.Issuer,
		NotBefore:       info.NotBefore,
		NotAfter:        info.NotAfter,
		DaysUntilExpiry: daysUntilExpiry,
		LastChecked:     now,
	}

	// Determine status
	if daysUntilExpiry <= 0 {
		status.Status = "EXPIRED"
	} else if daysUntilExpiry <= 1 {
		status.Status = "CRITICAL"
	} else if daysUntilExpiry <= 7 {
		status.Status = "WARNING"
	} else {
		status.Status = "OK"
	}

	// Check if we should issue a warning
	m.checkAndIssueWarning(ctx, status)

	return status
}

// checkAndIssueWarning checks if a warning should be issued for a certificate
func (m *CertificateMonitor) checkAndIssueWarning(ctx context.Context, status *CertificateStatus) {
	if status.Status == "OK" {
		return
	}

	// Check if we should warn based on warning days configuration
	shouldWarn := false
	for _, warningDay := range m.warningDays {
		if status.DaysUntilExpiry <= warningDay {
			shouldWarn = true
			break
		}
	}

	if !shouldWarn {
		return
	}

	// Check if we've already warned recently (avoid spam)
	m.mu.RLock()
	lastWarning, exists := m.lastWarnings[status.ServerName]
	m.mu.RUnlock()

	// Only warn once per day for the same certificate
	if exists && time.Since(lastWarning) < 24*time.Hour {
		return
	}

	// Issue warning
	m.issueExpirationWarning(ctx, status)

	// Update last warning time
	m.mu.Lock()
	m.lastWarnings[status.ServerName] = time.Now()
	m.mu.Unlock()
}

// issueExpirationWarning issues a certificate expiration warning
func (m *CertificateMonitor) issueExpirationWarning(ctx context.Context, status *CertificateStatus) {
	attrs := []slog.Attr{
		slog.String("server_name", status.ServerName),
		slog.String("subject", status.Subject),
		slog.String("issuer", status.Issuer),
		slog.Time("expires_on", status.NotAfter),
		slog.Int("days_remaining", status.DaysUntilExpiry),
		slog.String("status", status.Status),
	}

	switch status.Status {
	case "EXPIRED":
		m.logger.LogAttrs(ctx, slog.LevelError,
			"CERTIFICATE EXPIRED - Immediate action required", attrs...)

		// Record certificate error metric
		if m.metricsCollector != nil {
			m.metricsCollector.RecordCertificateError(ctx, status.ServerName, "expired",
				"Certificate has expired")
		}

	case "CRITICAL":
		m.logger.LogAttrs(ctx, slog.LevelError,
			"CERTIFICATE EXPIRES VERY SOON - Urgent action required", attrs...)

	case "WARNING":
		m.logger.LogAttrs(ctx, slog.LevelWarn,
			"CERTIFICATE EXPIRES SOON - Action recommended", attrs...)
	}
}

// getServerNames extracts server names from the certificate manager
func (m *CertificateMonitor) getServerNames(fileCertManager *FileCertificateManager) []string {
	fileCertManager.mutex.RLock()
	defer fileCertManager.mutex.RUnlock()

	serverNames := make([]string, 0, len(fileCertManager.certificates))
	for serverName := range fileCertManager.certificates {
		serverNames = append(serverNames, serverName)
	}

	return serverNames
}

// GetCertificateStatuses returns the current status of all certificates
func (m *CertificateMonitor) GetCertificateStatuses(ctx context.Context) ([]*CertificateStatus, error) {
	fileCertManager, ok := m.certManager.(*FileCertificateManager)
	if !ok {
		return nil, ErrUnsupportedCertificateManager
	}

	serverNames := m.getServerNames(fileCertManager)
	statuses := make([]*CertificateStatus, 0, len(serverNames))

	for _, serverName := range serverNames {
		status := m.checkCertificate(ctx, fileCertManager, serverName)
		if status != nil {
			statuses = append(statuses, status)
		}
	}

	return statuses, nil
}

// GetCertificateStatus returns the status of a specific certificate
func (m *CertificateMonitor) GetCertificateStatus(ctx context.Context, serverName string) (*CertificateStatus, error) {
	fileCertManager, ok := m.certManager.(*FileCertificateManager)
	if !ok {
		return nil, ErrUnsupportedCertificateManager
	}

	return m.checkCertificate(ctx, fileCertManager, serverName), nil
}

// ForceCheck forces an immediate check of all certificates
func (m *CertificateMonitor) ForceCheck(ctx context.Context) {
	m.logger.Info("Forcing certificate health check")
	m.checkAllCertificates(ctx)
}

// Custom errors
var (
	ErrUnsupportedCertificateManager = fmt.Errorf("unsupported certificate manager type")
)
