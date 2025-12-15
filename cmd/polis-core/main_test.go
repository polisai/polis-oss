package main

import (
	"net/http"
	"testing"

	"github.com/polisai/polis-oss/pkg/config"
	"github.com/polisai/polis-oss/pkg/logging"
)

func TestDetermineListenerAddresses(t *testing.T) {
	logger := logging.NewLogger(logging.Config{Level: "info"})

	tests := []struct {
		name          string
		serverConfig  config.ServerConfig
		legacyAddr    string
		expectedHTTP  []string
		expectedHTTPS []string
	}{
		{
			name: "legacy configuration",
			serverConfig: config.ServerConfig{
				AdminAddress: ":19090",
				DataAddress:  ":8090",
			},
			legacyAddr:    ":8090",
			expectedHTTP:  []string{":8090"},
			expectedHTTPS: []string{},
		},
		{
			name: "multi-listener HTTP only",
			serverConfig: config.ServerConfig{
				AdminAddress: ":19090",
				DataAddress:  ":8090",
				ListenParams: []config.ListenParamConfig{
					{Address: ":8080", Protocol: "http"},
					{Address: ":8081", Protocol: "http"},
				},
			},
			legacyAddr:    ":8090",
			expectedHTTP:  []string{":8080", ":8081"},
			expectedHTTPS: []string{},
		},
		{
			name: "multi-listener mixed HTTP/HTTPS",
			serverConfig: config.ServerConfig{
				AdminAddress: ":19090",
				DataAddress:  ":8090",
				ListenParams: []config.ListenParamConfig{
					{Address: ":8080", Protocol: "http"},
					{
						Address:  ":8443",
						Protocol: "https",
						TLS: &config.TLSConfig{
							Enabled:  true,
							CertFile: "/path/to/cert.pem",
							KeyFile:  "/path/to/key.pem",
						},
					},
				},
			},
			legacyAddr:    ":8090",
			expectedHTTP:  []string{":8080"},
			expectedHTTPS: []string{":8443"},
		},
		{
			name: "HTTPS only",
			serverConfig: config.ServerConfig{
				AdminAddress: ":19090",
				DataAddress:  ":8090",
				ListenParams: []config.ListenParamConfig{
					{
						Address:  ":8443",
						Protocol: "https",
						TLS: &config.TLSConfig{
							Enabled:  true,
							CertFile: "/path/to/cert.pem",
							KeyFile:  "/path/to/key.pem",
						},
					},
					{
						Address:  ":9443",
						Protocol: "https",
						TLS: &config.TLSConfig{
							Enabled:  true,
							CertFile: "/path/to/cert2.pem",
							KeyFile:  "/path/to/key2.pem",
						},
					},
				},
			},
			legacyAddr:    ":8090",
			expectedHTTP:  []string{},
			expectedHTTPS: []string{":8443", ":9443"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpAddrs, httpsAddrs := determineListenerAddresses(tt.serverConfig, tt.legacyAddr, logger)

			// Check HTTP addresses
			if len(httpAddrs) != len(tt.expectedHTTP) {
				t.Errorf("Expected %d HTTP addresses, got %d", len(tt.expectedHTTP), len(httpAddrs))
			}
			for i, expected := range tt.expectedHTTP {
				if i >= len(httpAddrs) || httpAddrs[i] != expected {
					t.Errorf("Expected HTTP address %d to be %q, got %q", i, expected, httpAddrs[i])
				}
			}

			// Check HTTPS addresses
			if len(httpsAddrs) != len(tt.expectedHTTPS) {
				t.Errorf("Expected %d HTTPS addresses, got %d", len(tt.expectedHTTPS), len(httpsAddrs))
			}
			for i, expected := range tt.expectedHTTPS {
				if i >= len(httpsAddrs) || httpsAddrs[i] != expected {
					t.Errorf("Expected HTTPS address %d to be %q, got %q", i, expected, httpsAddrs[i])
				}
			}
		})
	}
}

func TestShutdownHTTPServers(t *testing.T) {
	logger := logging.NewLogger(logging.Config{Level: "info"})

	// Test that shutdownHTTPServers doesn't panic with empty slice
	shutdownHTTPServers(nil, logger)
	shutdownHTTPServers([]*http.Server{}, logger)

	// This test mainly ensures the function doesn't panic
	// More comprehensive testing would require setting up actual servers
}
