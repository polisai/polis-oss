package e2e

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"
)

// TestProxyMechanisms verifies that the Polis proxy handles various modes correctly
// by running the actual binary and sending real network requests.
func TestProxyMechanisms(t *testing.T) {
	// 1. Build the binary once
	binaryPath := buildProxyBinary(t)
	defer os.Remove(binaryPath)

	// A mock upstream server (HTTP)
	httpUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Hit", "true")
		_, _ = w.Write([]byte("http-upstream-response"))
	}))
	defer httpUpstream.Close()

	// A mock upstream server (HTTPS) for CONNECT testing
	httpsUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Secure-Hit", "true")
		_, _ = w.Write([]byte("https-upstream-response"))
	}))
	defer httpsUpstream.Close()

	t.Run("HTTP Forward Proxy", func(t *testing.T) {
		// Start Polis in "proxy" mode
		proxy := startProxy(t, proxyOptions{
			BinaryPath:  binaryPath,
			UpstreamURL: "", // Dynamic proxy doesn't need upstream_url but currently config might require it?
			// Actually config.yaml used upstream_mode: "proxy".
			// We need to inject upstream_mode: "proxy" into config.
			// The harness creates a dummy config. We might need to supply a custom config or env var.
			ExtraEnv: map[string]string{
				// We can override config via env? Assuming config loading supports env or we rely on default behaviour.
				// Our config loading supports YAML.
				// Let's rely on creating a specific config file for this test phase if needed,
				// or assume "proxy" mode is default if we don't specify anything?
				// Actually, "upstream_mode" default is "static".
				// We need to set it.
				// Our config loader doesn't seem to support generic env overrides for all fields yet strictly.
				// But `startProxy` allows `BootstrapPath`.
			},
		})

		// Wait, startProxy creates a minimal dummy config. We need one with upstream_mode: "proxy".
		// Instead of modifying startProxy, let's create our own config file and pass it.
		configContent := `
server:
  admin_address: :0
  data_address: :0
upstream_mode: "proxy"
logging:
  level: debug
`
		configPath := t.TempDir() + "/proxy_config.yaml"
		if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
			t.Fatalf("failed to write config: %v", err)
		}

		// Restart proxy with this config
		// Actually startProxy takes BootstrapPath.
		proxy.close(t) // Close the one started by default if we reused variables, but here we construct a new one.

		p := startProxy(t, proxyOptions{
			BinaryPath:    binaryPath,
			BootstrapPath: configPath,
		})
		defer p.close(t)

		// Create a client that uses Polis as proxy
		proxyURL, _ := url.Parse(p.dataURL())
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
			Timeout: 5 * time.Second,
		}

		// Make request to httpUpstream through proxy
		resp, err := client.Get(httpUpstream.URL + "/forward-path")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if string(body) != "http-upstream-response" {
			t.Errorf("Unexpected body: %s", string(body))
		}
	})

	t.Run("HTTPS CONNECT Tunnel", func(t *testing.T) {
		// Reuse proxy mode config
		configContent := `
server:
  admin_address: :0
  data_address: :0
upstream_mode: "proxy"
logging:
  level: debug
`
		configPath := t.TempDir() + "/connect_config.yaml"
		_ = os.WriteFile(configPath, []byte(configContent), 0600)

		p := startProxy(t, proxyOptions{
			BinaryPath:    binaryPath,
			BootstrapPath: configPath,
		})
		defer p.close(t)

		proxyURL, _ := url.Parse(p.dataURL())

		// Client must trust the test CA
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // Test certs
				},
			},
			Timeout: 5 * time.Second,
		}

		// Make HTTPS request to httpsUpstream
		resp, err := client.Get(httpsUpstream.URL + "/secure-path")
		if err != nil {
			// This often fails if CONNECT logic is broken (e.g. 502, 301, Hijack err)
			t.Fatalf("HTTPS request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if string(body) != "https-upstream-response" {
			t.Errorf("Unexpected body: %s", string(body))
		}
	})

	t.Run("Reverse Proxy (Static)", func(t *testing.T) {
		// Config for static upstream
		configContent := fmt.Sprintf(`
server:
  admin_address: :0
  data_address: :0
upstream_mode: "static"
upstream_url: "%s"
logging:
  level: debug
`, httpUpstream.URL)

		configPath := t.TempDir() + "/static_config.yaml"
		_ = os.WriteFile(configPath, []byte(configContent), 0600)

		p := startProxy(t, proxyOptions{
			BinaryPath:    binaryPath,
			BootstrapPath: configPath,
		})
		defer p.close(t)

		// Client connects DIRECTLY to Polis (reverse proxy)
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(p.dataURL() + "/reverse-path")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if string(body) != "http-upstream-response" {
			t.Errorf("Unexpected body: %s", string(body))
		}
	})

	t.Run("Custom Header Proxy", func(t *testing.T) {
		// Config for custom header
		configContent := `
server:
  admin_address: :0
  data_address: :0
upstream_mode: "custom_header"
upstream_allowlist:
  - "*"
logging:
  level: debug
`
		configPath := t.TempDir() + "/header_config.yaml"
		_ = os.WriteFile(configPath, []byte(configContent), 0600)

		p := startProxy(t, proxyOptions{
			BinaryPath:    binaryPath,
			BootstrapPath: configPath,
		})
		defer p.close(t)

		client := &http.Client{Timeout: 5 * time.Second}

		// Create request pointing to Polis
		req, _ := http.NewRequest("GET", p.dataURL()+"/header-path", nil)
		// Set the header used by handlers.extractCustomHeaderTarget (defaults to X-Upstream-Url or config?)
		// Set the header used by handlers.extractCustomHeaderTarget
		// Implementation uses "X-Target-URL"
		req.Header.Set("X-Target-URL", httpUpstream.URL)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if string(body) != "http-upstream-response" {
			t.Errorf("Unexpected body: %s", string(body))
		}
	})
}
