package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type proxyOptions struct {
	BinaryPath    string
	BootstrapPath string
	UpstreamURL   string
	OIDCIssuer    string
	OIDCAudience  string
	ExtraEnv      map[string]string
}

type proxyInstance struct {
	dataAddr  string
	adminAddr string
	cancel    context.CancelFunc
	stdout    *bytes.Buffer
	stderr    *bytes.Buffer
	exitCh    chan error
	mu        sync.Mutex
	exitErr   error
	cmd       *exec.Cmd
	closeOnce sync.Once
}

func (p *proxyInstance) dataURL() string {
	return fmt.Sprintf("http://%s", p.dataAddr)
}

func (p *proxyInstance) adminURL() string {
	return fmt.Sprintf("http://%s", p.adminAddr)
}

func (p *proxyInstance) logs() string {
	return fmt.Sprintf("stdout:\n%s\nstderr:\n%s", p.stdout.String(), p.stderr.String())
}

func (p *proxyInstance) waitForReady(t *testing.T) {
	t.Helper()

	client := &http.Client{Timeout: 250 * time.Millisecond}
	deadline := time.Now().Add(60 * time.Second)
	healthURL := p.dataURL() + "/health"

	for time.Now().Before(deadline) {
		if err := p.pollExit(); err != nil {
			t.Fatalf("proxy exited before readiness: %v\n%s", err, p.logs())
		}

		resp, err := client.Get(healthURL)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				_ = resp.Body.Close()
				return
			}
			_ = resp.Body.Close()
		}

		time.Sleep(100 * time.Millisecond)
	}

	if err := p.pollExit(); err != nil {
		t.Fatalf("proxy failed during readiness: %v\n%s", err, p.logs())
	}

	t.Fatalf("proxy did not become ready within deadline\n%s", p.logs())
}

func (p *proxyInstance) pollExit() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.exitErr != nil {
		return p.exitErr
	}
	select {
	case err := <-p.exitCh:
		p.exitErr = err
		return err
	default:
		return nil
	}
}

func (p *proxyInstance) close(t *testing.T) {
	t.Helper()
	p.closeOnce.Do(func() {
		// On Windows, use taskkill to ensure the process tree is killed and handles are released.
		if runtime.GOOS == "windows" && p.cmd != nil && p.cmd.Process != nil {
			// #nosec G204 -- PID is from our own spawned process, not user input
			if out, err := exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprint(p.cmd.Process.Pid)).CombinedOutput(); err != nil {
				t.Logf("taskkill failed: %v, output: %s", err, string(out))
			}
		} else if p.cmd != nil && p.cmd.Process != nil {
			if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
				t.Logf("failed to send interrupt to proxy: %v", err)
			}
		}

		p.cancel()

		select {
		case err := <-p.exitCh:
			if err != nil {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					t.Logf("proxy shutdown error: %v\n%s", err, p.logs())
				}
			}
		case <-time.After(5 * time.Second):
			if p.exitErr == nil && p.pollExit() == nil {
				if err := p.forceKill(); err != nil {
					t.Logf("failed to force kill proxy: %v", err)
				}
			}
		}

		// Give the OS a moment to release file locks
		time.Sleep(1 * time.Second)
	})
}

func (p *proxyInstance) forceKill() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.pollExit(); err != nil {
		return err
	}
	if p.cmd != nil && p.cmd.Process != nil {
		if err := p.cmd.Process.Kill(); err != nil {
			return fmt.Errorf("process kill failed: %w", err)
		}
	}
	return fmt.Errorf("proxy did not exit after cancellation")
}

func startProxy(t *testing.T, opts proxyOptions) *proxyInstance {
	t.Helper()
	t.Logf("Starting proxy with UpstreamURL: %s", opts.UpstreamURL)

	// Use dynamic ports
	dataAddr := "127.0.0.1:0"

	ctx, cancel := context.WithCancel(context.Background())
	var configPath string
	if opts.BootstrapPath != "" {
		configPath = opts.BootstrapPath
	} else {
		configPath = createDummyConfig(t)
	}

	args := []string{
		"--config", configPath,
		"--listen", dataAddr,
		"--log-level", "debug",
	}

	//nolint:gosec // G204: Test harness needs to execute binary with dynamic arguments
	cmd := exec.CommandContext(ctx, opts.BinaryPath, args...)
	cmd.Env = append(os.Environ(),
		"OIDC_ISSUER="+opts.OIDCIssuer,
		"OIDC_AUDIENCE="+opts.OIDCAudience,
		"UPSTREAM_URL="+opts.UpstreamURL,
		"PROXY_LOG_LEVEL=debug",
	)
	for k, v := range opts.ExtraEnv {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}
	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("failed to start proxy: %v", err)
	}

	instance := &proxyInstance{
		cancel: cancel,
		stdout: stdoutBuf,
		stderr: stderrBuf,
		exitCh: make(chan error, 1),
		cmd:    cmd,
	}

	go func() {
		err := cmd.Wait()
		instance.exitCh <- err
	}()

	// Wait for ports to be logged
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if err := instance.pollExit(); err != nil {
			t.Fatalf("proxy exited before startup: %v\n%s", err, instance.logs())
		}

		logs := instance.logs()
		if instance.dataAddr == "" {
			if addr := parsePortFromLogs(logs, "Server listening\" addr="); addr != "" {
				instance.dataAddr = addr
			}
		}

		if instance.dataAddr != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if instance.dataAddr == "" {
		t.Fatalf("failed to parse ports from logs within deadline\n%s", instance.logs())
	}

	instance.waitForReady(t)

	t.Cleanup(func() {
		instance.close(t)
	})

	return instance
}

func parsePortFromLogs(logs, prefix string) string {
	for _, line := range strings.Split(logs, "\n") {
		// Look for the log message "Server listening"
		if strings.Contains(line, "Server listening") {
			// Try to parse as JSON
			var logEntry map[string]interface{}
			if err := json.Unmarshal([]byte(line), &logEntry); err == nil {
				if addr, ok := logEntry["addr"].(string); ok {
					return addr
				}
			}

			// Fallback: simple string parsing (if JSON parsing failed or strict mode/pretty somehow enabled)
			// This matches `addr=...` or `"addr":"..."`
			for _, field := range strings.Fields(line) {
				if strings.HasPrefix(field, "addr=") {
					return strings.TrimPrefix(field, "addr=")
				}
			}
		}
	}
	return ""
}

func buildProxyBinary(t *testing.T) string {
	t.Helper()

	root := findRepoRoot(t)
	outputDir := t.TempDir()

	binaryName := "polis"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(outputDir, binaryName)

	//nolint:gosec // G204: Test harness needs to execute go build command
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/polis-core")
	cmd.Dir = root
	cmd.Env = os.Environ()

	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build proxy: %v\n%s", err, string(output))
	}

	return binaryPath
}

func findRepoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod not found from %s", dir)
		}
		dir = parent
	}
}

func createDummyConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// Write minimal valid config
	content := []byte(`
server:
  admin_address: :19090
  data_address: :8090
logging:
  level: debug
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("failed to write dummy config: %v", err)
	}
	return path
}
