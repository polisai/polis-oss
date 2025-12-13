package integration

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// ScenarioTestConfig defines the parameters for a scenario test
type ScenarioTestConfig struct {
	Name           string
	ConfigPath     string
	Description    string
	Setup          func(t *testing.T, mockUpstreamURL string) (string, func()) // returns modified config path, cleanup func
	Request        func(t *testing.T, client *http.Client, polisURL string)
	VerifyUpstream func(t *testing.T, reqs []ReceivedRequest)
	VerifyLogs     func(t *testing.T, stdout, stderr string)
}

type ReceivedRequest struct {
	Method string
	Path   string
	Body   string
	Header http.Header
}

func TestScenarios(t *testing.T) {
	// Build the binary first to ensure we are testing latest code
	// Path is relative to test/integration directory
	buildCmd := exec.Command("go", "build", "-o", "polis-test.exe", "../../cmd/polis-core")
	buildCmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build polis binary: %v\nOutput: %s", err, out)
	}
	defer os.Remove("polis-test.exe")

	wd, _ := os.Getwd()
	polisPath := filepath.Join(wd, "polis-test.exe")

	tests := []ScenarioTestConfig{
		{
			Name:        "Scenario 1: Basic Passthrough",
			ConfigPath:  "docs/user_simulation/scenarios/01_basic_passthrough/README.md",
			Description: "Simple GET request should pass through",
			Setup: func(t *testing.T, mockUpstreamURL string) (string, func()) {
				cfg := map[string]interface{}{
					"server": map[string]interface{}{
						"listenParams": []map[string]interface{}{
							{"address": ":8091", "protocol": "http"},
						},
					},
					"pipelines": []map[string]interface{}{
						{
							"id":       "basic-passthrough",
							"agentId":  "*",
							"protocol": "http",
							"nodes": []map[string]interface{}{
								{
									"id":   "start",
									"type": "egress",
									"config": map[string]interface{}{
										"upstream_url":  mockUpstreamURL,
										"upstream_mode": "static",
									},
									"on": map[string]string{"success": ""},
								},
							},
						},
					},
				}
				return writeTempConfig(t, cfg)
			},
			Request: func(t *testing.T, client *http.Client, polisURL string) {
				resp, err := client.Get(polisURL + "/v1/chat/completions")
				if err != nil {
					t.Fatalf("Failed to send request: %v", err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != 200 {
					t.Errorf("Expected status 200, got %d", resp.StatusCode)
				}
			},
			VerifyUpstream: func(t *testing.T, reqs []ReceivedRequest) {
				if len(reqs) == 0 {
					t.Error("Upstream received no requests")
					return
				}
				if reqs[0].Path != "/v1/chat/completions" {
					t.Errorf("Upstream expected path /v1/chat/completions, got %s", reqs[0].Path)
				}
			},
		},
		{
			Name:        "Scenario 3: PII Protection",
			ConfigPath:  "",
			Description: "Email should be redacted",
			Setup: func(t *testing.T, mockUpstreamURL string) (string, func()) {
				// Create DLP rules file
				rulesContent := `
rules:
  - name: "Redact Emails"
    pattern: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    action: redact
    replacement: "[EMAIL_REDACTED]"
`
				rulesFile := filepath.Join(os.TempDir(), "dlp_rules_test.yaml")
				os.WriteFile(rulesFile, []byte(rulesContent), 0644)

				cfg := map[string]interface{}{
					"server": map[string]interface{}{
						"listenParams": []map[string]interface{}{
							{"address": ":8092", "protocol": "http"},
						},
					},
					"pipelines": []map[string]interface{}{
						{
							"id":       "pii-protection",
							"agentId":  "*",
							"protocol": "http",
							"nodes": []map[string]interface{}{
								{
									"id":   "start",
									"type": "dlp",
									"config": map[string]interface{}{
										"rules_file": rulesFile,
										"scope":      "request",
									},
									"on": map[string]string{"success": "egress", "failure": "deny"},
								},
								{
									"id":   "egress",
									"type": "egress",
									"config": map[string]interface{}{
										"upstream_url":  mockUpstreamURL,
										"upstream_mode": "static",
									},
									"on": map[string]string{"success": ""},
								},
								{
									"id":   "deny",
									"type": "terminal.deny",
								},
							},
						},
					},
				}
				configPath, cleanupConfig := writeTempConfig(t, cfg)
				return configPath, func() {
					cleanupConfig()
					os.Remove(rulesFile)
				}
			},
			Request: func(t *testing.T, client *http.Client, polisURL string) {
				body := `{"email": "test@example.com"}`
				req, _ := http.NewRequest("POST", polisURL+"/test", strings.NewReader(body))
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("Failed to send request: %v", err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != 200 {
					t.Errorf("Expected 200, got %d", resp.StatusCode)
				}
			},
			VerifyUpstream: func(t *testing.T, reqs []ReceivedRequest) {
				if len(reqs) == 0 {
					t.Fatal("No requests received upstream")
				}
				if !strings.Contains(reqs[0].Body, "[EMAIL_REDACTED]") {
					t.Errorf("Expected body to contain redaction, got: %s", reqs[0].Body)
				}
			},
		},
		{
			Name:        "Scenario 4: LLM Judge Guardrails",
			ConfigPath:  "",
			Description: "Unsafe content should be blocked",
			Setup: func(t *testing.T, mockUpstreamURL string) (string, func()) {
				promptsDir := filepath.Join(os.TempDir(), "prompts")
				// Create dummy prompts
				os.MkdirAll(filepath.Join(promptsDir, "tasks"), 0755)
				os.MkdirAll(filepath.Join(promptsDir, "rules"), 0755)
				os.WriteFile(filepath.Join(promptsDir, "tasks", "safety_check.txt"), []byte("Is this content safe? {{.Input}}"), 0644)
				os.WriteFile(filepath.Join(promptsDir, "rules", "strict_safety.txt"), []byte("Block if contains 'UNSAFE'"), 0644)

				cfg := map[string]interface{}{
					"server": map[string]interface{}{
						"listenParams": []map[string]interface{}{
							{"address": ":8093", "protocol": "http"},
						},
					},
					"pipelines": []map[string]interface{}{
						{
							"id":       "llm-judge",
							"agentId":  "*",
							"protocol": "http",
							"nodes": []map[string]interface{}{
								{
									"id":   "start",
									"type": "llm_judge",
									"config": map[string]interface{}{
										"taskId":  "safety_check",
										"rulesId": "strict_safety",
										"target":  "request.body",
										"mode":    "strict",
										"apiBase": mockUpstreamURL + "/llm", // Point to mock LLM
									},
									"on": map[string]string{"success": "egress", "failure": "deny"},
								},
								{
									"id":   "egress",
									"type": "egress",
									"config": map[string]interface{}{
										"upstream_url":  mockUpstreamURL,
										"upstream_mode": "static",
									},
									"on": map[string]string{"success": ""},
								},
								{
									"id":   "deny",
									"type": "terminal.deny",
								},
							},
						},
					},
				}
				configPath, cleanupConfig := writeTempConfig(t, cfg)

				// Workaround: Create "prompts" in test/integration (where we run) and clean up.
				wd, _ := os.Getwd()
				localPrompts := filepath.Join(wd, "prompts")

				os.RemoveAll(localPrompts) // Force clean start
				if _, err := os.Stat(localPrompts); os.IsNotExist(err) {
					os.MkdirAll(filepath.Join(localPrompts, "tasks"), 0755)
					os.MkdirAll(filepath.Join(localPrompts, "rules"), 0755)
					os.WriteFile(filepath.Join(localPrompts, "tasks", "safety_check.txt"), []byte("Is this content safe? {{.Input}}"), 0644)
					os.WriteFile(filepath.Join(localPrompts, "rules", "strict_safety.txt"), []byte("Block if contains 'UNSAFE'"), 0644)
				}

				return configPath, func() {
					cleanupConfig()
					os.RemoveAll(filepath.Join(wd, "prompts"))
					os.RemoveAll(promptsDir)
				}
			},
			Request: func(t *testing.T, client *http.Client, polisURL string) {
				// UNSAFE REQUEST
				body := `{"message": "I am UNSAFE content"}`
				req, _ := http.NewRequest("POST", polisURL+"/v1/chat/completions", strings.NewReader(body))
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("Failed to send request: %v", err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != 403 {
					t.Errorf("Expected 403 Forbidden for unsafe content, got %d", resp.StatusCode)
				}
			},
			VerifyUpstream: func(t *testing.T, reqs []ReceivedRequest) {
				llmCalls := 0
				appCalls := 0
				for _, r := range reqs {
					if strings.HasPrefix(r.Path, "/llm") {
						llmCalls++
					} else {
						appCalls++
					}
				}

				if llmCalls == 0 {
					t.Error("LLM Judge did not call the mock LLM API")
				}
				if appCalls > 0 {
					t.Error("Unsafe request was forwarded to upstream application despite block")
				}
			},
		},
		{
			Name:        "Scenario 2: OPA Policy",
			ConfigPath:  "",
			Description: "Policy should block request based on header",
			Setup: func(t *testing.T, mockUpstreamURL string) (string, func()) {
				// Create Rego policy
				regoPolicy := `
package policy.decision

import rego.v1

default action := "allow"
default reason := "allowed by default"

action := "block" if {
	input.attributes["http.headers"]["X-Block-Me"][0] == "true"
}

reason := "blocked by policy" if {
	action == "block"
}
`
				// Create temporary directory for artifacts
				tempDir, err := os.MkdirTemp("", "polis-artifacts-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}

				regoFile := filepath.Join(tempDir, "policy.rego")
				if err := os.WriteFile(regoFile, []byte(regoPolicy), 0644); err != nil {
					t.Fatalf("Failed to write rego file: %v", err)
				}

				cfg := map[string]interface{}{
					"server": map[string]interface{}{
						"listenParams": []map[string]interface{}{
							{"address": ":8094", "protocol": "http"},
						},
					},
					"policyBundles": []map[string]interface{}{
						{
							"id":      "test-bundle",
							"name":    "Test Bundle",
							"version": 1,
							"path":    tempDir,
							"artifacts": []map[string]interface{}{
								{
									"name": "main",
									"type": "rego",
									"path": "policy.rego",
								},
							},
						},
					},
					"pipelines": []map[string]interface{}{
						{
							"id":       "policy-check",
							"agentId":  "*",
							"protocol": "http",
							"nodes": []map[string]interface{}{
								{
									"id":   "start",
									"type": "policy",
									"config": map[string]interface{}{
										"bundleRef":     "test-bundle",
										"bundleVersion": 1,
									},
									"on": map[string]string{
										"success": "egress",
										"failure": "deny", // OPA "block" action maps to "failure" outcome in runtime? No, OPA returns 'deny' outcome usually.
										// Let's check policy.go:
										// case policy.ActionBlock: return runtime.NodeResult{Outcome: runtime.OutcomeDeny}, nil
										// So we need to handle "deny"
									},
								},
								{
									"id":   "egress",
									"type": "egress",
									"config": map[string]interface{}{
										"upstream_url":  mockUpstreamURL,
										"upstream_mode": "static",
									},
									"on": map[string]string{"success": ""},
								},
								{
									"id":   "deny",
									"type": "terminal.deny",
								},
							},
							"edges": []map[string]interface{}{
								{"from": "start", "to": "deny", "if": "outcome == 'deny'"},
							},
						},
					},
				}
				configPath, cleanupConfig := writeTempConfig(t, cfg)
				return configPath, func() {
					cleanupConfig()
					os.RemoveAll(tempDir)
				}
			},
			Request: func(t *testing.T, client *http.Client, polisURL string) {
				// Allowed Request
				req1, _ := http.NewRequest("GET", polisURL+"/test", nil)
				resp1, err := client.Do(req1)
				if err != nil {
					t.Fatalf("Failed to send allowed request: %v", err)
				}
				defer resp1.Body.Close()
				if resp1.StatusCode != 200 {
					t.Errorf("Expected 200 for allowed request, got %d", resp1.StatusCode)
				}

				// Blocked Request
				req2, _ := http.NewRequest("GET", polisURL+"/test", nil)
				req2.Header.Set("X-Block-Me", "true")
				resp2, err := client.Do(req2)
				if err != nil {
					t.Fatalf("Failed to send blocked request: %v", err)
				}
				defer resp2.Body.Close()
				if resp2.StatusCode != 403 { // standard deny status
					t.Errorf("Expected 403 for blocked request, got %d", resp2.StatusCode)
				}
			},
			VerifyUpstream: func(t *testing.T, reqs []ReceivedRequest) {
				// Should only have received the first request
				if len(reqs) != 1 {
					t.Errorf("Expected 1 upstream request, got %d", len(reqs))
				}
			},
		},
		{
			Name:        "Scenario 5: Observability",
			ConfigPath:  "docs/user_simulation/scenarios/05_observability/README.md",
			Description: "Check for structured logs",
			Setup: func(t *testing.T, mockUpstreamURL string) (string, func()) {
				cfg := map[string]interface{}{
					"server": map[string]interface{}{
						"listenParams": []map[string]interface{}{
							{"address": ":8095", "protocol": "http"},
						},
					},
					"pipelines": []map[string]interface{}{
						{
							"id":       "observability-test",
							"agentId":  "*",
							"protocol": "http",
							"nodes": []map[string]interface{}{
								{
									"id":   "start",
									"type": "egress",
									"config": map[string]interface{}{
										"upstream_url":  mockUpstreamURL,
										"upstream_mode": "static",
									},
									"on": map[string]string{"success": ""},
								},
							},
						},
					},
				}
				return writeTempConfig(t, cfg)
			},
			Request: func(t *testing.T, client *http.Client, polisURL string) {
				resp, err := client.Get(polisURL + "/obs-test")
				if err != nil {
					t.Fatalf("Failed to send request: %v", err)
				}
				defer resp.Body.Close()
			},
			VerifyUpstream: func(t *testing.T, reqs []ReceivedRequest) {
				if len(reqs) == 0 {
					t.Error("No requests received")
				}
			},
			VerifyLogs: func(t *testing.T, stdout, stderr string) {
				// Check for key log fields in JSON format
				if !strings.Contains(stdout, "\"level\":\"INFO\"") && !strings.Contains(stdout, "\"level\":\"info\"") {
					t.Error("Logs missing level field")
				}
				if !strings.Contains(stdout, "\"msg\":") && !strings.Contains(stdout, "\"message\":") {
					t.Error("Logs missing message field")
				}
				// Check for trace ID (part of standard middleware/logging)
				// trace_id might be auto-generated or missing if not propagated, but request logs usually have it.
				// Let's just check that it looks like JSON
				if !strings.HasPrefix(strings.TrimSpace(stdout), "{") {
					t.Log("Stdout does not start with '{', might not be JSON:")
					// It might have some initialization lines, so let's look for a JSON line
					lines := strings.Split(stdout, "\n")
					foundJSON := false
					for _, line := range lines {
						if strings.HasPrefix(strings.TrimSpace(line), "{") {
							foundJSON = true
							break
						}
					}
					if !foundJSON {
						t.Error("Did not find any JSON log lines in stdout")
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			// Start Mock Upstream
			var mu sync.Mutex
			receivedRequests := []ReceivedRequest{}
			mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				rBody := string(body)

				mu.Lock()
				receivedRequests = append(receivedRequests, ReceivedRequest{
					Method: r.Method,
					Path:   r.URL.Path,
					Body:   rBody,
					Header: r.Header,
				})
				mu.Unlock()

				// Mock LLM Response logic
				if strings.HasPrefix(r.URL.Path, "/llm") {
					w.Header().Set("Content-Type", "application/json")
					if strings.Contains(rBody, "UNSAFE") {
						w.Write([]byte(`{
							"choices": [{
								"message": { "content": "{\"decision\":\"UNSAFE\", \"explanation\":\"Content contains unsafe keyword\"}" }
							}]
						}`))
					} else {
						w.Write([]byte(`{
							"choices": [{
								"message": { "content": "{\"decision\":\"SAFE\", \"explanation\":\"Content is safe\"}" }
							}]
						}`))
					}
				} else {
					// Normal upstream
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"status":"mock_ok"}`))
				}
			}))
			defer mockUpstream.Close()

			// Setup Config
			configPath, cleanup := tt.Setup(t, mockUpstream.URL)
			defer cleanup()

			// Start Polis
			port, err := getPortFromConfig(configPath)
			if err != nil {
				t.Fatalf("Failed to parse config for port: %v", err)
			}

			cmd := exec.Command(polisPath, "--config", configPath, "--listen", ":"+port)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			if err := cmd.Start(); err != nil {
				t.Fatalf("Failed to start polis: %v", err)
			}
			defer func() {
				if cmd.Process != nil {
					if runtime.GOOS == "windows" {
						cmd.Process.Kill()
					} else {
						cmd.Process.Signal(os.Interrupt)
					}
				}
			}()

			waitForServer(t, "http://localhost:"+port+"/healthz", &stdout, &stderr)

			client := &http.Client{Timeout: 5 * time.Second}
			tt.Request(t, client, "http://localhost:"+port)

			tt.VerifyUpstream(t, receivedRequests)

			if tt.VerifyLogs != nil {
				tt.VerifyLogs(t, stdout.String(), stderr.String())
			}

			if t.Failed() {
				t.Logf("Polis Stdout:\n%s", stdout.String())
				t.Logf("Polis Stderr:\n%s", stderr.String())
			}
		})
	}
}

func getPortFromConfig(configPath string) (string, error) {
	var cfgMap map[string]interface{}
	f, err := os.Open(configPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := yaml.NewDecoder(f).Decode(&cfgMap); err != nil {
		return "", err
	}

	server, _ := cfgMap["server"].(map[string]interface{})
	listenParams, _ := server["listenParams"].([]interface{})
	if len(listenParams) > 0 {
		param, _ := listenParams[0].(map[string]interface{})
		addr, _ := param["address"].(string)
		parts := strings.Split(addr, ":")
		if len(parts) == 2 {
			return parts[1], nil
		}
	}
	return "8090", nil
}

func writeTempConfig(t *testing.T, cfg map[string]interface{}) (string, func()) {
	f, err := os.CreateTemp("", "polis_config_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp config: %v", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	f.Close()
	return f.Name(), func() { os.Remove(f.Name()) }
}

func waitForServer(t *testing.T, url string, stdout, stderr *bytes.Buffer) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode == 200 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("Server failed to start at %s\nStdout:\n%s\nStderr:\n%s", url, stdout.String(), stderr.String())
}
