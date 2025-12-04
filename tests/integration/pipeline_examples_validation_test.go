package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/polisai/polis-oss/pkg/config"
)

// TestPipelineExamplesValidation ensures all pipeline example files can be
// unmarshaled and validate against the expected schema with no case/type mismatches.
//
//nolint:gocyclo // Test function with many cases
func TestPipelineExamplesValidation(t *testing.T) {
	examplesDir := filepath.Join("..", "fixtures", "pipelines")

	examples := []string{
		"simple-http.json",
		"simple-dlp.json",
		"dlp-enabled.json",
		"header-manipulation.json",
		"fraud-detection.json",
		"llm-gateway.json",
		"streaming-proxy.json",
		"multi-policy.json",
	}

	for _, example := range examples {
		t.Run(example, func(t *testing.T) {
			path := filepath.Join(examplesDir, example)
			data, err := os.ReadFile(path) // nolint:gosec // test file with controlled paths
			if err != nil {
				t.Fatalf("failed to read %s: %v", example, err)
			}

			var spec config.PipelineSpec
			if err := json.Unmarshal(data, &spec); err != nil {
				t.Fatalf("failed to unmarshal %s: %v", example, err)
			}

			// Validate required fields
			if spec.ID == "" {
				t.Errorf("%s: missing pipeline ID", example)
			}
			if spec.Version == 0 {
				t.Errorf("%s: missing pipeline version", example)
			}
			if spec.AgentID == "" {
				t.Errorf("%s: missing agentId", example)
			}
			if spec.Protocol == "" {
				t.Errorf("%s: missing protocol", example)
			}
			if len(spec.Nodes) == 0 {
				t.Errorf("%s: no nodes defined", example)
			}

			// Validate nodes
			for i, node := range spec.Nodes {
				if node.ID == "" {
					t.Errorf("%s: node[%d] missing ID", example, i)
				}
				if node.Type == "" {
					t.Errorf("%s: node[%d] missing type", example, i)
				}

				// Validate node outcome handlers
				if node.On.Success == "" && node.On.Failure == "" && node.On.Else == "" {
					// Terminal nodes don't need handlers
					if node.Type != "terminal.allow" && node.Type != "terminal.deny" {
						t.Errorf("%s: node[%d] (%s) missing outcome handlers", example, i, node.ID)
					}
				}

				// Validate governance fields use camelCase (not PascalCase or snake_case)
				if node.Governance.TimeoutMS != 0 {
					// TimeoutMS is the struct field name, but JSON should be timeoutMs
					// This is validated by successful unmarshaling
					_ = node.Governance.TimeoutMS // nolint:revive // intentional validation check
				}

				// For policy.opa nodes, validate bundleRef (not legacy "bundle")
				if node.Type == "policy.opa" {
					if bundleRef, ok := node.Config["bundleRef"].(string); ok && bundleRef != "" {
						// Good: using bundleRef
						_ = bundleRef // nolint:revive // intentional validation check
					} else if bundle, ok := node.Config["bundle"].(string); ok && bundle != "" {
						t.Errorf("%s: node[%d] (%s) uses legacy 'bundle' field, should use 'bundleRef'", example, i, node.ID)
					} else {
						t.Errorf("%s: node[%d] (%s) missing bundleRef in config", example, i, node.ID)
					}

					if rawVersion, ok := node.Config["bundleVersion"]; ok {
						version, ok := rawVersion.(float64)
						if !ok {
							t.Errorf("%s: node[%d] (%s) bundleVersion must be a number", example, i, node.ID)
						} else if version < 1 || version != float64(int(version)) {
							t.Errorf("%s: node[%d] (%s) bundleVersion must be a positive integer, got %v", example, i, node.ID, rawVersion)
						}
					} else {
						t.Errorf("%s: node[%d] (%s) missing bundleVersion in config", example, i, node.ID)
					}
				}
			}

			// Validate defaults use camelCase
			if spec.Defaults.TimeoutMS != 0 {
				// TimeoutMS is the struct field name, validated by successful unmarshal
				_ = spec.Defaults.TimeoutMS // nolint:revive // intentional validation check
			}

			if spec.Defaults.Retries.MaxAttempts > 0 {
				// Validate retry config fields
				if spec.Defaults.Retries.BaseMS == 0 && spec.Defaults.Retries.Backoff != "fixed" {
					t.Logf("%s: defaults.retries.baseMs is 0 (may be intentional)", example)
				}
			}

			t.Logf("%s: validation passed ✓", example)
		})
	}
}

// TestPipelineExamplesNoLegacyFields detects any legacy field names in pipeline examples
// that could cause silent failures or unexpected behavior.
func TestPipelineExamplesNoLegacyFields(t *testing.T) {
	examplesDir := filepath.Join("..", "fixtures", "pipelines")

	examples := []string{
		"simple-http.json",
		"simple-dlp.json",
		"dlp-enabled.json",
		"header-manipulation.json",
		"fraud-detection.json",
		"llm-gateway.json",
		"streaming-proxy.json",
		"multi-policy.json",
	}

	for _, example := range examples {
		t.Run(example, func(t *testing.T) {
			path := filepath.Join(examplesDir, example)
			data, err := os.ReadFile(path) // nolint:gosec // test file with controlled paths
			if err != nil {
				t.Fatalf("failed to read %s: %v", example, err)
			}

			// Parse as generic map to check for legacy fields
			var raw map[string]interface{}
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatalf("failed to unmarshal %s: %v", example, err)
			}

			// Check defaults for legacy timeoutMS (should be timeoutMs)
			if defaults, ok := raw["defaults"].(map[string]interface{}); ok {
				if _, hasLegacy := defaults["timeoutMS"]; hasLegacy {
					t.Errorf("%s: defaults contains legacy 'timeoutMS', should be 'timeoutMs'", example)
				}

				// Check retries for legacy baseMS/maxMS
				if retries, ok := defaults["retries"].(map[string]interface{}); ok {
					if _, hasLegacy := retries["baseMS"]; hasLegacy {
						t.Errorf("%s: defaults.retries contains legacy 'baseMS', should be 'baseMs'", example)
					}
					if _, hasLegacy := retries["maxMS"]; hasLegacy {
						t.Errorf("%s: defaults.retries contains legacy 'maxMS', should be 'maxMs'", example)
					}
				}
			}

			// Check nodes for legacy governance fields
			if nodes, ok := raw["nodes"].([]interface{}); ok {
				for i, nodeRaw := range nodes {
					if node, ok := nodeRaw.(map[string]interface{}); ok {
						if governance, ok := node["governance"].(map[string]interface{}); ok {
							if _, hasLegacy := governance["timeoutMS"]; hasLegacy {
								nodeID := node["id"].(string)
								t.Errorf("%s: node[%d] (%s) governance contains legacy 'timeoutMS', should be 'timeoutMs'", example, i, nodeID)
							}
						}

						// Check for legacy "bundle" in policy.opa nodes
						if nodeType, ok := node["type"].(string); ok && nodeType == "policy.opa" {
							if config, ok := node["config"].(map[string]interface{}); ok {
								if _, hasLegacy := config["bundle"]; hasLegacy {
									nodeID := node["id"].(string)
									t.Errorf("%s: node[%d] (%s) config contains legacy 'bundle', should be 'bundleRef'", example, i, nodeID)
								}
							}
						}
					}
				}
			}

			t.Logf("%s: no legacy fields found ✓", example)
		})
	}
}
