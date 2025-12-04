package integration

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/polisai/polis-oss/pkg/domain"
	pipelinepkg "github.com/polisai/polis-oss/pkg/engine"
	"github.com/polisai/polis-oss/pkg/policy"
	"github.com/polisai/polis-oss/pkg/storage"
)

// TestPolicyEngineBasic verifies that a policy engine can be initialized and used in a minimal pipeline.
func TestPolicyEngineBasic(t *testing.T) {
	ctx := context.Background()

	store := storage.NewMemoryPolicyStore()

	// Load standard bundle into store
	loadBundleIntoStore(t, store, "standard-policies", 1, "tests/fixtures/policy/bundles/standard", "policy.rego")

	// Create engine factory
	factory := pipelinepkg.NewEngineFactory(store, nil)

	// Create a minimal pipeline with just a policy node
	testPipeline := domain.Pipeline{
		ID:       "test-policy-only",
		Version:  1,
		AgentID:  "test-agent",
		Protocol: "http",
		Nodes: []domain.PipelineNode{
			{
				ID:   "policy",
				Type: "policy.opa",
				Config: map[string]interface{}{
					"bundleRef":     "standard-policies",
					"bundleVersion": 1,
					"entrypoint":    "policy/decision",
				},
				On: domain.NodeHandlers{
					Success: "", // Terminal node
					Failure: "deny",
				},
			},
			{
				ID:   "deny",
				Type: "terminal.deny",
			},
		},
	}

	// Initialize engines for the pipeline
	engineCtx, err := factory.InitializeEnginesForPipeline(ctx, &testPipeline)
	if err != nil {
		t.Fatalf("Failed to initialize engines: %v", err)
	}

	// Verify engine was created
	if engineCtx == nil {
		t.Fatal("Engine context is nil")
	}

	engineAny, ok := engineCtx.GetPolicyEngine("policy")
	if !ok {
		t.Fatal("Policy engine not found for node 'policy'")
	}

	engine, ok := engineAny.(*policy.Engine)
	if !ok || engine == nil {
		t.Fatal("Policy engine has wrong type or is nil")
	}

	t.Log("✓ Policy engine initialized successfully")

	// Test evaluation with a simple request
	testInput := createTestPolicyInput("test-user", "GET", "/api/test")

	decision, err := engine.Evaluate(ctx, testInput)
	if err != nil {
		t.Fatalf("Policy evaluation failed: %v", err)
	}

	if string(decision.Action) != "allow" {
		t.Errorf("Expected action 'allow', got '%s'", decision.Action)
	}

	t.Logf("✓ Policy evaluation successful: action=%s, reason=%s", decision.Action, decision.Reason)

	// Test with blocked user
	blockedInput := createTestPolicyInput("blocked-user", "GET", "/api/test")
	decision, err = engine.Evaluate(ctx, blockedInput)
	if err != nil {
		t.Fatalf("Policy evaluation failed: %v", err)
	}

	if string(decision.Action) != "block" {
		t.Errorf("Expected action 'block' for blocked-user, got '%s'", decision.Action)
	}

	t.Logf("✓ Blocked user correctly denied: action=%s, reason=%s", decision.Action, decision.Reason)

	// Cleanup
	if err := engineCtx.Close(); err != nil {
		t.Errorf("Failed to close engine context: %v", err)
	}
}

func TestEngineFactoryMultiBundle(t *testing.T) {
	ctx := context.Background()

	store := storage.NewMemoryPolicyStore()

	// Load bundles
	loadBundleIntoStore(t, store, "access-policies", 1, "tests/fixtures/policy/bundles/access", "access.rego")
	loadBundleIntoStore(t, store, "cost-policies", 1, "tests/fixtures/policy/bundles/cost", "cost.rego")

	factory := pipelinepkg.NewEngineFactory(store, nil)

	testPipeline := domain.Pipeline{
		ID:       "multi-policy",
		Version:  1,
		AgentID:  "agent-multi",
		Protocol: "http",
		Nodes: []domain.PipelineNode{
			{
				ID:   "access_policy",
				Type: "policy.opa",
				Config: map[string]interface{}{
					"bundleRef":     "access-policies",
					"bundleVersion": 1,
					"entrypoint":    "policy/access/decision",
				},
				On: domain.NodeHandlers{Success: "cost_policy", Failure: "deny"},
			},
			{
				ID:   "cost_policy",
				Type: "policy.opa",
				Config: map[string]interface{}{
					"bundleRef":     "cost-policies",
					"bundleVersion": 1,
					"entrypoint":    "policy/cost/decision",
				},
				On: domain.NodeHandlers{Success: "allow", Failure: "deny"},
			},
			{ID: "allow", Type: "terminal.allow"},
			{ID: "deny", Type: "terminal.deny"},
		},
	}

	engineCtx, err := factory.InitializeEnginesForPipeline(ctx, &testPipeline)
	if err != nil {
		t.Fatalf("failed to initialize multi-bundle engines: %v", err)
	}
	t.Cleanup(func() { _ = engineCtx.Close() })

	if len(engineCtx.PolicyEngines) != 2 {
		t.Fatalf("expected 2 policy engines, got %d", len(engineCtx.PolicyEngines))
	}

	accessEngine := mustPolicyEngine(t, engineCtx, "access_policy")
	allowDecision, err := accessEngine.Evaluate(ctx, policy.Input{
		RouteID: testPipeline.AgentID,
		Identity: domain.PolicyIdentity{
			Subject:  "agent@example.com",
			Audience: []string{"api://primary"},
			Scopes:   []string{"support-leads"},
		},
		Attributes: map[string]any{
			"http.method": "GET",
			"http.path":   "/tickets",
			"protocol":    "http",
		},
		Findings:   make(map[string]any),
		Entrypoint: "policy/access/decision",
	})
	if err != nil {
		t.Fatalf("access policy evaluation failed: %v", err)
	}
	if allowDecision.Action != policy.ActionAllow {
		t.Fatalf("expected access policy to allow, got %s", allowDecision.Action)
	}

	costEngine := mustPolicyEngine(t, engineCtx, "cost_policy")
	denyDecision, err := costEngine.Evaluate(ctx, policy.Input{
		RouteID:  testPipeline.AgentID,
		Identity: domain.PolicyIdentity{},
		Attributes: map[string]any{
			"http.method":                "POST",
			"http.path":                  "/budget",
			"protocol":                   "http",
			"session.tokens_in":          1000,
			"session.tokens_out":         250000,
			"session.estimated_cost_usd": 12.5,
		},
		Findings:   make(map[string]any),
		Entrypoint: "policy/cost/decision",
	})
	if err != nil {
		t.Fatalf("cost policy evaluation failed: %v", err)
	}
	if denyDecision.Action != policy.ActionBlock {
		t.Fatalf("expected cost policy to block, got %s", denyDecision.Action)
	}
	if reason := denyDecision.Metadata["cost.reason"]; reason != "budget_tokens_out_exceeded" {
		t.Fatalf("unexpected cost metadata reason: %v", reason)
	}
}

// createTestPolicyInput creates a test policy input.
func createTestPolicyInput(subject, method, path string) policy.Input {
	return policy.Input{
		RouteID: "test-agent",
		Identity: domain.PolicyIdentity{
			Subject: subject,
		},
		Attributes: map[string]any{
			"http.method": method,
			"http.path":   path,
			"protocol":    "http",
		},
		Findings:   make(map[string]any),
		Entrypoint: "policy/decision",
	}
}

func mustPolicyEngine(t testing.TB, ctx *domain.PipelineEngineContext, nodeID string) *policy.Engine {
	t.Helper()
	engineAny, ok := ctx.GetPolicyEngine(nodeID)
	if !ok {
		t.Fatalf("policy engine not found for node %s", nodeID)
	}
	engine, ok := engineAny.(*policy.Engine)
	if !ok || engine == nil {
		t.Fatalf("policy engine for node %s has unexpected type", nodeID)
	}
	return engine
}

func loadBundleIntoStore(t *testing.T, store *storage.MemoryPolicyStore, id string, version int, bundleDir, moduleName string) {
	t.Helper()
	regoPath := filepath.Join(repoRootPath(t), bundleDir, moduleName)
	//nolint:gosec // Test file path
	regoBytes, err := os.ReadFile(regoPath)
	if err != nil {
		t.Fatalf("failed to read rego fixture: %v", err)
	}

	bundle := &domain.PolicyBundle{
		ID:      id,
		Version: version,
		Artifacts: map[string]domain.PolicyArtifact{
			moduleName: {
				Type: "rego",
				Data: regoBytes,
			},
		},
	}
	if err := store.SavePolicyBundle(context.Background(), bundle); err != nil {
		t.Fatalf("failed to save bundle to store: %v", err)
	}
}

func repoRootPath(t testing.TB) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("failed to determine caller path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
}
