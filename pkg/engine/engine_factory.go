package engine

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/policy"
	"github.com/polisai/polis-oss/pkg/storage"
)

const maxIntValue = int(^uint(0) >> 1)

// EngineFactory creates and initializes engines for pipeline nodes.
//
//nolint:revive // EngineFactory is intentionally prefixed for clarity
type EngineFactory struct {
	policyStore storage.PolicyStore
	logger      *slog.Logger
}

// NewEngineFactory creates a new engine factory.
func NewEngineFactory(policyStore storage.PolicyStore, logger *slog.Logger) *EngineFactory {
	if logger == nil {
		logger = slog.Default()
	}
	return &EngineFactory{
		policyStore: policyStore,
		logger:      logger,
	}
}

// Close shuts down all bundle servers and cleans up resources.
func (f *EngineFactory) Close() error {
	return nil
}

// InitializeEnginesForPipeline scans pipeline nodes and creates required engines.
func (f *EngineFactory) InitializeEnginesForPipeline(ctx context.Context, pipeline *domain.Pipeline) (*domain.PipelineEngineContext, error) {
	f.logger.Info("InitializeEnginesForPipeline started", "pipeline_id", pipeline.ID)
	engineCtx := &domain.PipelineEngineContext{
		PolicyEngines: make(map[string]any),
	}

	for _, node := range pipeline.Nodes {
		switch node.Type {
		case "policy.opa", "policy":
			f.logger.Info("Initializing policy engine", "node_id", node.ID)
			engine, err := f.initPolicyEngine(ctx, &node)
			if err != nil {
				return nil, fmt.Errorf("failed to init policy engine for node %s: %w", node.ID, err)
			}
			engineCtx.PolicyEngines[node.ID] = engine
			f.logger.Info("initialized policy engine", "pipeline_id", pipeline.ID, "node_id", node.ID)
		}
	}

	f.logger.Info("InitializeEnginesForPipeline finished", "pipeline_id", pipeline.ID)
	return engineCtx, nil
}

// initPolicyEngine creates a policy engine with the bundle specified in node config.
func (f *EngineFactory) initPolicyEngine(ctx context.Context, node *domain.PipelineNode) (*policy.Engine, error) {
	// Extract bundle reference from node config, supporting legacy "bundle" key for active development.
	bundleRef, ok := node.Config["bundleRef"].(string)
	if !ok || strings.TrimSpace(bundleRef) == "" {
		if legacy, legacyOK := node.Config["bundle"].(string); legacyOK && strings.TrimSpace(legacy) != "" {
			bundleRef = strings.TrimSpace(legacy)
			if _, exists := node.Config["bundleRef"]; !exists {
				node.Config["bundleRef"] = bundleRef
			}
			delete(node.Config, "bundle")
			f.logger.Warn("policy node config uses legacy bundle field; prefer bundleRef",
				"node_id", node.ID,
				"bundle_ref", bundleRef,
			)
		}
	}

	bundleRef = strings.TrimSpace(bundleRef)
	if bundleRef == "" {
		return nil, fmt.Errorf("policy node %s missing bundleRef in config", node.ID)
	}

	bundleVersion := 1
	if rawVersion, ok := node.Config["bundleVersion"]; ok {
		if parsed, valid := toPositiveInt(rawVersion); valid {
			bundleVersion = parsed
		}
	}

	// Load the policy bundle from store
	bundle, err := f.policyStore.GetPolicyBundle(ctx, bundleRef, bundleVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to load policy bundle %s@%d: %w", bundleRef, bundleVersion, err)
	}

	// Extract Rego artifacts from bundle
	regoModules := make(map[string]string)
	for name, artifact := range bundle.Artifacts {
		artifactType := strings.ToLower(strings.TrimSpace(artifact.Type))
		if artifactType == "" {
			continue
		}
		if artifactType == "rego" || artifactType == "opa.rego" {
			regoModules[name] = string(artifact.Data)
		}
	}

	if len(regoModules) == 0 {
		return nil, fmt.Errorf("policy bundle %s@%d contains no rego artifacts", bundleRef, bundleVersion)
	}

	// Get entrypoint from node config or use default
	entrypoint := "policy/decision"
	if ep, ok := node.Config["entrypoint"].(string); ok && ep != "" {
		entrypoint = ep
	}

	engine, err := policy.NewEngine(ctx, policy.EngineOptions{
		Entrypoint:      entrypoint,
		Modules:         regoModules,
		CacheMaxEntries: 1024,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create policy engine: %w", err)
	}

	f.logger.Info("initialized policy engine",
		"bundle_ref", bundleRef,
		"node_id", node.ID,
		"entrypoint", entrypoint,
		"modules_count", len(regoModules),
	)

	return engine, nil
}

//nolint:gocyclo // Type-switch branches enumerate supported numeric types for safety checks.
func toPositiveInt(value any) (int, bool) {
	switch v := value.(type) {
	case int:
		if v > 0 {
			return v, true
		}
	case int8:
		if v > 0 {
			return int(v), true
		}
	case int16:
		if v > 0 {
			return int(v), true
		}
	case int32:
		if v > 0 {
			return int(v), true
		}
	case int64:
		if v > 0 && v <= int64(maxIntValue) {
			return int(v), true
		}
	case uint:
		if v > 0 && v <= uint(maxIntValue) {
			return int(v), true
		}
	case uint8:
		if v > 0 {
			return int(v), true
		}
	case uint16:
		if v > 0 {
			return int(v), true
		}
	case uint32:
		if v > 0 && uint64(v) <= uint64(maxIntValue) {
			return int(v), true
		}
	case uint64:
		if v > 0 && v <= uint64(maxIntValue) {
			return int(v), true
		}
	case float32:
		if v > 0 && float64(v) <= float64(maxIntValue) {
			return int(v), true
		}
	case float64:
		if v > 0 && v <= float64(maxIntValue) {
			return int(v), true
		}
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return 0, false
		}
		if parsed, err := strconv.ParseInt(trimmed, 10, 64); err == nil && parsed > 0 && parsed <= int64(maxIntValue) {
			return int(parsed), true
		}
	}
	return 0, false
}
