package config

import (
	"fmt"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/policy"
)

// ToDomain converts the configuration snapshot to a domain snapshot.
// It loads referenced policy bundles.
func (s Snapshot) ToDomain() (domain.Snapshot, error) {
	domainSnapshot := domain.Snapshot{
		Generation: fmt.Sprintf("%d", s.Generation),
		Timestamp:  s.ReceivedAt,
		Governance: domain.GovernanceConfig{}, // TODO: Convert governance
	}

	if s.GovernanceConfig != nil {
		domainSnapshot.Governance = *s.GovernanceConfig
	}

	// Load bundles
	bundles := make(map[string]*domain.PolicyBundle)
	for _, desc := range s.PolicyBundles {
		// Populate domain.Snapshot PolicyBundles
		domainDesc := desc.ToDomain()
		domainSnapshot.PolicyBundles = append(domainSnapshot.PolicyBundles, domainDesc)

		// Helper logic for policies that is already present...
		bundle, err := LoadPolicyBundle(desc)
		if err != nil {
			return domain.Snapshot{}, fmt.Errorf("load bundle %s: %w", desc.ID, err)
		}
		key := fmt.Sprintf("%s@%d", desc.ID, desc.Version)
		bundles[key] = bundle
	}

	// Convert policies
	for _, spec := range s.RawPolicies {
		pol := domain.Policy{
			ID:         spec.ID,
			Name:       spec.Name,
			Generation: fmt.Sprintf("%d", spec.Version),
			FailOpen:   spec.FailurePosture.Mode(policy.DomainGlobal) == policy.ModeFailOpen,
		}

		if spec.BundleRef != "" {
			key := fmt.Sprintf("%s@%d", spec.BundleRef, spec.BundleVersion)
			bundle, ok := bundles[key]
			if !ok {
				return domain.Snapshot{}, fmt.Errorf("policy %s references unknown bundle %s", spec.ID, key)
			}
			// TODO: domain.Policy expects Bundle []byte (OPA bundle).
			// We need to find the OPA bundle artifact in the policy bundle.
			// PolicySpec.Artifacts.OPA.Bundle is the name of the artifact.
			artifactName := spec.Artifacts.OPA.Bundle
			if artifactName != "" {
				if artifact, ok := bundle.Artifacts[artifactName]; ok {
					pol.Bundle = artifact.Data
				} else {
					return domain.Snapshot{}, fmt.Errorf("policy %s references unknown artifact %s in bundle %s", spec.ID, artifactName, spec.BundleRef)
				}
			}
			pol.Entrypoint = spec.Artifacts.OPA.RequestEntrypoint
		}

		domainSnapshot.Policies = append(domainSnapshot.Policies, pol)
	}

	// Convert pipelines
	for _, pipeSpec := range s.Pipelines {
		domainSnapshot.Pipelines = append(domainSnapshot.Pipelines, pipeSpec.ToDomain())
	}

	return domainSnapshot, nil
}

// ToDomain converts PipelineSpec to domain.Pipeline
func (s PipelineSpec) ToDomain() domain.Pipeline {
	triggers := make([]domain.Trigger, len(s.Triggers))
	for i, t := range s.Triggers {
		triggers[i] = domain.Trigger{
			Type:  t.Type,
			Match: t.Match,
		}
	}

	nodes := make([]domain.PipelineNode, len(s.Nodes))
	for i, n := range s.Nodes {
		nodes[i] = n.ToDomain()
	}

	edges := make([]domain.PipelineEdge, len(s.Edges))
	for i, e := range s.Edges {
		edges[i] = domain.PipelineEdge{
			From: e.From,
			To:   e.To,
			If:   e.If,
		}
	}

	return domain.Pipeline{
		ID:        s.ID,
		Version:   s.Version,
		AgentID:   s.AgentID,
		Protocol:  s.Protocol,
		Triggers:  triggers,
		Variables: s.Variables,
		Defaults:  s.Defaults.ToDomain(),
		Nodes:     nodes,
		Edges:     edges,
	}
}

// ToDomain converts PipelineDefaultsSpec to domain.PipelineDefaults.
func (s PipelineDefaultsSpec) ToDomain() domain.PipelineDefaults {
	return domain.PipelineDefaults{
		TimeoutMS:          s.TimeoutMS,
		Retries:            s.Retries.ToDomain(),
		EnableConditionals: s.EnableConditionals,
	}
}

// ToDomain converts PipelineRetryConfigSpec to domain.PipelineRetryConfig.
func (s PipelineRetryConfigSpec) ToDomain() domain.PipelineRetryConfig {
	return domain.PipelineRetryConfig{
		MaxAttempts: s.MaxAttempts,
		Backoff:     s.Backoff,
		BaseMS:      s.BaseMS,
		MaxMS:       s.MaxMS,
	}
}

// ToDomain converts PipelineNodeSpec to domain.PipelineNode.
func (s PipelineNodeSpec) ToDomain() domain.PipelineNode {
	when := make([]domain.ConditionalBranch, len(s.When))
	for i, w := range s.When {
		when[i] = domain.ConditionalBranch{
			If:   w.If,
			Then: w.Then,
		}
	}

	return domain.PipelineNode{
		ID:         s.ID,
		Type:       s.Type,
		Config:     s.Config,
		When:       when,
		Posture:    s.Posture,
		Governance: s.Governance.ToDomain(),
		On:         s.On.ToDomain(),
	}
}

// ToDomain converts PipelineGovernanceConfigSpec to domain.PipelineGovernanceConfig.
func (s PipelineGovernanceConfigSpec) ToDomain() domain.PipelineGovernanceConfig {
	var retries *domain.PipelineRetryConfig
	if s.Retries != nil {
		r := s.Retries.ToDomain()
		retries = &r
	}

	var cb *domain.PipelineCircuitBreakerConfig
	if s.CircuitBreaker != nil {
		c := s.CircuitBreaker.ToDomain()
		cb = &c
	}

	return domain.PipelineGovernanceConfig{
		TimeoutMS:      s.TimeoutMS,
		Retries:        retries,
		CircuitBreaker: cb,
	}
}

// ToDomain converts PipelineCircuitBreakerConfigSpec to domain.PipelineCircuitBreakerConfig.
func (s PipelineCircuitBreakerConfigSpec) ToDomain() domain.PipelineCircuitBreakerConfig {
	return domain.PipelineCircuitBreakerConfig{
		Window:                s.Window,
		FailureRateThreshold:  s.FailureRateThreshold,
		SlowCallDurationMS:    s.SlowCallDurationMS,
		SlowCallRateThreshold: s.SlowCallRateThreshold,
	}
}

// ToDomain converts NodeHandlersSpec to domain.NodeHandlers.
func (s NodeHandlersSpec) ToDomain() domain.NodeHandlers {
	return domain.NodeHandlers{
		Success:     s.Success,
		Failure:     s.Failure,
		Timeout:     s.Timeout,
		RateLimited: s.RateLimited,
		CircuitOpen: s.CircuitOpen,
		Else:        s.Else,
	}
}

// ToDomain converts PolicyBundleDescriptor to domain.PolicyBundleDescriptor
func (d PolicyBundleDescriptor) ToDomain() domain.PolicyBundleDescriptor {
artifacts := make([]domain.BundleArtifactDescriptor, len(d.Artifacts))
for i, a := range d.Artifacts {
artifacts[i] = a.ToDomain()
}
return domain.PolicyBundleDescriptor{
ID:        d.ID,
Name:      d.Name,
Version:   d.Version,
Revision:  d.Revision,
Path:      d.Path,
SizeLimit: d.SizeLimit,
Labels:    d.Labels,
Artifacts: artifacts,
}
}

// ToDomain converts BundleArtifactDescriptor to domain.BundleArtifactDescriptor
func (a BundleArtifactDescriptor) ToDomain() domain.BundleArtifactDescriptor {
return domain.BundleArtifactDescriptor{
Name:        a.Name,
Path:        a.Path,
Type:        a.Type,
MediaType:   a.MediaType,
Encoding:    a.Encoding,
Compression: a.Compression,
SHA256:      a.SHA256,
Metadata:    a.Metadata,
}
}

