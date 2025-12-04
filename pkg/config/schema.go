package config

import (
	"fmt"
	"sort"
	"strings"
)

// SnapshotFinalizationError wraps errors encountered while finalising snapshots.
type SnapshotFinalizationError struct {
	Reason error
}

func (e SnapshotFinalizationError) Error() string {
	return fmt.Sprintf("snapshot finalisation failed: %v", e.Reason)
}

func (e SnapshotFinalizationError) Unwrap() error {
	return e.Reason
}

// Finalize derives summaries and indices for downstream consumers.
func (s *Snapshot) Finalize() error {
	if s == nil {
		return nil
	}

	if s.PolicyBundles == nil {
		s.PolicyBundles = []PolicyBundleDescriptor{}
	}

	bundleIndex := make(map[string]PolicyBundleDescriptor, len(s.PolicyBundles))
	for i := range s.PolicyBundles {
		descriptor := s.PolicyBundles[i].Clone()
		if err := descriptor.Validate(); err != nil {
			return SnapshotFinalizationError{Reason: fmt.Errorf("policy bundle %s: %w", descriptor.ID, err)}
		}
		key := policyBundleKey(descriptor.ID, descriptor.Version)
		if _, exists := bundleIndex[key]; exists {
			return SnapshotFinalizationError{Reason: fmt.Errorf("duplicate policy bundle %s@%d", descriptor.ID, descriptor.Version)}
		}
		s.PolicyBundles[i] = descriptor
		bundleIndex[key] = descriptor
	}

	// Normalise policies.
	index := make(map[string]PolicySpec, len(s.RawPolicies))
	summaries := make([]PolicySummary, 0, len(s.RawPolicies))
	for _, raw := range s.RawPolicies {
		policyCopy := raw.Clone()
		if err := policyCopy.Normalize(); err != nil {
			return SnapshotFinalizationError{Reason: err}
		}
		if policyCopy.BundleRef == "" && policyCopy.BundleVersion > 0 {
			return SnapshotFinalizationError{Reason: fmt.Errorf("policy %s specifies bundleVersion without bundleRef", policyCopy.ID)}
		}
		if policyCopy.BundleRef != "" {
			key := policyBundleKey(policyCopy.BundleRef, policyCopy.BundleVersion)
			descriptor, ok := bundleIndex[key]
			if !ok {
				return SnapshotFinalizationError{Reason: fmt.Errorf("policy %s references unknown bundle %s@%d", policyCopy.ID, policyCopy.BundleRef, policyCopy.BundleVersion)}
			}
			if err := validatePolicyArtifactReferences(policyCopy, descriptor); err != nil {
				return SnapshotFinalizationError{Reason: err}
			}
		}
		index[policyCopy.ID] = policyCopy
		summaries = append(summaries, PolicySummary{ID: policyCopy.ID, Name: policyCopy.Name})
	}

	// Note: Pipelines are validated when loaded into PipelineRegistry
	// No per-policy attachment counting needed with pipeline-based configuration

	s.PolicyIndex = index
	s.Policies = summaries
	if s.TrustBundles == nil {
		s.TrustBundles = map[string]*TrustBundle{}
	}
	s.PolicyBundleIndex = bundleIndex

	return nil
}

// GetPolicy retrieves a policy specification by ID from the snapshot's index.
// This implements the PolicyLookup interface for routing integration.
func (s Snapshot) GetPolicy(policyID string) (PolicySpec, bool) {
	policy, found := s.PolicyIndex[policyID]
	return policy, found
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func normalizeArtifactList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return strings.ToLower(out[i]) < strings.ToLower(out[j])
	})
	return out
}

func policyBundleKey(id string, version int) string {
	id = strings.TrimSpace(id)
	return fmt.Sprintf("%s@%d", id, version)
}

func validatePolicyArtifactReferences(policy PolicySpec, descriptor PolicyBundleDescriptor) error {
	available := make(map[string]struct{}, len(descriptor.Artifacts))
	for _, artifact := range descriptor.Artifacts {
		name := strings.TrimSpace(artifact.Name)
		if name == "" {
			continue
		}
		available[name] = struct{}{}
	}

	check := func(ref, location string) error {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return nil
		}
		if _, ok := available[ref]; !ok {
			return fmt.Errorf("policy %s references unknown artifact %q in bundle %s@%d (%s)", policy.ID, ref, descriptor.ID, descriptor.Version, location)
		}
		return nil
	}

	if err := check(policy.Artifacts.OPA.Bundle, "opa.bundle"); err != nil {
		return err
	}
	for _, ref := range policy.Artifacts.DLP {
		if err := check(ref, "dlp"); err != nil {
			return err
		}
	}
	for _, ref := range policy.Artifacts.WAF {
		if err := check(ref, "waf"); err != nil {
			return err
		}
	}
	if err := check(policy.Artifacts.Governance.RateLimits, "governance.rateLimits"); err != nil {
		return err
	}
	if err := check(policy.Artifacts.Governance.CircuitBreaker, "governance.circuitBreaker"); err != nil {
		return err
	}
	if err := check(policy.Artifacts.Governance.Timeouts, "governance.timeouts"); err != nil {
		return err
	}

	return nil
}
