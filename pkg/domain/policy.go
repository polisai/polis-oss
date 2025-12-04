package domain

import (
	"context"
	"time"
)

// Policy represents a governance policy with evaluation rules.
type Policy struct {
	ID         string
	Name       string
	Generation string
	Entrypoint string
	Bundle     []byte
	FailOpen   bool `json:"fail_open"`
}

// PolicyBundle represents a collection of policy artifacts derived from a single
// source. It is the unit of storage and management in the control plane.
// Different pipeline nodes can consume different artifacts from the same bundle.
type PolicyBundle struct {
	ID        string                    `json:"id" yaml:"id"`
	Name      string                    `json:"name" yaml:"name"`
	Version   int                       `json:"version" yaml:"version"`
	Revision  string                    `json:"revision" yaml:"revision"`
	Labels    map[string]string         `json:"labels" yaml:"labels"`
	Artifacts map[string]PolicyArtifact `json:"artifacts" yaml:"artifacts"`
	CreatedAt time.Time                 `json:"created_at" yaml:"created_at"`
	UpdatedAt time.Time                 `json:"updated_at" yaml:"updated_at"`
}

// PolicyArtifact holds a single piece of processed policy data, like a Rego module
// or a DLP ruleset document.
type PolicyArtifact struct {
	Type        string            `json:"type" yaml:"type"`
	MediaType   string            `json:"media_type" yaml:"media_type"`
	Encoding    string            `json:"encoding" yaml:"encoding"`
	Compression string            `json:"compression" yaml:"compression"`
	Digest      string            `json:"digest" yaml:"digest"`
	Data        []byte            `json:"data" yaml:"data"`
	Metadata    map[string]string `json:"metadata" yaml:"metadata"`
}

// Clone returns a deep copy of the policy bundle to avoid shared mutable state.
func (b *PolicyBundle) Clone() *PolicyBundle {
	if b == nil {
		return nil
	}

	clone := &PolicyBundle{
		ID:        b.ID,
		Name:      b.Name,
		Version:   b.Version,
		Revision:  b.Revision,
		Labels:    cloneStringMap(b.Labels),
		CreatedAt: b.CreatedAt,
		UpdatedAt: b.UpdatedAt,
	}

	if len(b.Artifacts) > 0 {
		clone.Artifacts = make(map[string]PolicyArtifact, len(b.Artifacts))
		for name, artifact := range b.Artifacts {
			clone.Artifacts[name] = artifact.Clone()
		}
	} else {
		clone.Artifacts = map[string]PolicyArtifact{}
	}

	return clone
}

// Clone returns a deep copy of the policy artifact.
func (a PolicyArtifact) Clone() PolicyArtifact {
	clone := PolicyArtifact{
		Type:        a.Type,
		MediaType:   a.MediaType,
		Encoding:    a.Encoding,
		Compression: a.Compression,
		Digest:      a.Digest,
		Metadata:    cloneStringMap(a.Metadata),
	}
	if len(a.Data) > 0 {
		clone.Data = append([]byte(nil), a.Data...)
	}
	return clone
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return map[string]string{}
	}
	clone := make(map[string]string, len(input))
	for k, v := range input {
		clone[k] = v
	}
	return clone
}

// PolicyIdentity represents minimal identity info for policy evaluation (passthrough mode).
type PolicyIdentity struct {
	Subject  string
	Issuer   string
	Audience []string
	Scopes   []string
}

// Input represents policy evaluation input.
type Input struct {
	RouteID    string
	PolicyID   string
	Generation string
	Identity   PolicyIdentity
	Attributes map[string]any
	Findings   map[string]any
	Entrypoint string
}

// Decision represents the outcome of a policy evaluation.
type Decision struct {
	Allow      bool
	Deny       bool
	Violations []Violation
	Actions    []Action
	Metadata   map[string]any
}

// Violation represents a policy violation.
type Violation struct {
	Code     string
	Severity string
	Message  string
	Details  map[string]any
}

// Action represents an enforcement action.
type Action struct {
	Type   string
	Target string
	Params map[string]any
}

// PolicyService defines the interface for interacting with the policy engine.
type PolicyService interface {
	// Evaluate executes policy evaluation for the given input.
	Evaluate(ctx context.Context, input Input) (Decision, error)

	// LoadBundle loads a policy bundle.
	LoadBundle(ctx context.Context, bundle []byte) error

	// Ready returns true if the policy engine is ready.
	Ready() bool
}
