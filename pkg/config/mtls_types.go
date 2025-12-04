package config

import (
	"fmt"
	"strings"
)

// PeerVerificationMode controls how strictly peer certificates are validated.
type PeerVerificationMode string

const (
	// PeerVerificationStrict requires verifying peers against system trust roots and configured bundles.
	PeerVerificationStrict PeerVerificationMode = "strict"
	// PeerVerificationTrustBundleOnly limits verification to the configured trust bundle.
	PeerVerificationTrustBundleOnly PeerVerificationMode = "trust-bundle-only"
)

// ParsePeerVerification converts raw string values to a recognised mode.
func ParsePeerVerification(value string) (PeerVerificationMode, error) {
	if value == "" {
		return PeerVerificationStrict, nil
	}
	mode := PeerVerificationMode(strings.TrimSpace(strings.ToLower(value)))
	switch mode {
	case PeerVerificationStrict, PeerVerificationTrustBundleOnly:
		return mode, nil
	default:
		return "", fmt.Errorf("unknown peer verification mode %q", value)
	}
}

// DirectionMTLS captures the effective toggle for a direction.
type DirectionMTLS struct {
	Require          bool
	TrustBundle      string
	PeerVerification PeerVerificationMode
}

// EffectiveMTLS exposes upstream/downstream requirements.
type EffectiveMTLS struct {
	Upstream   DirectionMTLS
	Downstream DirectionMTLS
}

// RawMTLS tracks the raw policy representation before normalisation.
type RawMTLS struct {
	Enabled          *bool             `json:"enabled" yaml:"enabled"`
	TrustRootsRef    string            `json:"trustRootsRef" yaml:"trustRootsRef"`
	PeerVerification string            `json:"peerVerification" yaml:"peerVerification"`
	Upstream         *RawMTLSDirection `json:"upstream" yaml:"upstream"`
	Downstream       *RawMTLSDirection `json:"downstream" yaml:"downstream"`
}

// Clone performs a deep copy to keep maps and pointers immutable.
func (m RawMTLS) Clone() RawMTLS {
	clone := RawMTLS{
		TrustRootsRef:    m.TrustRootsRef,
		PeerVerification: m.PeerVerification,
	}
	if m.Enabled != nil {
		value := *m.Enabled
		clone.Enabled = &value
	}
	if m.Upstream != nil {
		value := *m.Upstream
		clone.Upstream = value.Clone()
	}
	if m.Downstream != nil {
		value := *m.Downstream
		clone.Downstream = value.Clone()
	}
	return clone
}

// RawMTLSDirection stores per-direction overrides in the raw config.
type RawMTLSDirection struct {
	Require          *bool  `json:"require" yaml:"require"`
	TrustRootsRef    string `json:"trustRootsRef" yaml:"trustRootsRef"`
	PeerVerification string `json:"peerVerification" yaml:"peerVerification"`
}

// Clone deep copies pointer members.
func (d RawMTLSDirection) Clone() *RawMTLSDirection {
	clone := d
	if d.Require != nil {
		value := *d.Require
		clone.Require = &value
	}
	return &clone
}

// ToEffective converts raw settings into an evaluated structure.
func (m RawMTLS) ToEffective() (EffectiveMTLS, error) {
	baseMode, err := ParsePeerVerification(m.PeerVerification)
	if err != nil {
		return EffectiveMTLS{}, err
	}

	effective := EffectiveMTLS{
		Upstream:   newDirection(baseMode),
		Downstream: newDirection(baseMode),
	}

	if m.Enabled != nil {
		effective.Upstream.Require = *m.Enabled
		effective.Downstream.Require = *m.Enabled
	}

	if effective.Upstream, err = applyDirectionOverrides(effective.Upstream, m.Upstream); err != nil {
		return EffectiveMTLS{}, err
	}
	if effective.Downstream, err = applyDirectionOverrides(effective.Downstream, m.Downstream); err != nil {
		return EffectiveMTLS{}, err
	}

	sharedBundle := strings.TrimSpace(m.TrustRootsRef)
	if effective.Upstream.TrustBundle == "" {
		effective.Upstream.TrustBundle = sharedBundle
	}
	if effective.Downstream.TrustBundle == "" {
		effective.Downstream.TrustBundle = sharedBundle
	}

	return effective, nil
}

func newDirection(mode PeerVerificationMode) DirectionMTLS {
	return DirectionMTLS{PeerVerification: mode}
}

func applyDirectionOverrides(direction DirectionMTLS, raw *RawMTLSDirection) (DirectionMTLS, error) {
	if raw == nil {
		return direction, nil
	}
	if raw.Require != nil {
		direction.Require = *raw.Require
	}
	if bundle := strings.TrimSpace(raw.TrustRootsRef); bundle != "" {
		direction.TrustBundle = bundle
	}
	if raw.PeerVerification != "" {
		mode, err := ParsePeerVerification(raw.PeerVerification)
		if err != nil {
			return DirectionMTLS{}, err
		}
		direction.PeerVerification = mode
	}
	return direction, nil
}
