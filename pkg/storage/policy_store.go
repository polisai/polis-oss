// Package storage provides policy storage and versioning capabilities for the proxy.
// It manages OPA bundles and policy metadata with support for activation tracking.
package storage

import (
	"context"
	"errors"

	"github.com/polisai/polis-oss/pkg/domain"
)

// ErrNotFound is returned when a requested bundle or artifact does not exist in the store.
var ErrNotFound = errors.New("policy bundle not found")

// PolicyStore exposes persistence operations for policy bundles.
type PolicyStore interface {
	GetPolicyBundle(ctx context.Context, id string, version int) (*domain.PolicyBundle, error)
	SavePolicyBundle(ctx context.Context, bundle *domain.PolicyBundle) error
	TriggerCompaction(ctx context.Context) error
	Close() error
}
