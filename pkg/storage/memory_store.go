package storage

import (
	"context"
	"fmt"
	"sync"

	"github.com/polisai/polis-oss/pkg/domain"
)

// MemoryPolicyStore is an in-memory implementation of PolicyStore.
type MemoryPolicyStore struct {
	mu      sync.RWMutex
	bundles map[string]*domain.PolicyBundle
}

// NewMemoryPolicyStore creates a new MemoryPolicyStore.
func NewMemoryPolicyStore() *MemoryPolicyStore {
	return &MemoryPolicyStore{
		bundles: make(map[string]*domain.PolicyBundle),
	}
}

func (s *MemoryPolicyStore) key(id string, version int) string {
	return fmt.Sprintf("%s:%d", id, version)
}

// GetPolicyBundle retrieves a policy bundle from memory.
func (s *MemoryPolicyStore) GetPolicyBundle(_ context.Context, id string, version int) (*domain.PolicyBundle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := s.key(id, version)
	bundle, ok := s.bundles[key]
	if !ok {
		return nil, fmt.Errorf("policy bundle not found: %s", key)
	}
	return bundle, nil
}

// SavePolicyBundle saves a policy bundle to memory.
func (s *MemoryPolicyStore) SavePolicyBundle(_ context.Context, bundle *domain.PolicyBundle) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := s.key(bundle.ID, bundle.Version)
	s.bundles[key] = bundle
	return nil
}

// TriggerCompaction is a no-op for memory store.
func (s *MemoryPolicyStore) TriggerCompaction(_ context.Context) error {
	return nil
}

// Close is a no-op for memory store.
func (s *MemoryPolicyStore) Close() error {
	return nil
}
