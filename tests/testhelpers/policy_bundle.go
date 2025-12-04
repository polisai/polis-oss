// Package testhelpers provides test utilities for building OPA policy bundles and creating policy engines with fixture data.
package testhelpers

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/polisai/polis-oss/pkg/policy"
)

const (
	standardBundleDir = "tests/fixtures/policy/bundles/standard"
	accessBundleDir   = "tests/fixtures/policy/bundles/access"
	costBundleDir     = "tests/fixtures/policy/bundles/cost"
)

// NewStandardPolicyEngine constructs a policy engine using the standard test fixture bundle.
func NewStandardPolicyEngine(ctx context.Context, t testing.TB) *policy.Engine {
	t.Helper()
	return newPolicyEngineFromFixture(ctx, t, standardBundleDir, "policy.rego", "policy/decision")
}

// NewAccessPolicyEngine constructs a policy engine using the access control bundle fixture.
func NewAccessPolicyEngine(ctx context.Context, t testing.TB) *policy.Engine {
	t.Helper()
	return newPolicyEngineFromFixture(ctx, t, accessBundleDir, "access.rego", "policy/access/decision")
}

// NewCostPolicyEngine constructs a policy engine using the cost/budget bundle fixture.
func NewCostPolicyEngine(ctx context.Context, t testing.TB) *policy.Engine {
	t.Helper()
	return newPolicyEngineFromFixture(ctx, t, costBundleDir, "cost.rego", "policy/cost/decision")
}

func newPolicyEngineFromFixture(ctx context.Context, t testing.TB, bundleDir, moduleName, entrypoint string) *policy.Engine {
	t.Helper()

	regoPath := fixturePath(t, bundleDir, moduleName)
	// #nosec G304 - Test fixture path is controlled by test code
	regoBytes, err := os.ReadFile(regoPath)
	if err != nil {
		t.Fatalf("failed to read rego fixture: %v", err)
	}

	opts := policy.EngineOptions{
		Entrypoint:      entrypoint,
		CacheMaxEntries: 32,
		Modules: map[string]string{
			moduleName: string(regoBytes),
		},
	}

	engine, err := policy.NewEngine(ctx, opts)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	return engine
}

func fixturePath(t testing.TB, elements ...string) string {
	t.Helper()

	path := filepath.Join(append([]string{moduleRoot()}, elements...)...)
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("failed to resolve fixture path: %v", err)
	}
	return abs
}

var (
	cachedRoot string
	rootOnce   sync.Once
)

func moduleRoot() string {
	rootOnce.Do(func() {
		_, currentFile, _, ok := runtime.Caller(0)
		if !ok {
			panic("unable to determine caller for policy bundle helpers")
		}
		cachedRoot = filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	})
	return cachedRoot
}
