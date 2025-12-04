package integration

import (
	"context"
	"testing"
	"time"

	"github.com/polisai/polis-oss/tests/testhelpers"
)

// TestPolicyEngineIntegration verifies policy engine loads correctly.
// Detailed policy enforcement is tested via DAG pipeline handlers in other tests.
func TestPolicyEngineIntegration(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	engine := testhelpers.NewStandardPolicyEngine(ctx, t)
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), time.Second)
		defer closeCancel()
		if err := engine.Close(closeCtx); err != nil {
			t.Fatalf("engine close failed: %v", err)
		}
	})

	// Verify engine is initialized
	if engine == nil {
		t.Fatal("expected non-nil policy engine")
	}

	// Note: Detailed policy enforcement testing (DLP, WAF, decisions) is done
	// via DAG pipeline handlers in dag_production_test.go and other integration tests.
	// This test ensures the policy engine itself initializes correctly.
}
