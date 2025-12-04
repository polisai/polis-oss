package integration

import (
	"context"
	"testing"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/policy"
	"github.com/polisai/polis-oss/tests/testhelpers"
)

func TestCostPolicyBundleDecisions(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	engine := testhelpers.NewCostPolicyEngine(ctx, t)

	cases := []struct {
		name       string
		tokensIn   int
		tokensOut  int
		costUSD    float64
		wantAction policy.Action
		wantReason string
	}{
		{
			name:       "within limits allows",
			tokensIn:   1000,
			tokensOut:  5000,
			costUSD:    3.25,
			wantAction: policy.ActionAllow,
			wantReason: "allow",
		},
		{
			name:       "cost budget exceeded blocks",
			tokensIn:   1000,
			tokensOut:  5000,
			costUSD:    60,
			wantAction: policy.ActionBlock,
			wantReason: "budget_cost_exceeded",
		},
		{
			name:       "tokens out budget exceeded blocks",
			tokensIn:   1000,
			tokensOut:  250000,
			costUSD:    3,
			wantAction: policy.ActionBlock,
			wantReason: "budget_tokens_out_exceeded",
		},
		{
			name:       "tokens in budget exceeded blocks",
			tokensIn:   250000,
			tokensOut:  5000,
			costUSD:    3,
			wantAction: policy.ActionBlock,
			wantReason: "budget_tokens_in_exceeded",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			input := policy.Input{
				RouteID:  "agent-budget-test",
				Identity: domain.PolicyIdentity{},
				Attributes: map[string]any{
					"session.tokens_in":          tc.tokensIn,
					"session.tokens_out":         tc.tokensOut,
					"session.estimated_cost_usd": tc.costUSD,
				},
				Findings:   make(map[string]any),
				Entrypoint: "policy/cost/decision",
			}

			decision, err := engine.Evaluate(ctx, input)
			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}

			if decision.Action != tc.wantAction {
				t.Fatalf("unexpected action: got %s want %s", decision.Action, tc.wantAction)
			}

			gotReason := decision.Metadata["cost.reason"]
			if gotReason != tc.wantReason {
				t.Fatalf("unexpected metadata reason: got %v want %v", gotReason, tc.wantReason)
			}

			// No extra metadata assertions; simplified bundle only surfaces reason codes.
		})
	}
}
