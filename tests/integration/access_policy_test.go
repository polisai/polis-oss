package integration

import (
	"context"
	"testing"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/policy"
	"github.com/polisai/polis-oss/tests/testhelpers"
)

func TestAccessPolicyBundleDecisions(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	engine := testhelpers.NewAccessPolicyEngine(ctx, t)

	cases := []struct {
		name           string
		subject        string
		audiences      []string
		scopes         []string
		wantAction     policy.Action
		wantMetaReason string
	}{
		{
			name:           "allow when audience and scope satisfied",
			subject:        "agent@example.com",
			audiences:      []string{"api://primary"},
			scopes:         []string{"support-leads"},
			wantAction:     policy.ActionAllow,
			wantMetaReason: "allow",
		},
		{
			name:           "denylist blocks subject",
			subject:        "blocked-agent@example.com",
			audiences:      []string{"api://primary"},
			scopes:         []string{"support-leads"},
			wantAction:     policy.ActionBlock,
			wantMetaReason: "denylist_subject",
		},
		{
			name:           "missing audience triggers mismatch",
			subject:        "agent@example.com",
			audiences:      []string{"api://secondary"},
			scopes:         []string{"support-leads"},
			wantAction:     policy.ActionBlock,
			wantMetaReason: "audience_mismatch",
		},
		{
			name:           "missing scope fails",
			subject:        "agent@example.com",
			audiences:      []string{"api://primary"},
			scopes:         []string{"support:view"},
			wantAction:     policy.ActionBlock,
			wantMetaReason: "scope_missing",
		},
		{
			name:           "missing subject fails closed",
			subject:        "",
			audiences:      []string{"api://primary"},
			scopes:         []string{"support-leads"},
			wantAction:     policy.ActionBlock,
			wantMetaReason: "missing_subject",
		},
		{
			name:           "missing audience header denies",
			subject:        "agent@example.com",
			audiences:      nil,
			scopes:         []string{"support-leads"},
			wantAction:     policy.ActionBlock,
			wantMetaReason: "audience_mismatch",
		},
		{
			name:           "empty audience array denies",
			subject:        "agent@example.com",
			audiences:      []string{},
			scopes:         []string{"support-leads"},
			wantAction:     policy.ActionBlock,
			wantMetaReason: "audience_mismatch",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			input := policy.Input{
				RouteID: "agent-test",
				Identity: domain.PolicyIdentity{
					Subject:  tc.subject,
					Audience: tc.audiences,
					Scopes:   tc.scopes,
				},
				Attributes: make(map[string]any),
				Findings:   make(map[string]any),
				Entrypoint: "policy/access/decision",
			}

			decision, err := engine.Evaluate(ctx, input)
			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}

			if decision.Action != tc.wantAction {
				t.Fatalf("unexpected action: got %s want %s", decision.Action, tc.wantAction)
			}

			gotReason := decision.Metadata["access.reason"]
			if gotReason != tc.wantMetaReason {
				t.Fatalf("unexpected metadata reason: got %q want %q", gotReason, tc.wantMetaReason)
			}
		})
	}
}
