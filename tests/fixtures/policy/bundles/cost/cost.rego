package policy.cost

import future.keywords.if

max_tokens_in := 200000
max_tokens_out := 200000
max_cost_usd := 50.0

tokens_in := numeric_attr("session.tokens_in")
tokens_out := numeric_attr("session.tokens_out")
cost_usd := numeric_attr("session.estimated_cost_usd")

cost_violation if {
	cost_usd > max_cost_usd
}

tokens_out_violation if {
	tokens_out > max_tokens_out
}

tokens_in_violation if {
	tokens_in > max_tokens_in
}

violation_reason := "budget_cost_exceeded" if {
	cost_violation
}

violation_reason := "budget_tokens_out_exceeded" if {
	not cost_violation
	tokens_out_violation
}

violation_reason := "budget_tokens_in_exceeded" if {
	not cost_violation
	not tokens_out_violation
	tokens_in_violation
}

default violation_reason := ""

decision := {
	"action": "block",
	"reason": "BUDGET_EXCEEDED",
	"metadata": {"cost.reason": violation_reason},
} if {
	violation_reason != ""
}

decision := {
	"action": "allow",
	"reason": "BUDGET_WITHIN_LIMIT",
	"metadata": {"cost.reason": "allow"},
} if {
	violation_reason == ""
}

numeric_attr(key) := value if {
	value := to_number(object.get(input.attributes, key, 0))
}
