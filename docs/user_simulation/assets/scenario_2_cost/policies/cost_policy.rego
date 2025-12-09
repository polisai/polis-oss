package policy.cost

default decision = {
    "action": "block",
    "reason": "default_deny"
}

# Allow if estimated cost is under $5.00
decision = {
    "action": "allow",
    "reason": "within_budget"
} {
    # In a real scenario, this attribute would be populated by a middleware or state store
    # For simulation, we assume it's passed in input.attributes
    cost := input.attributes["session.estimated_cost_usd"]
    cost < 5.00
}

# Block if cost is too high
decision = {
    "action": "block",
    "reason": "budget_exceeded"
} {
    cost := input.attributes["session.estimated_cost_usd"]
    cost >= 5.00
}
