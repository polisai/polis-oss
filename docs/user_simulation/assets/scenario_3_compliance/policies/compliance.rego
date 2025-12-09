package policy.compliance

import future.keywords.if
import future.keywords.in

default decision = {
    "action": "allow",
    "reason": "default_allow"
}

# Block if request body contains forbidden keywords
decision = {
    "action": "block",
    "reason": "forbidden_topic"
} if {
    some keyword in ["competitor_x", "insider_trading", "advice_financial"]
    contains(lower(input.request.body), keyword)
}
