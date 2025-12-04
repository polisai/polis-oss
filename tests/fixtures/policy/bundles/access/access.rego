package policy.access

import future.keywords.if

denylist := {"blocked-agent@example.com"}
required_audiences := {"api://primary"}
required_scopes := {"support-leads"}

subject := lower(object.get(input.identity, "subject", ""))
audiences := normalize_array(object.get(input.identity, "audience", []))
scopes := normalize_array(object.get(input.identity, "scopes", []))

violation_reason := "missing_subject" if {
	subject == ""
}

violation_reason := "denylist_subject" if {
	subject != ""
	denylist[subject]
}

violation_reason := "audience_mismatch" if {
	subject != ""
	not denylist[subject]
	audience_requirement_failed
}

violation_reason := "scope_missing" if {
	subject != ""
	not denylist[subject]
	not audience_requirement_failed
	value := required_scopes[_]
	not contains_ci(scopes, value)
}

default violation_reason := ""

audience_requirement_failed if {
	count(audiences) == 0
}

audience_requirement_failed if {
	value := required_audiences[_]
	not contains_ci(audiences, value)
}

decision := {
	"action": "block",
	"reason": "ACCESS_DENIED",
	"metadata": {
		"access.reason": violation_reason,
		"access.subject": subject,
	},
} if {
	violation_reason != ""
}

decision := {
	"action": "allow",
	"reason": "ACCESS_GRANTED",
	"metadata": {
		"access.reason": "allow",
		"access.subject": subject,
	},
} if {
	violation_reason == ""
}

contains_ci(list, needle) if {
	lower(sprintf("%v", [list[_]])) == lower(sprintf("%v", [needle]))
}

normalize_array(value) := value if {
	is_array(value)
}

normalize_array(value) := [] if {
	not is_array(value)
}
