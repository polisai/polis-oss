package policy.decision

import rego.v1

default action := "allow"
default reason := "allowed by default"

# Block requests with the X-Forbidden header
action := "block" if {
	input.attributes["http.headers"]["x-forbidden"][0] == "true"
}

reason := "forbidden header detected" if {
	action == "block"
}
