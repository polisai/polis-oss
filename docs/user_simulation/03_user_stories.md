# User Stories & Usage Scenarios

This document outlines three key scenarios for using Polis OSS: PII Protection, Cost Control, and Compliance Enforcement. Each scenario represents a common real-world use case.

## Scenario 1: PII Protection (Data Loss Prevention)

**Goal:** Ensure that sensitive information, specifically US Social Security Numbers (SSN) and Credit Card numbers, never leaves the secure perimeter, even if an LLM is tricked into generating them or a user inadvertently sends them.

**The Solution:**
We will configure a **DLP (Data Loss Prevention)** node in our pipeline. This node scans the request (prompt) and the response (completion) for regex patterns matching sensitive data.

*   **Config:** `pipeline.yaml` with a `dlp` node.
*   **Policy:** A configured DLP rule set (regexes).
*   **Outcome:** If a user types "My SSN is 000-00-0000", the proxy will either **Block** the request entirely or **Redact** it to "My SSN is [REDACTED]".

## Scenario 2: Cost Control (Budget Enforcement)

**Goal:** Prevent a specific AI Agent or Department from overspending on LLM tokens. We want to stop any request if the accumulated cost or token count in the current session exceeds a threshold.

**The Solution:**
We will use a **Policy** node running an OPA Cost Policy.
**Note:** In a full implementation, you would need a component to track usage state. For this simulation, we assume the session usage data (e.g., `session.estimated_cost_usd`) is available in the input attributes.

*   **Config:** `pipeline.yaml` with a `policy` node pointed to `policy/cost`.
*   **Policy:** `cost_policy.rego` that checks `input.attributes["session.estimated_cost_usd"] > 5.00`.
*   **Outcome:** If the estimated session cost is > $5.00, the request is rejected with a `403 Forbidden` and a "Budget Exceeded" message.

## Scenario 3: Compliance & Content Safety

**Goal:** Ensure the AI Agent does not discuss restricted topics (e.g., "Competitor X") or offer financial advice if it is not authorized.

**The Solution:**
We will specific a **Policy** node that inspects the request body text for forbidden keywords.

*   **Config:** `pipeline.yaml` with a `policy` node.
*   **Policy:** `compliance.rego` that searches for keywords like "CompetitorName".
*   **Outcome:** If the prompt contains "Tell me about CompetitorName", the proxy intercepts the request, logs the policy violation for auditing, and returns a pre-canned "I cannot discuss this topic" response.

---

## Testing These Scenarios

To test these scenarios, you can use the pre-configured assets provided in the `assets/` folder.

1.  Navigate to `docs/user_simulation/assets/<scenario_folder>`.
2.  Copy the `pipeline.yaml` and policy files to your proxy's config directory.
3.  Restart the proxy (or wait for hot-reload).
4.  Send a test request using `curl` or Postman to see the policy in action.

## Scenario 4: Observability & Auditing

**Goal:** As an administrator, I need to know *why* a request was blocked or exactly what PII was redacted, for compliance reporting.

**The Solution:**
Polis OSS sends structured JSON logs (and optionally traces) for every request. By inspecting the `audit` logs, we can see the decision trail.

*   **Config:** `config.yaml` with `logging.level: debug` and `logging.pretty: false` (for JSON).
*   **Outcome:** When a request is blocked (e.g., in Scenario 2), the logs will contain a structured entry:
    ```json
    {
      "level": "info",
      "msg": "Policy Eval",
      "decision": "block",
      "reason": "budget_exceeded",
      "policy_id": "cost_check",
      "request_id": "req-123..."
    }
    ```
    This confirms the system is working and provides immutable evidence of policy enforcement.

