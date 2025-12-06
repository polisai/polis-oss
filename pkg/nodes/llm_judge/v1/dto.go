// Package llmjudge provides an LLM-as-Judge node implementation for content safety evaluation.
package llmjudge

// Decision represents the safety decision from the LLM.
type Decision string

const (
	// DecisionSafe indicates content is safe.
	DecisionSafe Decision = "SAFE"
	// DecisionUnsafe indicates content violates safety policy.
	DecisionUnsafe Decision = "UNSAFE"
	// DecisionUnsure Decision = "UNSURE" // Future extension
)

// LLMResponse is the expected JSON struct from the LLM.
type LLMResponse struct {
	Decision    Decision `json:"decision"`
	Explanation string   `json:"explanation"`
	Score       float64  `json:"score,omitempty"` // Optional 0-1 safety score
}

// HandlerConfig represents the configuration for the LLM Judge node.
type HandlerConfig struct {
	// Mode: "strict" (blocking) or "log" (async)
	Mode string `json:"mode" yaml:"mode"`
	// Async: if true, runs in background. Overrides Mode implication if set.
	Async *bool `json:"async,omitempty" yaml:"async,omitempty"`

	// TaskID and RulesID identify which prompts to load
	TaskID  string `json:"taskId" yaml:"taskId"`
	RulesID string `json:"rulesId" yaml:"rulesId"`

	// Target specifies what to evaluate: "request.body" or "response.body"
	Target string `json:"target" yaml:"target"`

	// LLM config (could be expanded or ref inputs)
	Model       string  `json:"model" yaml:"model"`
	Temperature float64 `json:"temperature" yaml:"temperature"`
}

const (
	// ModeStrict blocks unsafe content synchronously.
	ModeStrict = "strict"
	// ModeLog logs safety findings asynchronously without blocking.
	ModeLog = "log"
)
