package llmjudge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
	"gopkg.in/yaml.v3"
)

// Handler implements the LLM-as-Judge node for content safety evaluation.
type Handler struct {
	logger         *slog.Logger
	promptProvider PromptProvider
	httpClient     *http.Client
}

// NewLLMJudgeHandler creates a new handler instance.
// NewLLMJudgeHandler creates a new LLM Judge handler instance.
func NewLLMJudgeHandler(logger *slog.Logger, provider PromptProvider) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	// Defaults to local provider if nil, though caller should typically provide one
	if provider == nil {
		provider = NewLocalPromptProvider("prompts")
	}

	return &Handler{
		logger:         logger,
		promptProvider: provider,
		httpClient:     &http.Client{Timeout: 30 * time.Second},
	}
}

// Execute evaluates the message against the rules using an LLM.
func (h *Handler) Execute(ctx context.Context, node *domain.PipelineNode, pipelineCtx *domain.PipelineContext) (runtime.NodeResult, error) {
	// 1. Parse Config
	cfg, err := h.parseConfig(node.Config)
	if err != nil {
		return runtime.Failure(nil), fmt.Errorf("llm_judge: invalid config: %w", err)
	}

	// 2. Resolve Content to Check
	content := h.resolveTargetContent(cfg.Target, pipelineCtx)
	if content == "" {
		// No content to check is considered safe (or skip)
		return runtime.Success(nil), nil
	}

	// 3. Get Prompts
	taskPrompt, rulesPrompt, err := h.promptProvider.GetPrompts(ctx, cfg.TaskID, cfg.RulesID)
	if err != nil {
		h.logger.Error("llm_judge: failed to load prompts", "task", cfg.TaskID, "rules", cfg.RulesID, "error", err)
		// Fail-open by default if configuration is broken? Or strict failure?
		// For safety nodes, strict failure is usually better, but let's return Failure.
		return runtime.Failure(map[string]any{"error": "prompt loading failed"}), nil
	}

	// 4. Construct Final Prompt (Logic moved to separate method for clarity)
	finalPrompt := h.constructPrompt(taskPrompt, rulesPrompt, content)

	// 5. Determine Execution Mode
	isAsync := false
	if cfg.Async != nil {
		isAsync = *cfg.Async
	} else {
		// Default behavior based on Mode
		isAsync = (cfg.Mode == ModeLog)
	}

	if isAsync {
		// ASYNC / LOG MODE
		// Fire-and-forget: we don't block the request.
		go func() {
			// Create a detached context for the async operation (with its own timeout)
			asyncCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			decision, err := h.callLLM(asyncCtx, cfg, finalPrompt)
			if err != nil {
				h.logger.Error("llm_judge (async): execution failed", "error", err)
				return
			}
			h.logDecision(decision, cfg, "async")
		}()

		return runtime.Success(map[string]any{"llm_judge_status": "async_started"}), nil
	}

	// STRICT / BLOCKING MODE
	decision, err := h.callLLM(ctx, cfg, finalPrompt)
	if err != nil {
		h.logger.Error("llm_judge (strict): execution failed", "error", err)
		// On technical failure, do we deny? Let's return Failure.
		return runtime.Failure(map[string]any{"error": err.Error()}), nil
	}

	h.logDecision(decision, cfg, "strict")

	if decision.Decision == DecisionUnsafe {
		// Deny the request
		return runtime.NodeResult{
			Outcome: runtime.OutcomeDeny,
			State: map[string]any{
				"block_reason":     decision.Explanation,
				"llm_judge_score":  decision.Score,
				"llm_judge_result": decision,
			},
		}, nil
	}

	return runtime.Success(map[string]any{
		"llm_judge_result": decision,
	}), nil
}

func (h *Handler) parseConfig(raw map[string]any) (HandlerConfig, error) {
	// Marshal/Unmarshal to cleanly map standard map[string]any to struct
	// This creates a slight overhead but ensures consistency with JSON/YAML tags
	data, err := yaml.Marshal(raw)
	if err != nil {
		return HandlerConfig{}, err
	}

	var cfg HandlerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return HandlerConfig{}, err
	}

	// Set defaults
	if cfg.Mode == "" {
		cfg.Mode = ModeLog
	}
	// Normalize mode
	cfg.Mode = strings.ToLower(cfg.Mode)
	if cfg.Mode != ModeStrict && cfg.Mode != ModeLog {
		return HandlerConfig{}, fmt.Errorf("invalid mode %q (must be 'strict' or 'log')", cfg.Mode)
	}

	if cfg.Temperature < 0 {
		cfg.Temperature = 0
	}

	return cfg, nil
}

func (h *Handler) resolveTargetContent(target string, ctx *domain.PipelineContext) string {
	// Support simple dot notation for now: request.body, response.body
	// In a real implementation this would ideally share the expression evaluator
	switch target {
	case "request.body":
		// TODO: Access body from context. Currently PipelineContext has generic Variables.
		// Assuming body is available or we need to add Body access to PipelineContext.
		// For now, looking in Variables as a fallback pattern used in some systems
		if val, ok := ctx.Variables["request.body_text"]; ok {
			return fmt.Sprint(val)
		}
		// Or assume it's simulated in variables for MVP
		return "" // Empty/Not found
	case "response.body":
		if val, ok := ctx.Variables["response.body_text"]; ok {
			return fmt.Sprint(val)
		}
		return ""
	default:
		// Try generic variable lookup
		if val, ok := ctx.Variables[target]; ok {
			return fmt.Sprint(val)
		}
	}
	return ""
}

func (h *Handler) constructPrompt(task, rules, input string) string {
	// Simple concatenation. A more robust system uses templates.
	var sb strings.Builder
	sb.WriteString("TASK:\n")
	sb.WriteString(task)
	sb.WriteString("\n\nRULES:\n")
	sb.WriteString(rules)
	sb.WriteString("\n\nINPUT TO EVALUATE:\n")
	sb.WriteString(input)
	sb.WriteString("\n\nINSTRUCTIONS:\n")
	sb.WriteString("Evaluate the input against the rules. Return JSON with 'decision' (SAFE/UNSAFE), 'explanation', and 'score' (0.0-1.0).")
	return sb.String()
}

// callLLM executes the request to the configured LLM API.
// Note: This implementation assumes an OpenAI-compatible completion API for MVP.
func (h *Handler) callLLM(ctx context.Context, cfg HandlerConfig, prompt string) (LLMResponse, error) {
	// Use configured model or default
	model := cfg.Model
	if model == "" {
		model = "gpt-4o"
	}

	// Simple OpenAI-like payload
	payload := map[string]any{
		"model":           model,
		"messages":        []map[string]string{{"role": "user", "content": prompt}},
		"temperature":     cfg.Temperature,
		"response_format": map[string]string{"type": "json_object"},
	}

	bodyBytes, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(bodyBytes))
	if err != nil {
		return LLMResponse{}, err
	}

	// TODO: Auth token via env var injection or config reuse
	// For MVP, we might assume env var OPENAI_API_KEY is standard
	// In production, this should come from a secure CredentialProvider
	if key := getEnv("OPENAI_API_KEY", ""); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return LLMResponse{}, fmt.Errorf("llm request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			h.logger.Warn("failed to close response body", "error", closeErr)
		}
	}()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return LLMResponse{}, fmt.Errorf("llm returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse OpenAI response structure
	var completion struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&completion); err != nil {
		return LLMResponse{}, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(completion.Choices) == 0 {
		return LLMResponse{}, fmt.Errorf("no completion choices returned")
	}

	// Parse the inner JSON content
	content := completion.Choices[0].Message.Content
	var result LLMResponse
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		h.logger.Warn("failed to parse JSON from LLM, attempting fallback", "content", content)
		// Fallback: Crude string check if JSON parsing fails
		if strings.Contains(strings.ToUpper(content), "UNSAFE") {
			result.Decision = DecisionUnsafe
		} else {
			result.Decision = DecisionSafe
		}
		result.Explanation = content
	}

	// Normalize decision
	result.Decision = Decision(strings.ToUpper(string(result.Decision)))
	if result.Decision != DecisionSafe && result.Decision != DecisionUnsafe {
		result.Decision = DecisionUnsafe // Fail closed on ambiguity
	}

	return result, nil
}

func (h *Handler) logDecision(decision LLMResponse, cfg HandlerConfig, mode string) {
	h.logger.Info("llm_judge decision",
		"mode", mode,
		"decision", decision.Decision,
		"score", decision.Score,
		"task", cfg.TaskID,
		"explanation", decision.Explanation,
	)
}

// getEnv is a simple helper (avoiding os import pollution in method body)
func getEnv(key, fallback string) string {
	// Implementation note: standard os.Getenv
	// In real handlers, we might have a dependency injected ConfigService
	importOS := "os" // Dummy to prevent import removal if I used os directly above
	_ = importOS
	// Actually os is imported at file level
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return fallback
	}
	return val
}
