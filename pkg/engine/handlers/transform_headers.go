package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/polisai/polis-oss/pkg/domain"
	"github.com/polisai/polis-oss/pkg/engine/runtime"
)

// ResponseTransformKey stores response-scoped header operations on the pipeline context.
const ResponseTransformKey = "transform.headers.response_ops"

// HeaderTransformOperation represents a single header mutation operation.
type HeaderTransformOperation struct {
	Action  string
	Header  string
	Values  []string
	Headers []string
	From    string
	To      string
}

// HeaderTransformHandler mutates request or response headers according to configuration.
type HeaderTransformHandler struct {
	logger *slog.Logger
}

// NewHeaderTransformHandler constructs a handler for header transform nodes.
func NewHeaderTransformHandler(logger *slog.Logger) *HeaderTransformHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &HeaderTransformHandler{logger: logger}
}

// Execute applies header transforms to the request immediately or stages response transforms for later execution.
func (h *HeaderTransformHandler) Execute(_ context.Context, node *domain.PipelineNode, pipelineCtx *domain.PipelineContext) (runtime.NodeResult, error) {
	if pipelineCtx == nil {
		return runtime.Failure(nil), errors.New("header transform: pipeline context missing")
	}

	scope := strings.ToLower(strings.TrimSpace(resolveScope(node)))
	if scope == "" {
		scope = "request"
	}

	ops, err := h.parseOperations(node)
	if err != nil {
		h.logger.Error("header transform: invalid configuration",
			"node_id", node.ID,
			"error", err,
		)
		return runtime.Failure(nil), fmt.Errorf("header transform: %w", err)
	}

	if len(ops) == 0 {
		return runtime.Success(nil), nil
	}

	renderer := newTemplateRenderer(pipelineCtx)
	switch scope {
	case "request":
		requestHeaders := http.Header(pipelineCtx.Request.Headers)
		applyHeaderOperations(ops, requestHeaders, renderer)
	case "response":
		existing, _ := pipelineCtx.Variables[ResponseTransformKey].([]HeaderTransformOperation)
		staged := make([]HeaderTransformOperation, 0, len(existing)+len(ops))
		staged = append(staged, existing...)
		staged = append(staged, ops...)
		pipelineCtx.Variables[ResponseTransformKey] = staged
	default:
		return runtime.Failure(nil), fmt.Errorf("header transform: unsupported scope %q", scope)
	}

	h.logger.Debug("header transform applied",
		"node_id", node.ID,
		"scope", scope,
		"operations", len(ops),
	)

	return runtime.Success(nil), nil
}

func (h *HeaderTransformHandler) parseOperations(node *domain.PipelineNode) ([]HeaderTransformOperation, error) {
	if node == nil {
		return nil, errors.New("node is nil")
	}

	config := node.Config
	if config == nil {
		return nil, nil
	}

	if raw, ok := config["operations"]; ok {
		return parseOperationList(raw)
	}

	// Backward compatibility for legacy node types without operations list.
	action := strings.ToLower(strings.TrimSpace(getString(config, "action")))
	if action == "" {
		action = inferActionFromType(node.Type)
	}

	switch action {
	case "remove":
		headers := parseHeaderList(config["headers"])
		if len(headers) == 0 {
			return nil, errors.New("remove action requires headers list")
		}
		return []HeaderTransformOperation{{Action: "remove", Headers: headers}}, nil
	case "set", "add":
		return parseMapOrPair(action, config)
	case "rename":
		from := strings.TrimSpace(getString(config, "from"))
		to := strings.TrimSpace(getString(config, "to"))
		if from == "" || to == "" {
			return nil, errors.New("rename action requires from and to headers")
		}
		return []HeaderTransformOperation{{Action: "rename", From: from, To: to}}, nil
	case "":
		// No operations configured.
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported legacy action %q", action)
	}
}

func parseOperationList(raw interface{}) ([]HeaderTransformOperation, error) {
	items, ok := raw.([]interface{})
	if !ok {
		return nil, errors.New("operations must be an array")
	}

	ops := make([]HeaderTransformOperation, 0, len(items))
	for idx, item := range items {
		cfg, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("operation %d must be an object", idx)
		}
		action := strings.ToLower(strings.TrimSpace(getString(cfg, "action")))
		if action == "" {
			return nil, fmt.Errorf("operation %d missing action", idx)
		}

		switch action {
		case "remove":
			headers := parseHeaderList(cfg["headers"])
			if len(headers) == 0 {
				return nil, fmt.Errorf("operation %d remove requires headers", idx)
			}
			ops = append(ops, HeaderTransformOperation{Action: "remove", Headers: headers})
		case "set", "add":
			operation, err := parseHeaderMutation(action, cfg)
			if err != nil {
				return nil, fmt.Errorf("operation %d: %w", idx, err)
			}
			ops = append(ops, operation...)
		case "rename":
			from := strings.TrimSpace(getString(cfg, "from"))
			to := strings.TrimSpace(getString(cfg, "to"))
			if from == "" || to == "" {
				return nil, fmt.Errorf("operation %d rename requires from/to", idx)
			}
			ops = append(ops, HeaderTransformOperation{Action: "rename", From: from, To: to})
		default:
			return nil, fmt.Errorf("operation %d unsupported action %q", idx, action)
		}
	}

	return ops, nil
}

func parseMapOrPair(action string, config map[string]interface{}) ([]HeaderTransformOperation, error) {
	if headers, ok := config["headers"]; ok {
		return parseHeaderMutation(action, map[string]interface{}{"headers": headers})
	}

	header := strings.TrimSpace(getString(config, "header"))
	if header == "" {
		return nil, fmt.Errorf("%s action requires header or headers", action)
	}
	values := parseValues(config["values"], getString(config, "value"))
	if len(values) == 0 {
		return nil, fmt.Errorf("%s action requires value or values", action)
	}
	return []HeaderTransformOperation{{Action: action, Header: header, Values: values}}, nil
}

func parseHeaderMutation(action string, cfg map[string]interface{}) ([]HeaderTransformOperation, error) {
	raw := cfg["headers"]
	switch values := raw.(type) {
	case map[string]interface{}:
		return buildOperationsFromMap(action, values), nil
	case map[string]string:
		converted := make(map[string]interface{}, len(values))
		for k, v := range values {
			converted[k] = v
		}
		return buildOperationsFromMap(action, converted), nil
	default:
		header := strings.TrimSpace(getString(cfg, "header"))
		if header == "" {
			return nil, fmt.Errorf("%s action requires headers map or header field", action)
		}
		vals := parseValues(cfg["values"], getString(cfg, "value"))
		if len(vals) == 0 {
			return nil, fmt.Errorf("%s action requires value", action)
		}
		return []HeaderTransformOperation{{Action: action, Header: header, Values: vals}}, nil
	}
}

func buildOperationsFromMap(action string, values map[string]interface{}) []HeaderTransformOperation {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ops := make([]HeaderTransformOperation, 0, len(values))
	for _, key := range keys {
		vals := parseValues(nil, values[key])
		if len(vals) == 0 {
			continue
		}
		op := HeaderTransformOperation{
			Action: action,
			Header: key,
			Values: vals,
		}
		ops = append(ops, op)
	}
	return ops
}

func parseValues(primary interface{}, fallback interface{}) []string {
	var raw interface{}
	if primary != nil {
		raw = primary
	} else {
		raw = fallback
	}

	switch v := raw.(type) {
	case nil:
		return nil
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []string{v}
	case []interface{}:
		var values []string
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				values = append(values, s)
			}
		}
		return values
	case []string:
		var values []string
		for _, s := range v {
			if strings.TrimSpace(s) != "" {
				values = append(values, s)
			}
		}
		return values
	default:
		switch vv := fallback.(type) {
		case string:
			if strings.TrimSpace(vv) != "" {
				return []string{vv}
			}
		case []string:
			return vv
		case []interface{}:
			return parseValues(vv, nil)
		}
	}
	return nil
}

func parseHeaderList(raw interface{}) []string {
	switch v := raw.(type) {
	case []interface{}:
		var headers []string
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				headers = append(headers, s)
			}
		}
		return headers
	case []string:
		var headers []string
		for _, s := range v {
			if strings.TrimSpace(s) != "" {
				headers = append(headers, s)
			}
		}
		return headers
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []string{v}
	default:
		return nil
	}
}

func applyHeaderOperations(ops []HeaderTransformOperation, headers http.Header, renderer templateRenderer) {
	if headers == nil {
		return
	}
	for _, op := range ops {
		switch op.Action {
		case "remove":
			for _, name := range op.Headers {
				canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
				if canonical != "" {
					headers.Del(canonical)
				}
			}
		case "set":
			header := http.CanonicalHeaderKey(strings.TrimSpace(op.Header))
			if header == "" {
				continue
			}
			headers.Del(header)
			for _, value := range op.Values {
				rendered := renderer.render(value)
				if rendered == "" {
					continue
				}
				headers.Add(header, rendered)
			}
		case "add":
			header := http.CanonicalHeaderKey(strings.TrimSpace(op.Header))
			if header == "" {
				continue
			}
			for _, value := range op.Values {
				rendered := renderer.render(value)
				if rendered == "" {
					continue
				}
				headers.Add(header, rendered)
			}
		case "rename":
			from := http.CanonicalHeaderKey(strings.TrimSpace(op.From))
			to := http.CanonicalHeaderKey(strings.TrimSpace(op.To))
			if from == "" || to == "" {
				continue
			}
			values := headers.Values(from)
			headers.Del(from)
			for _, value := range values {
				headers.Add(to, value)
			}
		}
	}
}

// ApplyResponseHeaderTransforms applies staged response header operations.
func ApplyResponseHeaderTransforms(ops []HeaderTransformOperation, headers http.Header, pipelineCtx *domain.PipelineContext) {
	if len(ops) == 0 || headers == nil || pipelineCtx == nil {
		return
	}
	renderer := newTemplateRenderer(pipelineCtx)
	applyHeaderOperations(ops, headers, renderer)
}

type templateRenderer struct {
	values map[string]string
}

func newTemplateRenderer(pctx *domain.PipelineContext) templateRenderer {
	values := map[string]string{}
	if pctx != nil {
		values["agent.id"] = pctx.Request.AgentID
		values["request.method"] = pctx.Request.Method
		values["request.path"] = pctx.Request.Path
		values["request.host"] = pctx.Request.Host
		values["request.protocol"] = pctx.Request.Protocol
		if pctx.Request.SessionID != "" {
			values["request.id"] = pctx.Request.SessionID
			values["session.id"] = pctx.Request.SessionID
		}
		if pctx.Response.Status != 0 {
			values["response.status"] = strconv.Itoa(pctx.Response.Status)
		}

		for key, val := range pctx.Variables {
			switch v := val.(type) {
			case string:
				values["variables."+key] = v
			}
		}

		for name, entries := range pctx.Request.Headers {
			if len(entries) == 0 {
				continue
			}
			canonical := strings.ToLower(strings.TrimSpace(name))
			if canonical == "" {
				continue
			}
			values["request.header."+canonical] = entries[0]
		}
	}

	return templateRenderer{values: values}
}

func (r templateRenderer) render(input string) string {
	if input == "" {
		return ""
	}
	return os.Expand(input, func(key string) string {
		if val, ok := r.values[key]; ok {
			return val
		}
		return ""
	})
}

func inferActionFromType(nodeType string) string {
	lower := strings.ToLower(strings.TrimSpace(nodeType))
	switch {
	case strings.Contains(lower, "rename"):
		return "rename"
	case strings.Contains(lower, "remove"):
		return "remove"
	case strings.Contains(lower, "add"):
		return "add"
	case strings.Contains(lower, "set"):
		return "set"
	default:
		return ""
	}
}

func resolveScope(node *domain.PipelineNode) string {
	if node == nil || node.Config == nil {
		return ""
	}
	return getString(node.Config, "scope")
}

func getString(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if value, ok := m[key]; ok {
		if s, ok := value.(string); ok {
			return s
		}
	}
	// Support camelCase to snake_case fallbacks
	for altKey, altValue := range m {
		if !strings.EqualFold(altKey, key) {
			continue
		}
		if s, ok := altValue.(string); ok {
			return s
		}
	}
	return ""
}
