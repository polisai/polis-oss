package engine

import (
	"fmt"
	"log/slog"
	"net/textproto"
	"strings"

	"github.com/polisai/polis-oss/pkg/domain"
)

type triggerMatcher struct {
	logger *slog.Logger
}

type triggerMatchResult struct {
	Matched       bool
	TriggerType   string
	TriggerIndex  int
	Streaming     bool
	StreamingMode string
	Labels        map[string]string
}

func newTriggerMatcher(logger *slog.Logger) *triggerMatcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &triggerMatcher{logger: logger}
}

func (m *triggerMatcher) Match(pipeline *domain.Pipeline, pipelineCtx *domain.PipelineContext) triggerMatchResult {
	if pipeline == nil || pipelineCtx == nil {
		return triggerMatchResult{}
	}

	for idx, trigger := range pipeline.Triggers {
		matched, labels := m.matchTrigger(trigger, pipelineCtx)
		if !matched {
			continue
		}

		streaming, mode := m.deriveStreaming(trigger, pipelineCtx)
		if !streaming {
			streaming = pipelineCtx.Request.Streaming
			if streaming && mode == "" {
				mode = pipelineCtx.Request.StreamingMode
			}
		}

		return triggerMatchResult{
			Matched:       true,
			TriggerType:   trigger.Type,
			TriggerIndex:  idx,
			Streaming:     streaming,
			StreamingMode: mode,
			Labels:        labels,
		}
	}

	return triggerMatchResult{}
}

func (m *triggerMatcher) matchTrigger(trigger domain.Trigger, pipelineCtx *domain.PipelineContext) (bool, map[string]string) {
	switch strings.ToLower(trigger.Type) {
	case "http.request":
		return m.matchHTTPTrigger(trigger.Match, pipelineCtx)
	case "session.start":
		// Session triggers are considered matched at start.
		return true, map[string]string{"type": "session.start"}
	default:
		// Unsupported trigger types are treated as non-matching for now.
		return false, nil
	}
}

func (m *triggerMatcher) matchHTTPTrigger(match map[string]interface{}, pipelineCtx *domain.PipelineContext) (bool, map[string]string) {
	if pipelineCtx == nil {
		return false, nil
	}

	labels := make(map[string]string)
	if match == nil {
		return true, labels
	}

	if rawMethod, ok := match["method"]; ok {
		expectedMethods := toStringSlice(rawMethod)
		if len(expectedMethods) > 0 {
			actualMethod := strings.ToUpper(pipelineCtx.Request.Method)
			if !valueInSlice(actualMethod, expectedMethods, true) {
				return false, nil
			}
			labels["method"] = actualMethod
		}
	}

	if rawHeaders, ok := match["headers"]; ok {
		headerMap, ok := rawHeaders.(map[string]interface{})
		if !ok {
			return false, nil
		}
		for name, expected := range headerMap {
			expectedValues := toStringSlice(expected)
			if len(expectedValues) == 0 {
				continue
			}
			actualValues := headerValues(pipelineCtx.Request.Headers, name)
			if len(actualValues) == 0 {
				return false, nil
			}
			if !headerValueMatches(name, actualValues, expectedValues) {
				return false, nil
			}
			labels[strings.ToLower(name)] = actualValues[0]
		}
	}

	return true, labels
}

func (m *triggerMatcher) deriveStreaming(trigger domain.Trigger, pipelineCtx *domain.PipelineContext) (bool, string) {
	if pipelineCtx == nil {
		return false, ""
	}

	if trigger.Match != nil {
		if rawStreaming, ok := trigger.Match["streaming"]; ok {
			if enabled, ok := rawStreaming.(bool); ok && enabled {
				return true, ""
			}
		}
	}

	if headers := pipelineCtx.Request.Headers; headers != nil {
		if values := headerValues(headers, "Accept"); len(values) > 0 {
			for _, v := range values {
				if strings.Contains(strings.ToLower(v), "text/event-stream") {
					return true, "sse"
				}
			}
		}
		if values := headerValues(headers, "Upgrade"); len(values) > 0 {
			for _, v := range values {
				if strings.EqualFold(v, "websocket") {
					return true, "websocket"
				}
			}
		}
	}

	return false, ""
}

func toStringSlice(value interface{}) []string {
	switch v := value.(type) {
	case nil:
		return nil
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []string:
		return v
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				if strings.TrimSpace(s) == "" {
					continue
				}
				result = append(result, s)
			}
		}
		return result
	default:
		return []string{strings.TrimSpace(fmt.Sprintf("%v", v))}
	}
}

func valueInSlice(value string, candidates []string, caseInsensitive bool) bool {
	for _, candidate := range candidates {
		if caseInsensitive {
			if strings.EqualFold(candidate, value) {
				return true
			}
		} else if candidate == value {
			return true
		}
	}
	return false
}

func headerValues(headers map[string][]string, name string) []string {
	if headers == nil {
		return nil
	}

	canonical := textproto.CanonicalMIMEHeaderKey(name)
	if values, ok := headers[canonical]; ok && len(values) > 0 {
		return values
	}

	for k, values := range headers {
		if strings.EqualFold(k, name) && len(values) > 0 {
			return values
		}
	}
	return nil
}

func headerValueMatches(name string, actual, expected []string) bool {
	if len(expected) == 0 {
		return true
	}

	lowerName := strings.ToLower(name)
	for _, want := range expected {
		want = strings.TrimSpace(want)
		if want == "" {
			continue
		}
		for _, have := range actual {
			if lowerName == "accept" {
				if strings.Contains(strings.ToLower(have), strings.ToLower(want)) {
					return true
				}
			} else if strings.EqualFold(have, want) {
				return true
			}
		}
	}
	return false
}
