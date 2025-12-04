package e2e

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/polisai/polis-oss/pkg/domain"
	pipelinepkg "github.com/polisai/polis-oss/pkg/engine"
	"github.com/polisai/polis-oss/pkg/engine/handlers"
)

// TestOpenMeteoWeatherForecast tests basic weather forecast API proxying using standard proxy protocol.
// This test uses the Host header approach (standard HTTP proxy protocol).
func TestOpenMeteoWeatherForecast(t *testing.T) {
	logger := slog.Default()

	registry := pipelinepkg.NewPipelineRegistry(nil)
	executor := pipelinepkg.NewDAGExecutor(pipelinepkg.DAGExecutorConfig{
		Registry: registry,
		Logger:   logger,
	})

	executor.RegisterHandler("egress.http", handlers.NewEgressHTTPHandler(logger))

	// Configure pipeline with proxy mode (standard HTTP proxy protocol)
	pipeline := domain.Pipeline{
		ID:       "openmeteo-weather-pipeline",
		AgentID:  "weather-agent",
		Version:  1,
		Protocol: "http",
		Nodes: []domain.PipelineNode{
			{
				ID:   "egress",
				Type: "egress.http",
				Config: map[string]interface{}{
					"upstream_mode": "proxy", // Use standard proxy protocol
				},
				On: domain.NodeHandlers{
					Success: "",
				},
			},
		},
	}

	_ = registry.UpdatePipelines(context.Background(), []domain.Pipeline{pipeline})

	ctx := context.Background()
	pipelineCtx := &domain.PipelineContext{
		Request: domain.RequestContext{
			Method:    "GET",
			Path:      "/v1/forecast?latitude=52.52&longitude=13.41&hourly=temperature_2m",
			Host:      "api.open-meteo.com",
			Protocol:  "http",
			AgentID:   "weather-agent",
			SessionID: "test-session-1",
			Headers: map[string][]string{
				"Host": {"api.open-meteo.com"},
			},
		},
		Variables: make(map[string]interface{}),
	}

	err := executor.Execute(ctx, "weather-agent", "http", pipelineCtx)
	if err != nil {
		t.Fatalf("Pipeline execution failed: %v", err)
	}

	t.Log("✓ Weather forecast pipeline executed successfully using standard proxy protocol")
}

// TestOpenMeteoGeocodingProxy tests geocoding API proxying using Host header.
func TestOpenMeteoGeocodingProxy(t *testing.T) {
	logger := slog.Default()

	registry := pipelinepkg.NewPipelineRegistry(nil)
	executor := pipelinepkg.NewDAGExecutor(pipelinepkg.DAGExecutorConfig{
		Registry: registry,
		Logger:   logger,
	})

	executor.RegisterHandler("egress.http", handlers.NewEgressHTTPHandler(logger))

	pipeline := domain.Pipeline{
		ID:       "openmeteo-geocoding-pipeline",
		AgentID:  "geocoding-agent",
		Version:  1,
		Protocol: "http",
		Nodes: []domain.PipelineNode{
			{
				ID:   "egress",
				Type: "egress.http",
				Config: map[string]interface{}{
					"upstream_mode": "proxy",
				},
				On: domain.NodeHandlers{
					Success: "",
				},
			},
		},
	}

	_ = registry.UpdatePipelines(context.Background(), []domain.Pipeline{pipeline})

	ctx := context.Background()
	pipelineCtx := &domain.PipelineContext{
		Request: domain.RequestContext{
			Method:    "GET",
			Path:      "/v1/search?name=Tokyo&count=3&language=en&format=json",
			Host:      "geocoding-api.open-meteo.com",
			Protocol:  "http",
			AgentID:   "geocoding-agent",
			SessionID: "test-session-2",
			Headers: map[string][]string{
				"Host": {"geocoding-api.open-meteo.com"},
			},
		},
		Variables: make(map[string]interface{}),
	}

	err := executor.Execute(ctx, "geocoding-agent", "http", pipelineCtx)
	if err != nil {
		t.Fatalf("Pipeline execution failed: %v", err)
	}

	t.Log("✓ Geocoding pipeline executed successfully using standard proxy protocol")
}

// TestOpenMeteoDirectAPI validates direct API calls for baseline comparison.
func TestOpenMeteoDirectAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping direct API test in short mode")
	}

	client := &http.Client{Timeout: 30 * time.Second}

	t.Run("weather_forecast", func(t *testing.T) {
		resp, err := client.Get("https://api.open-meteo.com/v1/forecast?latitude=52.52&longitude=13.41&current=temperature_2m")
		if err != nil {
			t.Fatalf("Direct API request failed: %v", err)
		}
		defer func() {
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
		}()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("Failed to parse JSON: %v", err)
		}

		if _, ok := result["latitude"]; !ok {
			t.Error("Response missing latitude field")
		}

		t.Logf("✓ Direct weather API call successful (%d bytes)", len(body))
	})

	t.Run("geocoding", func(t *testing.T) {
		resp, err := client.Get("https://geocoding-api.open-meteo.com/v1/search?name=Berlin&count=1")
		if err != nil {
			t.Fatalf("Direct geocoding request failed: %v", err)
		}
		defer func() {
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
		}()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("Failed to parse JSON: %v", err)
		}

		results, ok := result["results"].([]interface{})
		if !ok || len(results) == 0 {
			t.Error("No geocoding results found")
		}

		t.Logf("✓ Direct geocoding API call successful (found %d results)", len(results))
	})
}
