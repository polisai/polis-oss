package handlers

import (
	"net/http"
	"testing"
)

func TestApplyStripHeaders_RemovesConfiguredHeaders(t *testing.T) {
	headers := http.Header{
		"Authorization": []string{"Bearer abc"},
		"Content-Type":  []string{"application/json"},
	}

	config := map[string]interface{}{
		"strip_headers": []interface{}{"authorization"},
	}

	removed := applyStripHeaders(config, headers)
	if removed != 1 {
		t.Fatalf("expected 1 header removed, got %d", removed)
	}

	if headers.Get("Authorization") != "" {
		t.Fatalf("expected authorization header to be removed")
	}
	if headers.Get("Content-Type") == "" {
		t.Fatalf("content-type header should remain")
	}
}

func TestExtractStripHeadersSupportsStringValue(t *testing.T) {
	config := map[string]interface{}{
		"strip_headers": "X-Test",
	}

	result := extractStripHeaders(config)
	if len(result) != 1 || result[0] != "X-Test" {
		t.Fatalf("expected single header X-Test, got %v", result)
	}
}
