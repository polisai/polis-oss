package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"log/slog"

	"github.com/polisai/polis-oss/pkg/domain"
)

func TestDAGHandler_buildPipelineContext_MetadataHeaders(t *testing.T) {
	h := &DAGHandler{
		logger: slog.Default(),
	}
	req := httptest.NewRequest("POST", "http://proxy.local/tickets", http.NoBody)
	req.Header.Set(HeaderAgentSubject, "agent@example.com")
	req.Header.Set(HeaderAgentIssuer, "https://issuer.example.com")
	req.Header.Set(HeaderAgentAudience, "api://primary,api://support")
	req.Header.Set(HeaderAgentScopes, "support-leads,triage")
	req.Header.Set(HeaderSessionTokensIn, "1500")
	req.Header.Set(HeaderSessionTokensOut, "2000")
	req.Header.Set(HeaderSessionEstimatedCostUSD, "1.25")
	req.Header.Set("Authorization", "Bearer demo")

	ctx := h.buildPipelineContext(req, "multi-policy-agent")

	if got := ctx.Variables["auth.subject"]; got != "agent@example.com" {
		t.Fatalf("unexpected subject: %v", got)
	}
	if got := ctx.Variables["auth.issuer"]; got != "https://issuer.example.com" {
		t.Fatalf("unexpected issuer: %v", got)
	}

	audiences, ok := ctx.Variables["auth.audiences"].([]string)
	if !ok || len(audiences) != 2 {
		t.Fatalf("expected two audiences, got %v", ctx.Variables["auth.audiences"])
	}

	scopes, ok := ctx.Variables["auth.scopes"].([]string)
	if !ok || len(scopes) != 2 {
		t.Fatalf("expected two scopes, got %v", ctx.Variables["auth.scopes"])
	}

	if ctx.Session.TotalTokensIn != 1500 {
		t.Fatalf("unexpected tokens in: %d", ctx.Session.TotalTokensIn)
	}
	if ctx.Session.TotalTokensOut != 2000 {
		t.Fatalf("unexpected tokens out: %d", ctx.Session.TotalTokensOut)
	}
	if ctx.Session.EstimatedCostUSD != 1.25 {
		t.Fatalf("unexpected cost: %f", ctx.Session.EstimatedCostUSD)
	}

	if _, ok := ctx.Request.Headers[HeaderAgentSubject]; ok {
		t.Fatalf("identity header should have been stripped")
	}
	if _, ok := ctx.Request.Headers[HeaderSessionTokensIn]; ok {
		t.Fatalf("session header should have been stripped")
	}
	if _, ok := ctx.Request.Headers["Authorization"]; !ok {
		t.Fatalf("authorization header should remain")
	}
}

func TestDAGHandler_writeDirectResponse_Deny(t *testing.T) {
	h := &DAGHandler{
		logger: slog.Default(),
	}
	rec := httptest.NewRecorder()
	pctx := &domain.PipelineContext{
		Response: domain.ResponseContext{
			Status: http.StatusForbidden,
			Headers: map[string][]string{
				"X-Policy": {"access"},
			},
		},
		Security: domain.SecurityContext{
			Blocked:     true,
			BlockReason: "ACCESS_DENIED",
		},
		Variables: map[string]interface{}{
			responseErrorCodeKey:    "ACCESS_DENIED",
			responseErrorMessageKey: "Access denied by policy",
		},
	}

	h.writeDirectResponse(context.Background(), rec, pctx)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rec.Code)
	}
	if rec.Header().Get("X-Policy") != "access" {
		t.Fatalf("expected header passthrough")
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}

	errorObj, ok := body["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected nested error object, got: %v", body)
	}

	if errorObj["code"] != "ACCESS_DENIED" {
		t.Fatalf("unexpected error code: %v", errorObj["code"])
	}

	if errorObj["message"] != "Access denied by policy" {
		t.Fatalf("unexpected error message: %v", errorObj["message"])
	}
}

func TestDAGHandler_writeDirectResponse_Success(t *testing.T) {
	h := &DAGHandler{
		logger: slog.Default(),
	}
	rec := httptest.NewRecorder()
	pctx := &domain.PipelineContext{
		Response: domain.ResponseContext{
			Status: http.StatusAccepted,
			Headers: map[string][]string{
				"X-Custom": {"demo"},
			},
		},
	}

	h.writeDirectResponse(context.Background(), rec, pctx)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected status 202, got %d", rec.Code)
	}
	if rec.Header().Get("X-Custom") != "demo" {
		t.Fatalf("expected custom header to be forwarded")
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("expected empty body for success response")
	}
}
