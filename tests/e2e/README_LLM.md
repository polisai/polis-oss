# LLM E2E Tests for Secure AI Proxy

This directory contains end-to-end (e2e) tests that simulate AI agents calling Large Language Model (LLM) APIs through the proxy.

## Overview

The LLM e2e tests validate that the Secure AI Proxy correctly handles realistic AI agent workloads, specifically:

- **Streaming responses**: Server-Sent Events (SSE) from OpenAI and Anthropic APIs
- **Non-streaming responses**: Standard JSON responses
- **Error handling**: Rate limits, invalid requests, and service errors
- **Concurrency**: Multiple agents making simultaneous requests
- **Performance**: First-token latency and buffering behavior
- **Telemetry**: Capturing AI/agent-specific metadata

## Authentication Note

Despite the "NoAuth" naming in test functions, these tests use JWT authentication. The proxy architecture requires JWT validation at the middleware level. The tests use a test JWKS server to generate valid tokens. This simulates AI agents that authenticate with the proxy using service account tokens.

## Test Files

### `llm_test.go`
Contains all LLM-specific e2e tests:

- **`TestE2E_LLM_OpenAI_StreamingNoAuth`**: Tests OpenAI-style SSE streaming with JWT auth
- **`TestE2E_LLM_Anthropic_StreamingNoAuth`**: Tests Anthropic Claude-style SSE streaming
- **`TestE2E_LLM_LargeResponseNoBuffering`**: Validates no buffering occurs on large responses
- **`TestE2E_LLM_ErrorHandling`**: Tests error response forwarding (rate limits, overload, invalid requests)
- **`TestE2E_LLM_ConcurrentRequests`**: Simulates 10 concurrent agent requests
- **`TestE2E_LLM_NonStreaming`**: Tests standard JSON completions
- **`TestE2E_LLM_TelemetryCapture`**: Validates telemetry collection with agent metadata

### `mock_llm.go`
Reusable mock LLM server that simulates both OpenAI and Anthropic APIs:

- **OpenAI format**:
  - Endpoint: `/v1/chat/completions`
  - Streaming: SSE with `data:` lines containing JSON chunks
  - Terminator: `data: [DONE]`

- **Anthropic format**:
  - Endpoint: `/v1/messages`
  - Streaming: SSE with typed events (`message_start`, `content_block_delta`, `message_stop`)
  - Includes ping events for keepalive

- **Error simulation**:
  - Endpoint: `/error?type=<error_type>`
  - Types: `rate_limit`, `invalid_request`, `overloaded`

## Running the Tests

### Run all LLM tests
```pwsh
go test ./tests/e2e -run TestE2E_LLM -v
```

### Run specific test
```pwsh
go test ./tests/e2e -run TestE2E_LLM_OpenAI_StreamingNoAuth -v
```

### Run with race detector
```pwsh
go test ./tests/e2e -run TestE2E_LLM -race -v
```

### Run with coverage
```pwsh
go test ./tests/e2e -run TestE2E_LLM -cover -coverprofile=tests/coverage/llm-e2e.out
```

## Test Scenarios

### 1. OpenAI-Style Streaming (GPT-4)

**Scenario**: AI agent calls OpenAI chat completions API with streaming enabled.

**Request**:
```json
{
  "model": "gpt-4",
  "messages": [
    {"role": "user", "content": "Hello, AI!"}
  ],
  "stream": true
}
```

**Response Format** (SSE):
```
data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1234567890,"model":"gpt-4","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}

data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1234567890,"model":"gpt-4","choices":[{"index":0,"delta":{"content":" from"},"finish_reason":null}]}

...

data: [DONE]
```

**Validations**:
- ✅ Response is `text/event-stream`
- ✅ Tokens arrive incrementally
- ✅ First token latency < 500ms (no buffering)
- ✅ Request forwarded to upstream
- ✅ No authentication required

### 2. Anthropic-Style Streaming (Claude)

**Scenario**: AI agent calls Anthropic messages API with streaming enabled.

**Request**:
```json
{
  "model": "claude-sonnet-4-5",
  "messages": [
    {"role": "user", "content": "Hello, Claude!"}
  ],
  "max_tokens": 1024,
  "stream": true
}
```

**Response Format** (SSE):
```
event: message_start
data: {"type":"message_start","message":{...}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: ping
data: {"type":"ping"}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}

...

event: message_stop
data: {"type":"message_stop"}
```

**Validations**:
- ✅ Response is `text/event-stream`
- ✅ Receives `message_start` and `message_stop` events
- ✅ Text deltas arrive incrementally
- ✅ First delta latency < 500ms
- ✅ Proper SSE event type parsing

### 3. Error Handling

**Scenarios**:
- **Rate Limit**: Returns 429 with rate_limit_error
- **Invalid Request**: Returns 400 with invalid_request_error
- **Overloaded**: Returns 503 with server_error

**Validations**:
- ✅ Status codes correctly forwarded
- ✅ Error response structure preserved
- ✅ Error types match expectations

### 4. Concurrent Requests

**Scenario**: 10 AI agents simultaneously call LLM API through proxy.

**Validations**:
- ✅ All requests complete successfully
- ✅ No connection failures
- ✅ Responses remain independent
- ✅ Performance remains acceptable under load

## JWT Authentication in Tests

These tests use JWT authentication via a test JWKS server. The "NoAuth" naming is historical and refers to the use case of AI agents calling LLMs, where:
1. Agents authenticate via service account JWTs
2. The proxy enforces JWT validation at the middleware level
3. No user-specific authentication is required

**Test JWKS Configuration**:
```go
// Create test JWKS server
jwks := integration.NewTestJWKS(t)
t.Cleanup(jwks.Close)

// Generate valid JWT token
token := jwks.CreateToken(t, jwt.MapClaims{
    "sub": "ai-agent-123",
    "aud": []any{"llm-test-audience"},
})

// Use token in requests
req.Header.Set("Authorization", "Bearer "+token)
```

**Bootstrap Config**:
```yaml
generation: 1
rawPolicies:
  - id: policy-passthrough
    name: Passthrough (No Auth)
routes:
  - id: route-llm
    match:
      path: /
      methods: [GET, POST, PUT, DELETE]
    upstream:
      scheme: http
      host: 127.0.0.1
      port: <dynamic>
    policyID: policy-passthrough
```

## Architecture

```
┌─────────────┐                ┌─────────────┐                ┌─────────────┐
│ Test Client │───────────────▶│ Proxy (JWT  │───────────────▶│ Mock LLM    │
│ (AI Agent)  │   HTTP/SSE     │ Auth Mode)  │   HTTP/SSE     │ Server      │
│ + JWT Token │                │ + JWKS      │                │             │
└─────────────┘                └─────────────┘                └─────────────┘
                                      │
                                      │ OTLP
                                      ▼
                              ┌─────────────┐
                              │ Mock OTLP   │
                              │ Collector   │
                              └─────────────┘
```

## Performance Expectations

Based on proxy requirements (NFR-D-001, NFR-D-002):

- **Latency**: < 10ms p99 overhead for passthrough
- **Throughput**: 5,000 RPS per instance baseline
- **First Token**: < 500ms from request start (no buffering)
- **Memory**: < 150MB steady state
- **CPU**: < 0.50 vCPU baseline

## Future Enhancements

### Planned Tests
- [ ] **Mixed Auth**: Test authenticated and unauthenticated routes in same proxy
- [ ] **Protocol Detection**: Validate protocol.name telemetry attribute
- [ ] **Cost Tracking**: Verify resource.cost_usd attribute calculation
- [ ] **WebSocket**: Add WebSocket upgrade tests
- [ ] **HTTP/2**: Explicit HTTP/2 streaming tests
- [ ] **Load Testing**: Sustained 5,000 RPS validation

### Mock LLM Enhancements
- [ ] Function calling / tool use simulation
- [ ] Extended thinking (chain-of-thought) streaming
- [ ] Token usage tracking
- [ ] Cost estimation
- [ ] Configurable response patterns

## Troubleshooting

### Test fails with "proxy did not become ready"
- Check `tmp/e2e/secure-ai-proxy` binary exists
- Review proxy logs in test output
- Verify bootstrap config is valid YAML

### First chunk latency > 500ms
- Indicates buffering is occurring in proxy
- Check reverse proxy configuration
- Verify streaming middleware is not buffering

### No telemetry spans captured
- Authentication disabled mode may not wire telemetry fully
- Check OTLP endpoint configuration
- Verify OpenTelemetry SDK initialization

### Concurrent test failures
- Check for resource exhaustion (file descriptors)
- Verify proxy handles concurrent connections
- Review error messages for specific failures

## References

- **OpenAI API**: https://platform.openai.com/docs/api-reference/streaming
- **Anthropic API**: https://docs.anthropic.com/en/api/messages-streaming
- **Server-Sent Events**: https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events
- **Proxy Requirements**: `docs/proxy-requirements.md`
- **Proxy Architecture**: `docs/proxy-architecture-overview.md`
- **E2E Test Harness**: `tests/e2e/harness.go`

---

Last Updated: 2025-10-31
Status: Active Development
