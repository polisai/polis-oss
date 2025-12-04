package e2e

import (
	"context"
	"net"
	"sync"
	"testing"

	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"
)

type mockTraceCollector struct {
	collectortrace.UnimplementedTraceServiceServer

	t             *testing.T
	mu            sync.Mutex
	resourceSpans []*tracepb.ResourceSpans
	notify        chan struct{}
}

func startMockTraceCollector(t *testing.T) (*mockTraceCollector, string) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start OTLP listener: %v", err)
	}

	collector := &mockTraceCollector{
		notify: make(chan struct{}, 1),
		t:      t,
	}

	server := grpc.NewServer()
	collectortrace.RegisterTraceServiceServer(server, collector)

	go func() {
		_ = server.Serve(lis)
	}()

	t.Cleanup(func() {
		server.Stop()
		_ = lis.Close()
	})

	return collector, lis.Addr().String()
}

func (m *mockTraceCollector) Export(_ context.Context, req *collectortrace.ExportTraceServiceRequest) (*collectortrace.ExportTraceServiceResponse, error) {
	m.mu.Lock()
	m.resourceSpans = append(m.resourceSpans, req.ResourceSpans...)
	m.mu.Unlock()

	if m.t != nil {
		m.t.Logf("received %d resource spans", len(req.ResourceSpans))
	}

	select {
	case m.notify <- struct{}{}:
	default:
	}

	return &collectortrace.ExportTraceServiceResponse{}, nil
}

func (m *mockTraceCollector) WaitForSpans(ctx context.Context, minSpans int) []*tracepb.Span {
	for {
		m.mu.Lock()
		if len(m.resourceSpans) >= minSpans {
			spans := flattenResourceSpans(m.resourceSpans)
			m.mu.Unlock()
			return spans
		}
		m.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil
		case <-m.notify:
		}
	}
}

func (m *mockTraceCollector) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resourceSpans = nil
}

func flattenResourceSpans(resSpans []*tracepb.ResourceSpans) []*tracepb.Span {
	var spans []*tracepb.Span
	for _, rs := range resSpans {
		for _, scope := range rs.ScopeSpans {
			spans = append(spans, scope.Spans...)
		}
	}
	return spans
}
