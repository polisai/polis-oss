package sidecar

import (
	"context"
)

type mockMetrics struct{}

func (m *mockMetrics) UpdateProcessStatus(c string, r bool) {}

type mockTracer struct{}

func (t *mockTracer) InjectProcessEnv(ctx context.Context, env []string) []string { return env }
