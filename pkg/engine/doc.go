// Package engine implements DAG-based pipeline execution for AI agent requests.
//
// Architecture:
//
// executor.go         - Core DAG execution engine (DAGExecutor, node traversal, handler registry)
// handlers_builtin.go - Built-in terminal handlers (Passthrough, Deny, Error)
// http_handler.go     - HTTP integration layer (DAGHandler, ServeHTTP, egress HTTP client)
// config.go           - Pipeline registry and configuration management
// simulator.go        - Pipeline simulation for testing and validation
//
// The pipeline package is responsible for routing agent requests through configurable
// DAG pipelines that enforce authentication, policy, DLP, WAF, and governance controls.
package engine
