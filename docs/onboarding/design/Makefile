# Makefile for Polis Quickstart (Archived)

.PHONY: help quickstart quickstart-docker quickstart-local quickstart-k8s clean logs

help:
	@echo "================================"
	@echo "  Polis Quickstart Commands"
	@echo "================================"
	@echo ""
	@echo "Choose your path:"
	@echo ""
	@echo "  make quickstart-docker    - Option A: Docker Compose (Recommended, 2 min)"
	@echo "  make quickstart-local     - Option B: Local Binary (No Docker, 3 min)"
	@echo "  make quickstart-k8s       - Option C: Kubernetes (Production-parity, 4 min)"
	@echo ""
	@echo "Utilities:"
	@echo "  make logs                 - Tail logs from all services"
	@echo "  make clean                - Stop and remove all containers"
	@echo "  make openapi              - Generate OpenAPI docs"
	@echo ""

quickstart-docker:
	@echo "🚀 Starting Polis with Docker Compose..."
	docker compose -f quickstart/compose.http-proxy.yaml up

quickstart-local:
	@echo "This target depends on sample agent + UI assets (not included in OSS core)."

quickstart-k8s:
	@echo "This target depends on external images and K8s manifests (archived)."

logs:
	docker compose -f quickstart/compose.http-proxy.yaml logs -f

clean:
	docker compose -f quickstart/compose.http-proxy.yaml down -v

.DEFAULT_GOAL := help

