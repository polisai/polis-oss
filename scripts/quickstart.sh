#!/usr/bin/env bash
set -euo pipefail

exec docker compose -f quickstart/compose.http-proxy.yaml up --build
