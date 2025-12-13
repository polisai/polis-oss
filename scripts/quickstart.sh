#!/usr/bin/env bash
set -euo pipefail

exec docker compose -f quickstart/compose.polis.yaml up --build
