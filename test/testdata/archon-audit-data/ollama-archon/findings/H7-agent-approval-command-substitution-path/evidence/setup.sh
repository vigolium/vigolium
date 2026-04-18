#!/usr/bin/env bash
# H21 — environment setup
# Verifies the ollama source tree is present and the x/agent package compiles.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
echo "=== H21 Environment Setup ==="
echo "repo: $REPO_ROOT"
echo "date: $(date -u)"
echo "go:   $(go version)"

cd "$REPO_ROOT"
echo ""
echo "--- go build x/agent ---"
go build ./x/agent/
echo "--- go build x/tools ---"
go build ./x/tools/
echo "--- existing agent tests ---"
go test ./x/agent/ -run TestApproval -v 2>&1 | tail -20
echo ""
echo "=== Setup OK ==="
