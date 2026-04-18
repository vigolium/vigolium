#!/usr/bin/env bash
# Environment provisioning for H1-api-pull-ssrf PoC
# Uses the in-tree Go test environment (no external service required).
set -euo pipefail

echo "[setup] working directory: $(pwd)"
echo "[setup] go version: $(go version)"
echo "[setup] module: $(go env GOMOD)"
echo "[setup] git commit: $(git -C /Users/bytedance/Desktop/demo/ollama rev-parse HEAD)"
echo "[setup] branch: $(git -C /Users/bytedance/Desktop/demo/ollama rev-parse --abbrev-ref HEAD)"
echo "[setup] build check (compile only, no run)..."
go build -v ./server/ 2>&1 | tail -5
echo "[setup] done"
