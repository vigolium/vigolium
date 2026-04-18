#!/usr/bin/env bash
# H5 PoC environment setup
# No Docker needed: tests run directly against the ollama source tree.
set -euo pipefail

REPO="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
echo "[setup] repo root: $REPO"
echo "[setup] Go version: $(go version)"
echo "[setup] commit: $(git -C "$REPO" rev-parse HEAD)"
go build ./... 2>&1 | head -20 && echo "[setup] build OK"
