#!/usr/bin/env bash
# Setup: verify Go toolchain and Ollama source tree are available.
# evidence/ is at <repo>/archon/findings/<ID>/evidence/
# so repo root is four levels up from evidence/
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../../../.." && pwd)"
echo "Repo root: $REPO"
go version
echo "Module: $(head -1 "$REPO/go.mod")"
echo "Commit: $(git -C "$REPO" rev-parse HEAD)"
echo "Relevant source files:"
ls -lh "$REPO/fs/ggml/ggml.go" "$REPO/fs/ggml/gguf.go" "$REPO/server/quantization.go" "$REPO/ml/backend/ggml/quantization.go"
echo "Setup OK"
