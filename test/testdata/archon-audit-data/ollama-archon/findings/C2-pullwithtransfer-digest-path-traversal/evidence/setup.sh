#!/usr/bin/env bash
# Evidence: environment setup for C1 PoC
# Requires: Go 1.21+, Python 3.9+
# Platform: Linux / macOS (darwin)
set -euo pipefail

REPO_ROOT="/Users/bytedance/Desktop/demo/ollama"
LOG_DIR="$(dirname "$0")"

echo "[setup] Platform: $(uname -s) $(uname -m)"
echo "[setup] Go: $(go version 2>/dev/null || echo 'not found')"
echo "[setup] Python: $(python3 --version 2>/dev/null || echo 'not found')"
echo "[setup] Repo HEAD: $(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo 'unknown')"

# Confirm vulnerable functions exist at expected lines
echo ""
echo "[setup] Verifying vulnerable symbols ..."

grep -n "blobs\[i\] = transfer.Blob{" "$REPO_ROOT/server/images.go" | head -3
grep -n "func digestToPath" "$REPO_ROOT/x/imagegen/transfer/transfer.go"
grep -n "os.MkdirAll(filepath.Dir(dest)" "$REPO_ROOT/x/imagegen/transfer/download.go"
grep -n "if blob.Size < resumeThreshold" "$REPO_ROOT/x/imagegen/transfer/download.go"

echo ""
echo "[setup] Key constants:"
grep -n "resumeThreshold\s*=" "$REPO_ROOT/x/imagegen/transfer/transfer.go"

echo ""
echo "[setup] BlobsPath regex (the guard that pullWithTransfer bypasses):"
grep -A5 "func BlobsPath" "$REPO_ROOT/manifest/paths.go" | head -8

echo ""
echo "[setup] Confirming BlobsPath is NOT called per-layer in pullWithTransfer:"
# Should show only one call with "" (directory root), never with layer.Digest
grep -n "BlobsPath" "$REPO_ROOT/server/images.go" | grep -A2 -B2 "pullWithTransfer" || true
awk '/func pullWithTransfer/,/^}/' "$REPO_ROOT/server/images.go" | grep "BlobsPath"

echo ""
echo "[setup] Setup complete." | tee "$LOG_DIR/setup.log"
