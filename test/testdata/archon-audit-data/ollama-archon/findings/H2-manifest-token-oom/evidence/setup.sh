#!/usr/bin/env bash
# evidence/setup.sh — environment provisioning for H2 manifest-token-oom PoC
set -euo pipefail

echo "=== H2 manifest-token-oom — environment setup ==="
echo "date: $(date -u)"
echo "host: $(uname -a)"

# Verify Go toolchain
echo ""
echo "--- Go toolchain ---"
go version

# Verify we are inside the ollama repo
REPO_ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null || echo 'unknown')"
echo "repo root: $REPO_ROOT"
echo "commit: $(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo 'unknown')"

# Confirm vulnerable sinks present in the source tree
echo ""
echo "--- Sink presence check ---"
MANIFEST_SINK=$(grep -n 'io.ReadAll(resp.Body)' "$REPO_ROOT/server/images.go" | head -5)
TOKEN_SINK=$(grep -n 'io.ReadAll(response.Body)' "$REPO_ROOT/server/auth.go" | head -5)

echo "server/images.go  io.ReadAll sinks:"
echo "  $MANIFEST_SINK"
echo "server/auth.go    io.ReadAll sinks:"
echo "  $TOKEN_SINK"

# Confirm absence of LimitReader / MaxBytesReader in the registry-fetch path
echo ""
echo "--- LimitReader / MaxBytesReader absence in server/ ---"
LIMIT_HITS=$(grep -rn 'LimitReader\|MaxBytesReader' "$REPO_ROOT/server/" \
    --include='*.go' \
    | grep -v 'cloud_proxy\|cache/blob' || true)
if [ -z "$LIMIT_HITS" ]; then
    echo "  CONFIRMED: no LimitReader or MaxBytesReader on registry response paths"
else
    echo "  WARNING — unexpected hit(s):"
    echo "  $LIMIT_HITS"
fi

echo ""
echo "--- Setup complete ---"
