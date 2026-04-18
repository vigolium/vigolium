#!/usr/bin/env bash
# H11 environment setup
# Provisions a minimal Ollama instance with a CLIP-projected vision model.
# Requires: docker, ~4 GB disk, internet access to pull the model.
set -euo pipefail

OLLAMA_HOST="http://127.0.0.1:11434"
MODEL="llava:7b"   # smallest widely-available CLIP-projected model
EVIDENCE_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[setup] Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[setup] Host OS: $(uname -srm)"
echo "[setup] Model target: $MODEL"

# ---- Option A: use an already-running local Ollama -------------------
if curl -sf "${OLLAMA_HOST}/api/tags" >/dev/null 2>&1; then
    echo "[setup] Existing Ollama detected at ${OLLAMA_HOST}"
    echo "[setup] Pulling ${MODEL} if not present ..."
    ollama pull "${MODEL}" 2>&1 | tee -a "${EVIDENCE_DIR}/setup.log"
    echo "[setup] DONE (local Ollama)" | tee -a "${EVIDENCE_DIR}/setup.log"
    exit 0
fi

# ---- Option B: Docker container --------------------------------------
echo "[setup] No local Ollama found. Attempting Docker ..."
docker pull ollama/ollama:latest 2>&1 | tee -a "${EVIDENCE_DIR}/setup.log"

docker run -d \
    --name ollama-h11-poc \
    -p 11434:11434 \
    -v ollama-h11-data:/root/.ollama \
    ollama/ollama:latest \
    2>&1 | tee -a "${EVIDENCE_DIR}/setup.log"

echo "[setup] Waiting for Ollama to start ..."
for i in $(seq 1 30); do
    if curl -sf "${OLLAMA_HOST}/api/tags" >/dev/null 2>&1; then
        echo "[setup] Ollama ready after ${i}s"
        break
    fi
    sleep 1
done

echo "[setup] Pulling ${MODEL} ..."
docker exec ollama-h11-poc ollama pull "${MODEL}" 2>&1 | tee -a "${EVIDENCE_DIR}/setup.log"

echo "[setup] DONE (Docker)" | tee -a "${EVIDENCE_DIR}/setup.log"
