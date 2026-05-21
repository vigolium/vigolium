#!/usr/bin/env bash
# Setup: install DOMPurify 3.2.4 (vulnerable) and jsdom for PoC execution
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
mkdir -p node_modules
npm install --prefix . dompurify@3.2.4 jsdom 2>&1
echo "Setup complete. DOMPurify version: $(node -e "require('./node_modules/dompurify'); console.log('installed')")"
