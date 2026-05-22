#!/usr/bin/env bash
set +e
SESSION="00000000-0000-4000-8000-000000000000"
# Remove labelled containers if Docker is available
docker ps -aq --filter "label=archon.session=$SESSION" 2>/dev/null | xargs -r docker rm -f >/dev/null 2>&1
# Kill app pid if provisioner writes one
if [ -f "/Users/<user>/Desktop/oss-to-run/acme/archon/confirm-workspace/app.pid" ]; then
  kill "$(cat "/Users/<user>/Desktop/oss-to-run/acme/archon/confirm-workspace/app.pid")" >/dev/null 2>&1 || true
fi
rm -f "/Users/<user>/Desktop/oss-to-run/acme/archon/confirm-workspace/.lock"
