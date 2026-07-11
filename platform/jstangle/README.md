<p align="center">
  <a href="https://github.com/vigolium"><img alt="Vigolium" src="https://avatars.githubusercontent.com/u/266502139?s=200&v=4" height="140" /></a>
  <br />
  <strong>Vigolium - High-fidelity vulnerability scanner with native scan precision and agentic scan intelligence.</strong>
  <br />

  <p align="center"><a href="https://www.vigolium.com">www.vigolium.com</a> - <a href="https://docs.vigolium.com"> docs.vigolium.com</a></p>
</p>

# jstangle

`jstangle` is the JavaScript intelligence engine inside [Vigolium](https://www.vigolium.com/). It deobfuscates and beautifies real-world JavaScript, parses it into an AST, and mines the result for the things that matter to a scanner: hidden HTTP endpoints, API request shapes, GraphQL operations, WebSocket/SSE metadata, client-side routes, browser security flows, and other useful information buried in modern bundles.

Modern front-ends ship their attack surface as minified, obfuscated, tree-shaken JavaScript. A plain regex sweep misses most of it and drowns the rest in noise. `jstangle` untangles that code first, then reasons over the structure — so Vigolium discovers endpoints and secrets that only exist inside the bundle.

## Why?

Static string-grepping over bundled JavaScript is fast but nearly blind — it can't follow how a URL is assembled, which adapter sends it, or whether a match is live code or a comment. `jstangle` takes the opposite approach: deobfuscate and normalize the source, walk the AST, and resolve request facts with real evidence and confidence. The output is typed and provenance-tracked, so Vigolium knows what is safe to replay and what is only a discovery hint.

The goal is simple: turn opaque JavaScript into precise, actionable facts about a target's real HTTP surface.

## Install as a standalone CLI

`jstangle` ships inside Vigolium, but you can also install it on its own as a
standalone CLI:

```bash
npm install -g @vigolium/jstangle
```

This puts a `jstangle` command on your `PATH`. See [CLI](#cli) for usage.

## Build and test

From the Vigolium repository root:

```bash
make ensure-jstangle       # rebuild the host helper only when its source hash changed
make update-jstangle       # build and stage every release target
```

From this directory:

```bash
bun install --linker isolated
bun run build:types
bun run test
bun run build:bin:host
```

`make ensure-jstangle` compares the current deterministic source fingerprint to
the fingerprint compiled into the staged helper, so an old or incompatible
helper can never silently run against newer Go code.

## Profiles

Each caller requests only the stages it consumes.

| Profile | Intended consumer | Main output |
|---|---|---|
| `endpoints` | endpoint-only API use | HTTP request facts |
| `dom-security` | passive DOM security module | DOM/browser flow facts |
| `beautify` | passive JS beautifier | beautified artifact only |
| `discovery` | normal content discovery | requests, assets, GraphQL, protocols, routes, optional transformed artifact |
| `discovery-lite` | larger discovery assets | discovery facts without transformed code |
| `full` | manual research | all analysis capabilities |
| `inspect` | debugging/evidence | full output plus request evidence |

Skipped stages appear with zero duration and `status: "skipped"` in stage
metrics. Webcrack is loaded lazily only when a beautify stage runs.

## CLI

The JavaScript to analyze comes from the first positional argument — which may
be either a **file path** or the **raw JS source** itself — and falls back to
**stdin** when omitted.

```bash
# From a file
jstangle --profile discovery --source-url https://app.test/assets/app.js app.js

# From raw JS passed inline as the first argument
jstangle --profile endpoints 'fetch("/api/v1/users")'

# From stdin (pipe a bundle in)
curl -s https://app.test/assets/app.js | jstangle --profile discovery

# Put transformed/beautified documents in a contained artifact directory
jstangle --profile beautify --artifact-dir /tmp/jstangle-artifacts app.js

# Machine-readable build and capability contract
jstangle --capabilities

# Persistent length-prefixed worker transport (normally owned by Go)
jstangle --worker
```

Important limits include `--max-requests`, `--max-ast-nodes`,
`--max-output-bytes`, `--max-artifact-bytes`, and `--deadline-ms`.

## Output

`--capabilities` reports the tool version, deterministic source hash, supported
profiles, record schema versions, runtime, framing, and compiled dependency
versions.

An `analysisResult` contains:

- `source`: source URL, content SHA-256, size, filename/media type, and bundle format.
- `stats`: overall status, record counts, total time, and per-stage metrics.
- `diagnostics`: explicit parse, budget, fallback, and artifact degradations.
- `records`: compact typed facts.
- `artifacts`: contained paths, hashes, lengths, and formats for large output.

Current typed records are:

- `httpRequest`: method, URL/query/body/header templates, client adapter,
  confidence, source span, and resolution evidence.
- `domFlow`: binding/order-aware source-to-sink browser flow.
- `assetReference`: dynamic/static chunks, workers, service workers, manifests,
  source maps, Wasm, and config assets.
- `graphqlOperation`: parsed operation/document, variables, persisted hash,
  endpoint, and transport.
- `websocket` and `eventSource`: protocol metadata and message/event behavior.
- `clientRoute`: framework-aware routes, guards, and lazy assets.
- `browserSecurityFlow`: postMessage trust, open redirect, script/network URL,
  dynamic execution, sensitive exfiltration, and prototype-pollution evidence.

Unknown future record kinds are retained by the Go decoder under a bounded
budget, allowing forward-compatible diagnostics instead of silent loss.

## Safety and degradation

- Per-analysis state is isolated; persistent workers process one framed job at
  a time and Go supplies bounded parallelism.
- Content/profile results are byte-bounded and coalesced by content hash.
- Worker admission is memory-weighted, with job-count and RSS recycling.
- Oversized discovery input first drops transformed-code work, then uses a
  bounded lexical endpoint/asset fallback. Hard-limit input is rejected.
- AST node, resolution, evidence, request, artifact, output, graph, and time
  budgets produce explicit diagnostics.
- Artifact paths are verified to remain inside the job directory before Go
  reads them; all job directories are removed after success, failure, or cancel.

## Vigolium integration policy

High-confidence request facts are eligible for exact replay with their observed
method, query, body, content type, and safe static headers. Medium-confidence
facts are available only in conservative mode. Low-confidence generic strings
are discovery hints and never cause direct traffic by default.

Relative requests resolve once against the JavaScript asset that produced them.
Authorization, cookies, API keys, CSRF tokens, browser-controlled headers, and
dynamic header values are not copied into replay traffic. Authentication comes
from Vigolium's configured session instead.

WebSocket and SSE facts never enter the ordinary HTTP variant generator. A
bounded handshake is synthesized only when `protocol_handshake: true` is set.

Source maps are fetched by Go under normal scope/auth/rate limits. Bounded
`sourcesContent` files are analyzed individually and stored as immutable,
session-scoped artifacts; source paths are display metadata and never filesystem
destinations.

## Credits

`jstangle` stands on the shoulders of the open-source JavaScript deobfuscation,
debundling, and beautification community. It is inspired by — and grateful to —
these projects:

- [de4js](https://github.com/lelinhtinh/de4js)
- [debundle](https://github.com/1egoman/debundle)
- [javascript-deobfuscator](https://github.com/ben-sb/javascript-deobfuscator)
- [js-beautify](https://github.com/beautifier/js-beautify)
- [js-deobfuscator](https://github.com/kuizuo/js-deobfuscator)
- [restringer](https://github.com/HumanSecurity/restringer)
- [retidy](https://github.com/Xmader/retidy)
- [synchrony](https://github.com/relative/synchrony)
- [wakaru](https://github.com/pionxzh/wakaru)
- [webcrack](https://github.com/j4k0xb/webcrack)

## License

jstangle is made with ♥ by [@j3ssie](https://twitter.com/j3ssie), with [@theblackturtle](https://github.com/theblackturtle) as a core contributor.
