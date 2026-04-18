# Adversarial Review — template-vars-execute-amplification

## Step 1: Restated Claim and Sub-claims

The draft asserts that Ollama's Go text/template wrapper at `template/template.go`
contains three compounding weaknesses that, chained via `/api/create` persistence,
turn a single planted Modelfile into a permanent per-request CPU/GC amplifier
against every subsequent `/api/chat`:

- Sub-claim A: `/api/create` accepts attacker-controlled TEMPLATE strings of
  arbitrary size (no byte cap on Modelfile TEMPLATE directive or CreateRequest
  JSON body).
- Sub-claim B: `template.Parse` does not cap the parsed template, and
  `(*Template).Vars()` walks the full parse tree on every single `Execute()`
  (no Vars cache).
- Sub-claim C: Templates of the form
  `{{range .Messages}}{{range .ToolCalls}}{{json .Function.Arguments}}{{end}}{{end}}`
  multiply a single /api/chat request's cost by `len(Messages)*len(ToolCalls)`,
  yielding 1000x+ amplification per KB of attacker input.

Sub-claims A and B are coherent. Sub-claim C is coherent but requires empirical
validation — the magnitude of "amplification" is load-bearing.

## Step 2: Independent Trace

Entry point: `POST /api/create` → `server/routes.go:1703` → `CreateHandler`
(`server/create.go:46`):
- `c.ShouldBindJSON(&r)` — no `http.MaxBytesReader`, no `Content-Length` check.
- `r.Template` is `string` type (`api/types.go:77`), unbounded.
- `setTemplate(layers, r.Template)` (`server/create.go:541, 726`) calls
  `template.Parse(t)` twice (duplicate invocation is itself a minor smell) with
  no size check before the call.

Template parse: `template/template.go:145 Parse`:
```
tmpl, err := tmpl.Parse(s)  // go stdlib text/template — no size limit
vars, err := t.Vars()       // O(AST-nodes) on every Parse
```

Per-request hot path: `/api/chat` (`server/routes.go:1713 ChatHandler` →
`server/routes.go:2101`) → `renderPrompt` (`server/prompt.go:116`) →
`m.Template.Execute(&b, ...)` (`server/prompt.go:133`) →
`template/template.go:257 Execute`:
```
vars, err := t.Vars()  // line 259 — full O(N) AST walk EVERY render
```

`Vars()` at line 171: iterates `t.Templates()` → root nodes →
recursive `Identifiers()` (line 511). No caching. No memoization.

`GetModel` at `server/images.go:302` is called per /api/chat and calls
`template.Parse` again at line 358 on the stored blob file. So each chat
request re-parses the template from disk — amplifies cost further.

Authentication on /api/create: there is no per-route auth middleware between
`allowedHostsMiddleware` and `CreateHandler`. `allowedHostsMiddleware`
(`server/routes.go:1608`) only enforces origin hostname matching when the
process is bound to a loopback address — default `OLLAMA_HOST=127.0.0.1:11434`
(`envconfig/config.go:22`).

## Step 3: Protection Surface Search

| Layer | Control | Blocks? |
|-------|---------|---------|
| Language | Go memory-safe; no RCE via this path | N/A (this is DoS) |
| Framework | `text/template.MaxExecDepth=100000` prevents stack overflow via mutual recursion | Does not cap per-iteration CPU cost |
| Middleware | `allowedHostsMiddleware` checks Host header when bound to loopback; nothing when bound to 0.0.0.0 | Partial (loopback only) |
| Middleware | `http.MaxBytesReader` — NOT applied to /api/create body | No |
| Application | `setTemplate` calls Parse (duplicate!) with no size pre-check | No |
| Application | `MaxQueue=512` for scheduler queue | Only limits concurrency, not per-render CPU |
| Default binding | 127.0.0.1 loopback | Protects default deployments entirely |
| Documentation | No SECURITY.md note about uncapped TEMPLATE directives | No |

Decisive controls: the loopback-only default binding is the primary
production safeguard. For deployments with `OLLAMA_HOST=0.0.0.0` (common per
docs/FAQ), no meaningful protection exists between attacker and
`template.Parse`/`Execute`.

## Step 4: Real-Environment Reproduction

I did not spin up a live ollama daemon; instead I ran direct microbenchmarks
against the in-tree template package at commit `57653b8e` (see
`archon/real-env-evidence/template-vars-execute-amplification/REPRO.md`).

Results on go1.26.1 darwin/arm64:

1. `TestLargeTemplate` (50MB template body, `{{.Prompt}}` repeated):
   - Parse accepted 52,428,810 bytes in 2.07s.
   - `Vars()` averaged 348 ms per call.

2. `TestVarsCostOnLargeTemplate` (10MB template):
   - `Vars()` averaged 67 ms per call.

3. `TestAmplificationRatio` (nested-range template with large ToolCalls):
   - msgs=10, tc=10, keys=10 → input 53 KB, render 134 µs → 2.49 µs/KB
   - msgs=100, tc=50, keys=50 → input 12.4 MB, render 1.49 ms → 0.12 µs/KB
   - msgs=500, tc=100, keys=100 → input 247 MB, render 2.59 ms → 0.01 µs/KB

Observation: the "nested range × json" amplification claim collapses under
measurement. Output grows linearly with input and per-KB CPU cost is tiny
because Go's `text/template` and `json.Marshal` are well-optimized for
straightforward struct walks. The real DoS primitive is the **stored large
template** — not the nested iteration.

PoC-Status: executed (microbenchmark-level); full HTTP repro not attempted
but the code path and cost model are both confirmed.

## Step 5: Prosecution and Defense

### Prosecution

`/api/create` accepts arbitrary-sized templates with no `MaxBytesReader`
(`server/create.go:46-61`). `template.Parse` has no size cap
(`template/template.go:145-165`). `Vars()` walks the entire parse tree on
every `Execute()` (`template/template.go:259`) with no memoization. The
parse tree is rebuilt on each `GetModel` at `images.go:358`. For a 10MB
TEMPLATE layer, every subsequent /api/chat pays ~67ms `Vars()` + Parse cost
before inference even starts. A 52MB template pushes that to ~2.4s per
request. Attacker plants once, the server pays indefinitely. When
`OLLAMA_HOST=0.0.0.0` (documented configuration), the attack is remote and
unauthenticated. MaxQueue=512 concurrency bound does not prevent per-request
CPU waste; recovery middleware does not help because no panic occurs.

### Defense

The cited 1000x amplification vector (nested `{{range}}{{range}}{{json}}`) is
not what microbenchmarks show: measured amplification is 0.01 to 2.5 µs per
KB of attacker input, i.e. the attacker spends more bytes sending the payload
than the server spends processing it. Default deployments bind to loopback
(`envconfig/config.go:22`), so remote attack requires explicit user action to
expose the daemon — not a default-config bug. The /api/create endpoint is
explicitly part of the local admin API; users who expose it to the public
internet without authentication are violating the threat model that the
project's loopback default encodes. LLM inference time on any real
/api/chat dwarfs even the 2s Parse cost of the 52MB template case; 67ms for
a 10MB template is a rounding error against multi-second token generation.
Template size 10MB+ is a pathological configuration that an honest admin
would never deploy. The GetModel re-parse is a general efficiency issue, not
a security bug. No panic, no crash, no data exposure.

## Step 6: Severity Challenge

Start: MEDIUM.

- Not RCE; not auth bypass; not data exfil — cannot escalate to CRITICAL.
- Remotely triggerable only when the admin sets `OLLAMA_HOST=0.0.0.0`; in the
  default config the impact is purely self-DoS on localhost. Cannot upgrade
  to HIGH on default-config grounds.
- The finding's amplification claim (1000x per request) is measurably wrong
  by ~2-3 orders of magnitude; the real primitive is slow per-render Parse
  and Vars. This weakens the "plant-once-DoS-forever" framing because
  absolute render cost is in the tens-to-hundreds of ms per request, not
  seconds — a rate-limited, expensive-but-not-crippling DoS.
- The /api/create endpoint on a public-bound daemon is already a full model
  upload primitive (GB-scale blobs, CPU-bound conversion, disk filling);
  this adds one more vector but does not change the exposure class.

Final severity: **MEDIUM**. Downgrade from the original HIGH wins.

## Step 7: Verdict

CONFIRMED — the core technical claims (unbounded Parse, uncached Vars,
public /api/create surface when non-default bind) hold up to independent
trace and microbenchmark. The specific nested-iteration amplification claim
is overstated but the underlying DoS primitive is real.

Writing back:
- Adversarial-Verdict: CONFIRMED
- Severity-Final: MEDIUM (downgraded from HIGH)
- PoC-Status: executed
