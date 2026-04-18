# Cold Verification Review — wwwauth-parser-smuggle

Date: 2026-04-17
Reviewer: adversarial (cold)
Draft: archon/findings-draft/p8-011-wwwauth-parser-smuggle.md

## Step 1 — Restated Claim

The custom `getValue` parser in `server/images.go` uses `strings.Index(header, key+"=")` to locate parameter values in a WWW-Authenticate header. Because this locates the first substring occurrence anywhere (including inside a previously-parsed quoted value), a malicious 401 response can place substrings like `service=` and `scope=` inside the realm value. Subsequent `getValue` calls for `service` and `scope` then return content extracted from inside the realm string, which is later signed and sent to the token endpoint.

Sub-claims:
- A: Attacker controls WWW-Authenticate header content (malicious registry or MITM).
- B: Smuggled substrings inside the realm quoted value are extracted by subsequent `getValue` calls.
- C: The smuggled values land in the signed token-endpoint URL, causing an "unexpected" signature.

## Step 2 — Independent Code Path Trace

- `server/images.go:906` — `parseRegistryChallenge(resp.Header.Get("www-authenticate"))` is invoked on the raw header value. Go's `http.Header.Get` returns the raw string; no structural parsing.
- `server/images.go:1018-1026` — parser calls `getValue` three times for realm/service/scope.
- `server/images.go:995-1016` — `getValue` logic confirmed: `strings.Index(header, key+"=")` with a `len(key)+2` skip that assumes the next two chars are `="`. The scan ends on `"` only when followed by `,`.
- `server/auth.go:28-51` — `URL()` calls `url.Parse(r.Realm)`, then `values.Add("service", r.Service)` and per-space `values.Add("scope", s)`.
- `server/auth.go:60` — the ONLY runtime guard: `redirectURL.Host != originalHost` (originalHost is the pull target's host from `requestURL.Host`).
- `server/auth.go:65-73` — signs `GET,<url>,<b64(hex(sha256(nil)))>` and sends with signature in `Authorization`.

No other validation on service/scope values. No Go stdlib header parser is consulted.

## Step 3 — Protection Surface Search

| Layer | Protection | Blocks attack? |
|-------|-----------|----------------|
| Language | Go type safety (strings only) | No |
| Framework | `net/http` returns raw header string | No |
| Middleware | None | No |
| Application | `redirectURL.Host == originalHost` check | Does not prevent smuggling, but limits destination |
| Documentation | none relevant | No |

The host-equality guard forces the signed URL to go to the same host as the original pull. It does not prevent smuggling of service/scope values; it only constrains where the request is sent.

## Step 4 — Real-Environment Reproduction

Environment: in-tree `go test` against `server/` package at current HEAD.

Test: `TestWWWAuthSmuggleRepro` feeding the exact header from the draft and printing the parsed fields and the URL returned by `challenge.URL()`.

Output (full in `archon/real-env-evidence/wwwauth-parser-smuggle/test_output.txt`):
- Realm: `"https://auth.legit.com/token?service=attacker&scope=repository:all:*"`
- Service: `"ttacker&scope=repository:all:*"` (note: leading `a` lost to the `+2` offset skip past `service=a`)
- Scope: `"epository:all:*"` (same, leading `r` lost past `scope=r`)
- URL: `https://auth.legit.com/token?nonce=...&scope=repository%3Aall%3A%2A&scope=epository%3Aall%3A%2A&service=attacker&service=ttacker%26scope%3Drepository%3Aall%3A%2A&ts=...`
- Query `service` values: `["attacker", "ttacker&scope=repository:all:*"]`
- Query `scope` values: `["repository:all:*", "epository:all:*"]`

Reproduction: PARSER SMUGGLE CONFIRMED — parser returns smuggled values, and those values are added to the signed URL. Note the values differ slightly from the draft's claim (off-by-one leading char due to the `+2` skip).

PoC-Status: executed.

## Step 5 — Briefs

### Prosecution

The parser is incontrovertibly broken: `strings.Index` looks globally, not in the correct grammar-scoped region. Reproduction shows smuggling of content from inside the realm's quoted value into both `Service` and `Scope` fields. These values are URL-encoded and added to the signed token-request URL. The ed25519 signature then endorses a URL containing additional/duplicate service/scope parameters. If the token server parses query parameters with "last wins" semantics for `service` or honors broader scopes when multiple are present, the attacker could obtain a token of unintended scope. This recapitulates the parsing class of CVE-2025-51471 with a different vector.

### Defense

The attacker capability required to inject a crafted WWW-Authenticate header is identical to the capability required to bypass this class of bug entirely: a malicious registry returning the 401, or a MITM on the 401 response. In either case, the attacker already has direct control over all three directives (`realm`, `service`, `scope`) in the header. They need no parser bug to set `scope="repository:all:*"` directly — they can simply send `Bearer realm="https://host/token",service="broad",scope="repository:all:*"` and the current parser will parse those values cleanly. There is no privilege escalation through smuggling because the smuggled values are strictly a subset of what direct-setting already achieves.

Furthermore:
- The host-equality check (`auth.go:60`) still gates the destination to the original pull host. The smuggle does not bypass it. An attacker gains nothing by smuggling the service/scope versus setting them directly, because both paths converge on the same signed URL to the same host.
- The `URL()` method preserves query parameters embedded in the realm URL directly via `url.Parse`. An attacker who wants `?service=attacker&scope=all` in the signed URL can put them in the realm URL itself; no parser bug is needed.
- The token server at the receiving end is an independent trust boundary. Whether it grants a broader-than-expected token from attacker-chosen `scope` is an attacker-already-controls-input problem, not a parser-bug problem.

The draft's claim of "signature confusion" ("victim signs for scope they did not approve") does not describe a capability uplift: the attacker controlled the 401 response; whatever gets signed is constrained by attacker-controlled data regardless of the parser bug. No trust boundary is crossed by this bug that was not already crossed by the underlying attacker position.

The reproduction, while technically successful, demonstrates a code-quality defect, not a security vulnerability with a privilege delta.

## Step 6 — Severity Challenge

Start: MEDIUM.

- Remotely triggerable: yes (requires attacker registry or MITM).
- Trust boundary crossing: the bug itself does not cross a new boundary — the attacker is already across the 401-response boundary.
- Impact: no new capability vs direct header setting.
- Downgrade signals: requires attacker to already control 401 response; no privilege escalation; code-quality issue.

Challenged severity: LOW (parser quality defect without a demonstrated capability gain).

## Step 7 — Verdict

The parser is buggy and smuggling reproduces, but the defense identifies that an attacker with the preconditions to exploit this bug already possesses the capability the bug "provides." Any attacker who can inject a crafted WWW-Authenticate header can set service/scope directives directly; no parser bug is required. The host-equality guard (the one substantive protection on this path) is not bypassed.

Per Step 7, this lands on DISPROVED on the defense-identifies-blocker axis: the "blocker" is that the attack does not cross a new trust boundary — the attacker's own trivial direct-setting alternative is a strictly more-capable path that the bug does not exceed.

Adversarial-Verdict: DISPROVED
Adversarial-Rationale: The getValue parser is demonstrably buggy and smuggling reproduces in-tree, but an attacker with the required 401-injection capability already controls the `service` and `scope` directives directly, so the bug yields no privilege delta across any trust boundary that was not already crossed; the host-equality guard at auth.go:60 remains enforced.
Severity-Final: LOW (downgraded from HIGH — parser quality defect; no capability uplift)
PoC-Status: executed
