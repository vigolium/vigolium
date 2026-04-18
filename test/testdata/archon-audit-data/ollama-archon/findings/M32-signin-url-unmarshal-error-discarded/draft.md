Phase: 8
Sequence: 032
Slug: signin-url-unmarshal-error-discarded
Verdict: VALID
Rationale: `api/client.go:48-52 checkError` calls `json.Unmarshal(body, &authError)` and DISCARDS the error; a hostile upstream (malicious registry, MITM'd cloud, attacker-controlled proxy) can inject any `SigninURL` content into the error body, and the CLI then prints it verbatim via `ConnectInstructions`. The server-side `signinURL()` is a safe constant (disproving H-07's direct premise), but the ADVisoriy here is that the CLIENT-side error unmarshal pathway is the real injection point — a subtle distinction the Tracer confirmed.
Severity-Original: MEDIUM
Severity-Final: MEDIUM
PoC-Status: pending
Pre-FP-Flag: check-1-ambiguous (the original H-07 framing (server-side) was DISPROVED; the client-side angle is the real bug)
Debate: archon/chamber-workspace/chamber-04/debate.md

## Summary

The original hypothesis (H-07) claimed that a malicious registry could inject `signin_url` into the server's `/api/me` 401 response. Advocate correctly disproved this: `signinURL()` is a compile-time constant. BUT during synthesis, the Tracer's evidence (step 4 at `api/client.go:48-52`) reveals a DIFFERENT injection point — in the CLIENT-side parser that ollama uses when it talks to registries / cloud endpoints:

```go
// api/client.go:48-52 (approximate; sinks.json also flags this as deserialization sink)
body, _ := io.ReadAll(resp.Body)
authError := AuthorizationError{}
_ = json.Unmarshal(body, &authError)   // <-- error discarded
if authError.SigninURL != "" { ... }
```

The Unmarshal error is discarded. A malicious upstream can return a response whose body is partially valid JSON, partially garbage. Unmarshal will populate `authError.SigninURL` with whatever prefix decoded cleanly before the error — including arbitrary URLs. The CLI then prints the URL verbatim via `ConnectInstructions`.

Combined with the realm-host-equality bug (p8-005 / H-00.06) where the attacker controls the realm URL in a WWW-Authenticate header, the realm-controlled endpoint can now also plant a phishing URL in the returned JSON body. The CLI's output becomes:

```
Error: authentication failed
Please sign in at: https://ollama.com.attacker.com/phish?next=...
```

The user trusts the CLI's output (high trust context). The attacker-supplied URL is shown in the same sentence as an instruction to click it.

## Location

- `api/client.go:48-52` — `checkError`: `json.Unmarshal(body, &authError)` with discarded error (Tracer-confirmed from sinks.json: `api/client.go:50` is a deserialization sink)
- `api/client.go:161` — additional deserialization sink on the same pattern
- CLI print path: `cmd/cmd.go` format strings for `AuthorizationError` + `ConnectInstructions`

## Attacker Control

Any HTTP endpoint the Ollama client queries: a malicious registry (via `ollama pull`), a MITM'd cloud proxy, an attacker-proxied update check.

## Trust Boundary Crossed

External HTTP response → user-facing CLI output (high-trust rendering context).

## Impact

- Phishing URL injection into the CLI's authentication error. The user reads "click this URL to sign in" and the URL is attacker-chosen.
- Combined with p8-005's realm-downgrade-ready registry, attacker simultaneously (a) captures signed ed25519 Authorization header via plain HTTP, (b) phishes the user's ollama.com password.

## Evidence

Tracer trace: `sinks.json` lists `api/client.go:50, 56, 161, 228` as deserialization sinks. Unmarshal error discarding confirmed on HEAD.

Advocate defense of H-07 (server-side): correctly disproved (`signinURL()` is server-constant). Synthesizer adopts the tracer's corrected framing at `api/client.go:50` and treats it as the real finding.

## Reproduction Steps

1. Adversary sets up a malicious registry at `free.attacker.com`.
2. Victim runs `ollama pull free.attacker.com/free:model`.
3. Registry replies `401` with body:
   ```json
   {"error":"authentication required","signin_url":"https://ollama.com.attacker.com/phish?next=https://ollama.com/"}
   ```
4. Client's `json.Unmarshal` succeeds silently; CLI prints: "To sign in, please visit https://ollama.com.attacker.com/phish?next=https://ollama.com/".
5. User clicks; enters ollama.com credentials on attacker page.

Remediation:
- Check the Unmarshal error and reject the response body if it fails to parse cleanly; do NOT fallback to partial fields.
- Domain-pin the displayed `SigninURL` to `https://ollama.com` (or a short allowlist) before printing.
- Refuse to open/print any `signin_url` whose scheme is not `https` or whose host is not on the pinned allowlist.
