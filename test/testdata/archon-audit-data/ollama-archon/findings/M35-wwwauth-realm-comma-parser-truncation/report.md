## Summary

The custom WWW-Authenticate parser at `server/images.go:995-1016 getValue` scans for the end of a quoted value using a bespoke state machine:

```go
for endIdx := startIdx + 1; endIdx < len(authStr); endIdx++ {
    if authStr[endIdx] == '"' {
        if endIdx+1 == len(authStr) || authStr[endIdx+1] == ',' {
            break
        }
        endIdx++  // escaped quote, continue
    }
}
```

The intent is "a closing quote followed by a comma terminates the value". But the state machine is order-dependent: it stops at any inner comma that happens to be preceded by a quote-character-lookbehind. More precisely, it is confused by legitimate URL query-strings:

- `realm="https://auth.example.com/token?scope=pull,push"` — the comma inside the scope parameter is between two non-quote chars, so the parser correctly keeps going. OK.
- `realm="https://auth.example.com/token?a=1\",b=2"` — an escaped quote inside the value triggers premature termination.
- Custom registry responses that embed structured values (comma-delimited scopes) can cause similar truncation when the quote-escape is imperfect.

When truncation occurs, `url.Parse` may return either an error (downstream rejects) or — more dangerously — a valid URL pointing at an attacker-chosen prefix of the original. Combined with p8-005's host-equality-without-scheme check, a registry that crafts a realm like `"http://legit-registry.com/token","realm="http://attacker.com/token"` could achieve a parser-confusion scheme-downgrade.

This is the same pattern class as AP-036 (substring-based header parsers, already recorded for p8-011 `parseRegistryChallenge`).

## Details

The custom WWW-Authenticate parser at `server/images.go:995-1016 getValue` scans for the end of a quoted value using a bespoke state machine:

```go
for endIdx := startIdx + 1; endIdx < len(authStr); endIdx++ {
    if authStr[endIdx] == '"' {
        if endIdx+1 == len(authStr) || authStr[endIdx+1] == ',' {
            break
        }
        endIdx++  // escaped quote, continue
    }
}
```

The intent is "a closing quote followed by a comma terminates the value". But the state machine is order-dependent: it stops at any inner comma that happens to be preceded by a quote-character-lookbehind. More precisely, it is confused by legitimate URL query-strings:

- `realm="https://auth.example.com/token?scope=pull,push"` — the comma inside the scope parameter is between two non-quote chars, so the parser correctly keeps going. OK.
- `realm="https://auth.example.com/token?a=1\",b=2"` — an escaped quote inside the value triggers premature termination.
- Custom registry responses that embed structured values (comma-delimited scopes) can cause similar truncation when the quote-escape is imperfect.

When truncation occurs, `url.Parse` may return either an error (downstream rejects) or — more dangerously — a valid URL pointing at an attacker-chosen prefix of the original. Combined with p8-005's host-equality-without-scheme check, a registry that crafts a realm like `"http://legit-registry.com/token","realm="http://attacker.com/token"` could achieve a parser-confusion scheme-downgrade.

This is the same pattern class as AP-036 (substring-based header parsers, already recorded for p8-011 `parseRegistryChallenge`).

### Location

- `server/images.go:995-1016` — `getValue` state machine
- `server/images.go:1004-1014` — the quote-followed-by-comma termination branch

### Attacker Control

Malicious registry fully controls the WWW-Authenticate header sent back on 401.

### Trust Boundary Crossed

External HTTP response header → URL parser state.

### Evidence

Tracer: PARTIAL — "the parser bug is real and confirmed at `server/images.go:1004-1014`. It causes functional failures... but does not create a directly exploitable security bypass in isolation." Synthesizer retains MEDIUM because:
- Low standalone severity (robustness gap).
- Non-trivial composition risk with p8-005.
- Same pattern as AP-036 — aggregating instances improves detection coverage.

## Root Cause

Validated rationale: `server/images.go:995-1016 getValue` scans for the closing quote of a WWW-Authenticate directive by looking for quote-followed-by-comma; if the realm URL's query string itself contains a comma (e.g., `realm="https://auth/token?a=1,b=2"`), the scanner stops at the first internal comma and the returned realm is truncated. Tracer marked PARTIAL; Advocate did not defend this specifically. Standalone impact is low (robustness bug for registries using commas in realm URLs), but combined with p8-005 / H-00.06's scheme downgrade, a crafted registry response can split a realm URL into fragments the downstream URL parser misinterprets. Related to AP-036 pattern.

Primary cited code reference: `server/images.go:995`.

Merge extraction sink line: - `server/images.go:995-1016` — `getValue` state machine

## Proof of Concept

Merge-normalized status: `pending`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

1. Craft a registry that returns `WWW-Authenticate: Bearer realm="https://real/token?a=1,b=2",service="real"` on `/v2/<ns>/<model>/manifests/<tag>`.
2. Observe the URL the client then POSTs the token request to — it is truncated to `https://real/token?a=1` (missing `b=2`).
3. Combined with an attacker who controls both the comma-embedding registry AND a follow-up plain-HTTP endpoint matching the target host, the client sends its ed25519 Authorization header to the truncated URL (scheme check already broken per p8-005).

Remediation: replace the hand-rolled parser with a well-tested library (e.g., `github.com/rfjakob/gocryptfs/internal/openfile_test/authparser`, or a simple RFC 7235 tokeniser). At minimum:
- Reject embedded commas in quoted values, OR
- Use a proper unescaped-quote state machine (track whether the previous char was a backslash).

See AP-036 for cross-reference.

## Impact

Standalone: robustness (wrong realm URL parsed → token fetch failure). Composed: attacker who can provide an ambiguous realm field achieves parser-confusion that may bypass the scheme check in p8-005. The ambiguity also feeds the phishing injection angle (p8-072).

_Synthesized during merge normalization from `archon/findings/M35-wwwauth-realm-comma-parser-truncation/draft.md`._
