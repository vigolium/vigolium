Phase: 8
Sequence: 011
Slug: wwwauth-parser-smuggle
Verdict: FALSE POSITIVE (adversarial)
Rationale: Custom getValue parser uses strings.Index("key=") which finds substrings inside previously-parsed quoted values; realm content containing "service=X" or "scope=Y" smuggles those into signed token request parameters — Advocate confirmed no structural parsing or RFC-compliant tokenizer exists.
Severity-Original: HIGH
Adversarial-Verdict: DISPROVED
Adversarial-Rationale: Parser smuggling reproduces in-tree, but any attacker able to inject this crafted WWW-Authenticate header already directly controls the service/scope directives, so the bug yields no privilege delta; host-equality guard at auth.go:60 remains enforced.
Severity-Final: LOW
PoC-Status: executed
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-01/debate.md

## Summary

`server/images.go:995-1026` implements a custom WWW-Authenticate header parser via `getValue(header, key)` and `parseRegistryChallenge`. `getValue` uses `strings.Index(header, key+"=")` — finding the FIRST substring occurrence anywhere in the header, regardless of whether that occurrence is inside a previously-parsed quoted value. If the realm value contains a substring like `service=X` or `scope=Y`, the subsequent `getValue(header, "service")` returns that inner substring instead of the real `service=` directive.

This allows a malicious registry to smuggle `service` and `scope` values into the signed token request URL even while the realm host still passes the host-equality check (Finding 005's guard). The smuggled scope appears in the signed challenge data (`auth.go:65`), so the victim's ed25519 signature endorses attacker-chosen scope. This is the same class of bug as CVE-2025-51471; the registered fix did not address the underlying substring-matching parser.

## Location

- `server/images.go:995-1016` — `getValue` (substring-based)
- `server/images.go:1018-1026` — `parseRegistryChallenge`
- `server/auth.go:32-48` — `registryChallenge.URL()` builds signed token-endpoint URL using `Service` and `Scope` fields
- `server/auth.go:65` — `fmt.Sprintf("%s,%s,%s", http.MethodGet, redirectURL.String(), ...)` includes smuggled query params in signed data

## Attacker Control

Malicious registry OR MITM on the 401 response injects a crafted WWW-Authenticate header.

## Trust Boundary Crossed

Network (hostile registry / MITM) → signed auth material.

## Impact

- Signature confusion: victim signs for scope they did not approve; downstream registry may grant a token of unexpected scope.
- Token-endpoint URL structure (including query parameters) comes from smuggled values — the token server may return tokens scoped for attacker-chosen resources.
- Foundation for chained auth attacks (Finding 005 downgrade + this smuggle = plaintext leak of bad-scope signed request).

## Evidence

```go
// server/images.go:995-1016
func getValue(header, key string) string {
    startIdx := strings.Index(header, key+"=")   // <-- finds ANY substring match
    if startIdx == -1 { return "" }

    // Move the index to the starting quote after the key.
    startIdx += len(key) + 2
    endIdx := startIdx

    for endIdx < len(header) {
        if header[endIdx] == '"' {
            if endIdx+1 < len(header) && header[endIdx+1] != ',' {
                endIdx++
                continue
            }
            break
        }
        endIdx++
    }
    return header[startIdx:endIdx]
}

// server/images.go:1018-1026
func parseRegistryChallenge(authStr string) registryChallenge {
    authStr = strings.TrimPrefix(authStr, "Bearer ")
    return registryChallenge{
        Realm:   getValue(authStr, "realm"),
        Service: getValue(authStr, "service"),
        Scope:   getValue(authStr, "scope"),
    }
}
```

Attack header (real `service` / `scope` are smuggled inside the realm value):
```
Bearer realm="https://auth.legit.com/token?service=attacker&scope=repository:all:*",service="legit",scope="repository:foo:pull"
```
- `getValue(h, "realm")` returns the full URL (scans until `"` followed by `,`).
- `getValue(h, "service")` finds `service=` WITHIN the realm — returns `attacker&scope=repository:all:*` (until the `"` at the end of the URL).
- `getValue(h, "scope")` similarly finds `scope=` WITHIN the realm — returns `repository:all:*`.

These smuggled values end up in the signed token-endpoint URL.

## Reproduction Steps

1. Run attacker registry that replies 401 on the manifest fetch with the attack header above.
2. Victim: `ollama pull auth.legit.com/foo:latest`.
3. Sniff the signed token request or attacker-side log: `Authorization: <sig-over-url-containing-smuggled-scope>`; `scope=repository:all:*` in the URL.
4. If the token server grants scope per URL query, attacker-scoped token returned.

Debate context: Advocate confirmed no structural parser. Fix: replace `getValue` with RFC 7235 / 9110 compliant WWW-Authenticate parsing (e.g., adopt `github.com/docker/distribution/registry/client/auth/challenge` or a hand-written tokenizer that correctly handles quoted strings).
