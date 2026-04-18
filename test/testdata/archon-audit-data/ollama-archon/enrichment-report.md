# Merged Enrichment Summary

## Included Sources

- `.archon-merge-staging-1765496804/enrichment-summary.md`
- `ollama-with-opus-4.7` has no matching source file

## Source 1 - enrichment-summary.md

# Phase 7 Enrichment Summary — ollama/ollama

**Date**: 2026-04-07
**Commit audited**: 8c8f8f3450d39735355fc6cd7f2e436c8aa42ab1 (main) + remotes/origin/parth/agents
**Findings processed**: p4-f01 through p4-f11 (11 total)
**CodeQL artifacts**: Not present in environment — all reachability assessed via manual code trace and KB cross-reference

---

## Enrichment Verdict Table

| Finding | Classification | Attacker Control | Trust Boundary Crossed | CodeQL Reachability | Severity | Verdict |
|---------|---------------|-----------------|----------------------|-------------------|----------|---------|
| p4-f01 | SECURITY | Registry publisher controls `Entrypoint` JSON field in OCI config blob | Registry-to-client (pull → exec, no consent gate) | No slice; manual trace confirmed; parth/agents branch only | CRITICAL | KEEP |
| p4-f02 | SECURITY | LLM output (influenceable via prompt injection) controls `bash -c` argument | LLM-to-host-OS (approval gate bypassable) | No slice; manual trace confirmed; x/ agent package | HIGH | KEEP |
| p4-f03 | SECURITY | Unauthenticated HTTP client controls GGUF string length field | Network-to-server (unauthenticated blob upload) | No slice; manual trace confirmed; main branch | HIGH | KEEP |
| p4-f04 | SECURITY | Unauthenticated HTTP client controls GGUF array count field | Network-to-server (unauthenticated blob upload) | No slice; manual trace confirmed; main branch | HIGH | KEEP |
| p4-f05 | SECURITY | Unauthenticated HTTP client controls GGUF tensor shape fields | Network-to-server + Go-to-C++ (bounds-check bypass) | No slice; manual trace confirmed; main branch | HIGH | KEEP |
| p4-f06 | SECURITY | Unauthenticated HTTP client controls `general.alignment` GGUF KV field | Network-to-server (unauthenticated blob upload) | No slice; manual trace confirmed; main branch | HIGH | KEEP |
| p4-f07 | SECURITY | Attacker delivers local HTML file opened by victim in browser | Browser same-origin policy → localhost API (file://* CORS bypass) | Confirmed in main branch code; no formal slice | HIGH | KEEP |
| p4-f08 | SECURITY | DNS rebinding attacker controls DNS resolution | allowedHostsMiddleware bypass for /api/delete, /api/pull | Confirmed in main branch code; structural bypass | HIGH | KEEP |
| p4-f09 | ENVIRONMENT | Requires update server compromise or MITM on update channel | Update-server-to-client (privileged network position needed) | Confirmed in code; darwin-specific | MEDIUM (downgraded from HIGH) | KEEP |
| p4-f10 | ENVIRONMENT | Local user on shared system with write access to 0o777 blob dir | Multi-user filesystem (single-user systems unaffected) | Confirmed in code | MEDIUM | KEEP |
| p4-f11 | SECURITY | Unauthenticated HTTP client controls model name host portion | Client-to-server + server's network boundary (SSRF) | No slice; manual trace confirmed; main branch | MEDIUM (recommend escalation to HIGH) | KEEP |

**Findings dropped**: 0
**Findings kept**: 11
**Severity adjustments**: p4-f09 HIGH→MEDIUM; p4-f11 MEDIUM (flagged for Phase 8 escalation to HIGH)

---

## Classification Breakdown

### SECURITY findings (9): p4-f01, p4-f02, p4-f03, p4-f04, p4-f05, p4-f06, p4-f07, p4-f08, p4-f11
All cross a clear trust boundary with attacker-reachable input.

### ENVIRONMENT findings (2): p4-f09, p4-f10
Both retained (not dropped) because:
- p4-f09: "extraction before verification" ordering makes the zip slip permanent even with signature checks — the safety net does not function
- p4-f10: 0o777 blob dir is a simple fix that eliminates a concrete multi-user attack surface; combined with GGUF parser vulns, enables code execution

---

## Key Enrichment Decisions

### p4-f01 — Branch Context Critical
The `Entrypoint` field does NOT exist in `types/model/config.go` on `main`. The vulnerability is fully present on `remotes/origin/parth/agents` (confirmed via `git show`). Severity retained at CRITICAL because the finding is architecturally complete, requires design-level intervention, and is one PR away from merge. Pre-merge finding is the correct time to flag this.

### p4-f05 — Escalated Impact
Initial assessment focused on DoS; enrichment identifies the overflow-to-bounds-bypass creating a path into C++ memory-unsafe code (the llama.cpp runner). This is more severe than pure DoS — potential OOB read in C++ context.

### p4-f08 — CVE-2024-28224 Patch Bypass
`registry.Local.ServeHTTP` intercepts `/api/delete` and `/api/pull` before the gin middleware chain (confirmed in `server/routes.go:1727-1736` and `server/internal/registry/server.go:114-129`). This is a structural bypass of `allowedHostsMiddleware` (the DNS rebinding fix for CVE-2024-28224) for exactly the two most sensitive endpoints.

### p4-f09 — Downgraded to MEDIUM
Attack requires either (a) compromise of Ollama's update server, or (b) MITM on the update download. These represent privileged attacker positions. However, the "extract before verify" ordering in Loop 2 means the write is permanent even if signature verification subsequently fails — so this is not a theoretical issue once the attacker has network position. Retained as MEDIUM.

### p4-f11 — Recommend Phase 8 Escalation
CVE-2026-5530 rates this HIGH. Cloud IMDS credential theft is a HIGH-impact outcome. The MEDIUM classification in the draft was conservative. Phase 8 reviewers should escalate to HIGH.

---

## GGUF Parser Cluster Note (p4-f03, p4-f04, p4-f05, p4-f06)

These four findings share a common attack path (unauthenticated blob upload → `/api/create` → GGUF parse) and represent a structural absence of bounds-checking in the GGUF parser. The KB confirms 9 total GGUF advisories with this structural pattern. Phase 8 should consider issuing a single architectural recommendation: implement a GGUF validation layer at the HTTP boundary that enforces field-level limits (max string length, max array count, valid alignment values, overflow-checked element counts) before any parsing proceeds.

---

## Entry Points Not in Phase 3 DFD Slices

The following attack surface was active but not modeled in DFD slices:
- `registry.Local.ServeHTTP` as outermost HTTP handler (p4-f08) — the DFD modeled the gin middleware chain as the entry point, but `registry.Local` is upstream of it when enabled
- `cmd/cmd.go:runEntrypoint` (p4-f01) — the CLI execution path was not in the server DFD; it requires a separate DFD slice for the CLI trust model

## Sinks Without Modeled High-Risk Flows

- `exec.Command` in `cmd/cmd.go:runEntrypoint` (parth/agents) — no DFD sink for CLI command execution
- `exec.CommandContext(ctx, "bash", "-c", command)` in `x/tools/bash.go:64` — the DFD-3 slice existed but did not enumerate the specific approval bypass vectors
- `url.URL{Host: n.Host}` in `types/model/name.go:BaseURL()` — SSRF sink; DFD-1 modeled the pull flow but did not identify `BaseURL()` as an unvalidated SSRF sink

---

## No-Slice Findings — On-Demand Query Recommendation

Since CodeQL artifacts are absent from this environment, the following findings most benefit from on-demand CodeQL analysis in a tooled environment:

1. **p4-f11 (SSRF)**: Query: dataflow from `c.ShouldBindJSON(&req) -> req.Model -> ParseNameBare -> Name.Host -> BaseURL() -> http.Get(url)`. This would confirm whether response data is returned to the caller and whether any host allowlist check exists in any code path.

2. **p4-f05 (tensor overflow)**: Query: `Tensor.Elements()` return value flows to bounds check `tensorEnd > fileSize`. Confirm the overflow case produces `tensorEnd <= fileSize` (false negative in bounds check).

3. **p4-f08 (middleware bypass)**: Query: taint from `http.Request` in `registry.Local.ServeHTTP` — confirm no `allowedHostsMiddleware` equivalent is called before `handleDelete`/`handlePull`.

