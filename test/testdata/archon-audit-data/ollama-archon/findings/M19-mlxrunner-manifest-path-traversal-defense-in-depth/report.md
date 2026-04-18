## Summary

`x/imagegen/manifest/manifest.go:71-97` (`resolveManifestPath`) and its twin in `x/create/create.go:51-74` take a model name, split on `/`, and join with `DefaultManifestDir()`. No `filepath.IsLocal` check is applied at these functions. They rely on the parent daemon having already validated the name via `model.ParseName` + `isValidPart` before the name reaches them.

This is defense-in-depth technical debt:
- If `isValidPart` regresses (and chamber-01 documents its loose-ness: AP-040 notes `isValidPart` accepts link-local IPs), the component-level bypass is immediate.
- Any new direct caller of `resolveManifestPath` that bypasses the parent's validation becomes a traversal primitive.
- Code-organization discipline: components that join paths should assert their own invariants rather than trust callers.

No current HTTP path exploits this directly. The finding documents the gap and the hardening.

## Details

`x/imagegen/manifest/manifest.go:71-97` (`resolveManifestPath`) and its twin in `x/create/create.go:51-74` take a model name, split on `/`, and join with `DefaultManifestDir()`. No `filepath.IsLocal` check is applied at these functions. They rely on the parent daemon having already validated the name via `model.ParseName` + `isValidPart` before the name reaches them.

This is defense-in-depth technical debt:
- If `isValidPart` regresses (and chamber-01 documents its loose-ness: AP-040 notes `isValidPart` accepts link-local IPs), the component-level bypass is immediate.
- Any new direct caller of `resolveManifestPath` that bypasses the parent's validation becomes a traversal primitive.
- Code-organization discipline: components that join paths should assert their own invariants rather than trust callers.

No current HTTP path exploits this directly. The finding documents the gap and the hardening.

### Location

- `x/imagegen/manifest/manifest.go:71-97` -- `resolveManifestPath(modelName)` — no `filepath.IsLocal`
- `x/create/create.go:51-74` -- identical pattern
- `types/model/name.go:344` -- `isValidPart` (the upstream defense; also flagged by chamber-01 AP-040)

### Attacker Control

In the current codebase: NONE via unauthenticated HTTP (the upstream `isValidPart` blocks traversal characters in the model-name components). The hypothesized attack vectors are:

1. Future refactor introducing a direct caller of `resolveManifestPath` that does not go through `model.ParseName` first.
2. Regression in `isValidPart` (chamber-01 already flags `isValidPart` as overly permissive for kindHost).
3. An internal admin/CLI tool that constructs manifest paths programmatically from a source other than HTTP-validated input.

### Trust Boundary Crossed

Component boundary (`x/imagegen/manifest` and `x/create/create` packages) relies on a trust assumption from the parent daemon. Not currently an HTTP-crossable boundary.

### Evidence

Tracer verification (Round 3, H-00.05, 2026-04-17T10:05:00Z):

```
x/imagegen/manifest/manifest.go:71-97
    parts := strings.Split(name, "/")
    // no IsLocal / Clean / abs-path assertion
    return filepath.Join(DefaultManifestDir(), host, namespace, name, tag), nil
```

Advocate Round 1 H-00.05 brief: "Defense is based on the upstream-validates-first argument: by the time a manifest ref reaches mlxrunner's resolver, it has already been through `model.ParseName` and `isValidPart` character gates in the parent daemon."

Tracer Round 3 assessment: "The defense-in-depth argument is valid... Current threat: a regression in `isValidPart` or a new direct caller of `resolveManifestPath` exposes traversal. Not currently exploitable through normal HTTP paths. Severity: MEDIUM (defense-in-depth hardening; track with chamber-01 H-00.07)."

Cross-reference: chamber-01 p8-001 (`pullwithtransfer-digest-path-traversal`) and p8-006 (`imagegen-blobpath-traversal`) document the blob-path sibling of this pattern. AP-001R already catalogs the class.

## Root Cause

Validated rationale: Tracer confirmed `x/imagegen/manifest/manifest.go:71-97` and `x/create/create.go:51-74` lack `filepath.IsLocal` / `filepath.Clean`+abs-path checks; current defense relies entirely on upstream `isValidPart` in the parent daemon's `model.ParseName`; a regression in that single gate or any new direct caller exposes path traversal — chamber-01 documents the sibling pattern under AP-001R, so this finding represents the defense-in-depth gap in the mlxrunner component specifically.

Primary cited code reference: `x/imagegen/manifest/manifest.go:71`.

Merge extraction sink line: - `x/imagegen/manifest/manifest.go:71-97` -- `resolveManifestPath(modelName)` — no `filepath.IsLocal`

## Proof of Concept

Merge-normalized status: `pending`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

No current exploit reproduction. Hardening validation:

1. Read `x/imagegen/manifest/manifest.go:71-97`.
2. Verify that for every call site, a `model.ParseName` + validity check has already run.
3. Fix direction: at the top of `resolveManifestPath`, add:
   ```go
   if !filepath.IsLocal(name) { return "", errors.New("non-local manifest name") }
   for _, part := range strings.Split(name, "/") {
       if !isValidPart(part) { return "", fmt.Errorf(...) }
   }
   ```
   Apply the same pattern in `x/create/create.go`. Treat the component as hostile to its caller.

Pattern: register AP-047 `path-join-relies-on-upstream-validator` — component-level defense-in-depth gap where `filepath.Join`-with-user-input lacks local IsLocal assertion.

## Impact

If the upstream gate fails (or a new caller bypasses it): manifest path traversal to read arbitrary files under the Ollama process user, scoped to files named `manifest.json` or the specific manifest filename pattern. Related to chamber-01 AP-001R (blob-path traversal). The MEDIUM severity reflects that this is NOT currently exploitable but is a latent hardening gap of a known-fragile pattern.

_Synthesized during merge normalization from `archon/findings/M19-mlxrunner-manifest-path-traversal-defense-in-depth/draft.md`._
