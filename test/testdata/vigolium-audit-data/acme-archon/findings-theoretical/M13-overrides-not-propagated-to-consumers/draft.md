# p2-051: fast-xml-parser fix relies on npm `overrides`, not propagated to downstream consumers

Verdict: VALID
Severity-Original: MEDIUM
Class: Supply-Chain / Patch Propagation
Triage-Priority: skip
Triage-Reasoning: supply-chain propagation concern, not a acme-internal bug — informational/theoretical
Intent-Verdict: genuine
Intent-Source: none
Intent-Quote: n/a
Intent-Confidence: weak
FP-Verdict: TRUE-POSITIVE
FP-Confidence: HIGH
FP-Evidence: package.json:163-165 declares overrides; package-lock.json:15201-15203 still resolves openapi-sampler→fast-xml-parser@^4.5.0 in consumer trees
FP-Reasoning: npm `overrides` is documented as scoped to install root only; downstream consumers of acme-as-dependency do not inherit the override.

Source patch: 11111111 (PR #2785), package.json + package-lock.json
Status: confirmed by lockfile + package-manager semantics

## Summary
PR #2785 mitigates the fast-xml-parser CVE wave (CVE-2026-25896, -26278, -25128, -41650) by adding `overrides.fast-xml-parser: ">=5.7.0"` in `package.json`. While this correctly forces `5.8.0` in this repo's own `package-lock.json`, npm `overrides` is **scoped to the install root**. Projects that install `acme` as a dependency will:

1. Not see this `overrides` block applied to their own dependency tree (npm does not honor overrides from non-root packages).
2. Continue to resolve `openapi-sampler@1.6.2` -> `fast-xml-parser@^4.5.0`, which is vulnerable to all four CVEs.

Because acme invokes openapi-sampler at runtime from `src/services/models/MediaType.ts` to render XML examples in attacker-supplied OpenAPI specs, the parser is on the runtime attack path.

## Evidence
- `package.json:163-165` declares `"fast-xml-parser": ">=5.7.0"` under `overrides`.
- `package-lock.json:15201-15203` shows `openapi-sampler` still declares `"fast-xml-parser": "^4.5.0"`.
- `src/services/models/MediaType.ts:1` imports openapi-sampler.
- npm docs: overrides only apply to the project containing them, not to packages that depend on this project.

## Recommended Fix
Either:
- Add a direct top-level `dependencies.fast-xml-parser` entry pinned `>=5.7.0` (forces resolution in consumer trees only when acme is the leaf, still partial), or preferably
- Open an upstream PR against openapi-sampler bumping the `fast-xml-parser` range to `>=5.7.0`.
- Additionally mirror as `resolutions` (yarn) and `pnpm.overrides` (pnpm) for non-npm users of this source tree.
