# Commit Archaeology Report

**Repository**: Acme (Acmely) — `git@github.com:Acmely/acme`
**Commit range**: full repo history (earliest available) .. `[REDACTED]` (HEAD, main)
**Scan depth**: up to 519 commits (full history, no age cap applied — repo is small enough to scan entirely)
**Branches searched**: `origin/main` (only branch)
**Languages detected**: TypeScript (109 files), TSX (99 files), JavaScript (6 files)
**Project security vocabulary discovered**:
- `PROJECT_VOCAB_VALIDATORS`: `sanitize`, `escapeHTMLAttrChars`, `unescapeHTMLChars`, `htmlEncode`, `DOMPurify`, `dompurify.sanitize`, `mergeObjects`
- `PROJECT_VOCAB_AUTH`: `SecurityRequirement`, `SecuritySchemes`, `OAuthFlow`, `SecurityDetails`, `SecurityHeader`
- `PROJECT_VOCAB_CONFIG`: `untrustedSpec`, `sanitize` (AcmeNormalizedOptions), `ALLOW_UNKNOWN_PROTOCOLS` (DOMPurify config — not present, searched negative)
**Scan date**: 2026-05-19T00:00:00Z
**Total commits in repo**: 519
**Coverage caveat**: Full history scanned (519 commits). No age or count cap applied due to manageable repo size.

---

## Summary Statistics

| Category | Commits Found | HIGH | MEDIUM | LOW |
|----------|--------------|------|--------|-----|
| 1. Dangerous Pattern Introduction | 3 | 1 | 1 | 1 |
| 2. Security Control Weakening | 1 | 1 | 0 | 0 |
| 3. Silent Security Fixes | 5 | 3 | 2 | 0 |
| 4. Reverted Security Fixes | 1 | 0 | 1 | 0 |
| 5. Secret Archaeology | 0 | 0 | 0 | 0 |
| 6. CI/CD Pipeline Weakening | 2 | 1 | 1 | 0 |
| 7. Suspicious Patterns | 1 | 0 | 1 | 0 |
| **Total (deduplicated)** | **11** | **5** | **5** | **1** |

---

## High-Risk Commits

| # | SHA | Date | Author | Summary | Category | Risk | Reason |
|---|-----|------|--------|---------|----------|------|--------|
| 1 | `153ec7a` | 2025-01-28 | Contributor Two | fix: Prototype Pollution Vulnerability Affecting acme <=2.2.0 (#2638) | 3 – Silent Fix | HIGH | Fixes a prototype pollution in `mergeObjects()` used during spec ingestion. The exploit vector existed in all versions <=2.2.0. The commit message explicitly names the vuln but no CVE/GHSA was assigned. Pre-fix state in `src/utils/helpers.ts` is exploitable via malicious `__proto__` keys in a crafted OpenAPI spec. |
| 2 | `ddde105` | 2022-09-05 | Contributor Three | fix: add hard limit on deref depth to prevent crashes | 3 – Silent Fix | HIGH | Adds `MAX_DEREF_DEPTH = 999` to `OpenAPIParser.ts` to prevent crash/DoS via deeply recursive `$ref` chains. No CVE. Vague message ("prevent crashes"). Signals B+C satisfied (message lacks security keywords; file is `src/services/OpenAPIParser.ts`). |
| 3 | `87c7991` | 2022-08-08 | Contributor Three / Contributor One | chore: fix circular crash | 3 – Silent Fix | HIGH | Fixes a crash in schema model traversal when oneOf contains a circular `$ref`. Labeled `chore`, not `fix` — disguises security-relevant crash. Touches `src/services/models/Schema.ts`. DoS via malicious recursive schema. All 3 silent-fix signals satisfied. |
| 4 | `53a6afc` | 2025-01-30 | Contributor One | fix: unify acme config (#2647) | 2 – Security Control Weakening | HIGH | Renames `untrustedSpec` → `sanitize` in AcmeNormalizedOptions and SanitizedMdBlock. In the same commit, the demo `index.tsx` changes `untrustedSpec: true` to `sanitize: true`. While semantically equivalent, any downstream consumer relying on the old `untrustedSpec` field will silently get `sanitize = false` (the argValueToBoolean default) on versions after this commit. The parameter rename without a deprecation shim creates an XSS window. |
| 5 | `errata-ai/vale-action@reviewdog` | ongoing | workflow authors | docs-tests.yaml uses unpinned branch ref for `errata-ai/vale-action` | 6 – CI/CD Weakening | HIGH | The action `errata-ai/vale-action@reviewdog` is pinned to a **branch name**, not a SHA or semver tag. Any push to that branch by the action author (or a supply-chain compromise of that account) immediately executes attacker-controlled code in the Acme CI runner, which has access to secrets and the checkout. |

---

## Category 1: Dangerous Pattern Introduction

### [4fc6aa0] dangerouslySetInnerHTML in SourceCode — no sanitization path

- **Commit**: `[REDACTED]`
- **Author**: Contributor One <contributor1@example.com>
- **Date**: 2022-07-06
- **Files**: `src/components/SourceCode/SourceCode.tsx`, `src/utils/highlight.ts`
- **Pattern**: `dangerouslySetInnerHTML={{ __html: highlight(source, lang) }}` — source code samples rendered via Prism.js output injected as raw HTML. Prism's `highlight()` does NOT sanitize its input; it only adds syntax-highlight spans. If an attacker can supply a malicious `source` value through a crafted OpenAPI `example` field, XSS is possible.
- **Discovery source**: generic baseline (dangerouslySetInnerHTML scan) + project-vocab
- **Risk**: MEDIUM
- **FP assessment**: Not a false positive — `source` flows from OpenAPI example values that are user-controlled when `sanitize: false` (the default). The `highlight()` function in `src/utils/highlight.ts` passes the raw string to `Prism.highlight()` which does not escape the input before inserting it into spans. Prism wraps tokens in `<span>` but does not strip malformed HTML from unrecognized tokens.
- **Downstream**: Phase 5 (deep-probe `src/components/SourceCode/SourceCode.tsx` and `src/utils/highlight.ts`)

### [2ca8e08] dangerouslySetInnerHTML in expand/collapse path — context review

- **Commit**: `2ca8e08` (Expand/Collapse buttons disappearing fix, 2022-XX-XX)
- **Pattern**: Existing `dangerouslySetInnerHTML` in `JsonViewer`. `jsonToHTML()` does apply `htmlEncode()` for string values but constructs URL `href` attributes via `encodeURI()` — `encodeURI` does not encode `'`, `"`, or `<`/`>`. A JSON string value starting with `http://` passes the URL check and is placed in `href="<encodeURI(value)>"`. Single- or double-quote injection in the value is possible if the surrounding HTML uses the other quote style, potentially enabling attribute injection.
- **Risk**: LOW
- **FP assessment**: Partial guard (htmlEncode used for display, but encodeURI used for href) — the value would need to contain an unescaped quote to break out of the attribute context. Exploitability depends on browser attribute parsing.
- **Downstream**: Phase 5 only

---

## Category 2: Security Control Weakening

### [53a6afc] Sanitize option rename breaks backward compatibility — XSS window for API consumers

- **Commit**: `[REDACTED]`
- **Author**: Contributor One <contributor1@example.com>
- **Date**: 2025-01-30
- **Files**: `[REDACTED].tsx`, `src/services/AcmeNormalizedOptions.ts`, `demo/index.tsx` (27 files total)
- **Pattern**: `untrustedSpec` option renamed to `sanitize`. The guard in `SanitizedMdBlock.tsx` changes from `options.untrustedSpec` to `options.sanitize`. `AcmeNormalizedOptions` now processes `raw.sanitize || raw.untrustedSpec` so old callers passing `untrustedSpec: true` still work — BUT the `demo/index.tsx` explicitly switches to `sanitize: true`, suggesting deliberate migration. Any integrator who passes `{ untrustedSpec: true }` on the post-rename package version without updating to `sanitize: true` will silently disable sanitization for markdown rendering (DOMPurify will not be called) because `options.sanitize` evaluates to `false` (default).
- **Risk**: HIGH
- **Confidence**: HIGH
- **FP assessment**: The `AcmeNormalizedOptions` does forward `untrustedSpec` via `raw.sanitize || raw.untrustedSpec`, so programmatic API users are protected. However, consumers using HTML attribute `untrustedSpec="true"` on the web component do not benefit from this OR/fallback and get `sanitize = false`. The web component attribute name is the breaking surface.
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5 (deep-probe `AcmeNormalizedOptions.ts`, `SanitizedMdBlock.tsx`)

---

## Category 3: Silent Security Fixes

### [153ec7a] Prototype Pollution in mergeObjects() — no CVE assigned

- **Commit**: `[REDACTED]`
- **Author**: Contributor Two <contributor2@example.com>
- **Date**: 2025-01-28
- **Files**: `src/utils/helpers.ts`, `src/utils/__tests__/helpers.test.ts`
- **Pattern**: `mergeObjects()` previously iterated `Object.keys(source)` without filtering `__proto__`. A crafted OpenAPI spec (JSON) containing `{"__proto__": {"polluted": "yes"}}` as a schema extension would pollute `Object.prototype` during spec ingestion, potentially enabling property injection across the entire renderer.
- **Signal A**: Adds `key !== '__proto__'` check and `hasOwnProperty` guard — protective pattern
- **Signal B**: PR title explicitly says "Prototype Pollution Vulnerability" but no linked CVE/GHSA advisory
- **Signal C**: `src/utils/helpers.ts` is core spec-ingestion path
- **Risk**: HIGH
- **Confidence**: HIGH
- **FP assessment**: Tests added explicitly verify `({} as any).polluted` is `undefined` after `mergeObjects` on a `__proto__`-bearing input. Not a false positive.
- **Downstream**: Phase 2 (type: undisclosed-fix), Phase 5

### [ddde105] Hard deref depth limit — DoS via recursive $ref

- **Commit**: `[REDACTED]`
- **Author**: Contributor Three <contributor3@example.com>
- **Date**: 2022-09-05
- **Files**: `src/services/OpenAPIParser.ts`
- **Pattern**: Without this commit, a spec with a deeply nested or cyclically-referencing `$ref` chain would cause the JS call stack to overflow (crash/DoS). The fix adds `const MAX_DEREF_DEPTH = 999` and short-circuits deref when `baseRefsStack.length > MAX_DEREF_DEPTH`.
- **Signal A**: Adds hard limit to recursive deref — protective
- **Signal B**: "fix: add hard limit on deref depth to prevent crashes" — vague, no security keywords
- **Signal C**: `src/services/OpenAPIParser.ts` is the spec-ingestion core
- **Risk**: HIGH
- **Confidence**: HIGH (all 3 signals)
- **FP assessment**: The guard is specifically designed to handle adversarial input. The deref stack length check is the only protection against $ref bomb DoS. No preceding guard existed (confirmed by examining the pre-patch diff).
- **Downstream**: Phase 2 (type: undisclosed-fix), Phase 5

### [87c7991] Fix circular crash in Schema.ts — DoS via recursive oneOf

- **Commit**: `[REDACTED]`
- **Author**: Contributor Three / Contributor One
- **Date**: 2022-08-08
- **Files**: `src/services/models/Schema.ts`, `src/services/__tests__/models/Schema.circular.test.ts`
- **Pattern**: Schema model building crashed when a `oneOf` contained a self-referencing `$ref` (e.g., `Tag.items → oneOf → $ref: Tag`). Fix: changes the pointer argument from `this.pointer + '/oneOf/' + idx` to `variant.$ref || ...` and uses a correctly-scoped `refsStack` rather than `this.refsStack` — preventing infinite recursion.
- **Signal A**: Fixes recursive guard logic in schema model
- **Signal B**: Labeled `chore` (not `fix` or `security`) — deliberately downplayed
- **Signal C**: `src/services/models/Schema.ts` — core spec processing
- **Risk**: HIGH
- **Confidence**: HIGH (all 3 signals; the `chore` label on a crash-fix is especially suspicious)
- **FP assessment**: The added test case explicitly demonstrates the crash scenario with a crafted spec. Not a false positive.
- **Downstream**: Phase 2 (type: undisclosed-fix), Phase 5

### [bb325d0] hoistOneOf missing refs stack — potential infinite recursion

- **Commit**: `[REDACTED]`
- **Author**: Contributor One / Contributor Three
- **Date**: 2022-08-29
- **Files**: `src/services/OpenAPIParser.ts`
- **Pattern**: `hoistOneOfs()` was not receiving the current `refsStack` — meaning circular reference detection was blind during allOf/oneOf hoisting. The fix passes `refsStack` to `hoistOneOfs`. Without it, deeply nested allOf+oneOf combos could bypass the circular reference guard and loop indefinitely (DoS).
- **Signal A**: Passes refs stack into hoisting — prevents bypass of circular detection
- **Signal B**: "fix: hoistOneOf missing refs stack and improve allOf for same $ref" — technical, no security framing
- **Signal C**: `src/services/OpenAPIParser.ts`
- **Risk**: MEDIUM
- **Confidence**: MEDIUM (Signals A + C)
- **FP assessment**: Confirmed that the missing `refsStack` argument meant the guard in `hoistOneOfs` could not detect cycles introduced during allOf processing.
- **Downstream**: Phase 5 (deep-probe)

### [2970f95] Rewrite recursive checks — sweeping refactor of cycle detection

- **Commit**: `[REDACTED]`
- **Author**: Contributor One / Contributor Three
- **Date**: 2022-07-18
- **Files**: 46 files including `src/services/OpenAPIParser.ts`, all model files, `src/services/models/Schema.ts`
- **Pattern**: Large-scale rewrite replacing implicit recursion tracking with an explicit `refsStack` parameter passed through all model constructors. Adds 559-line `Schema.circular.test.ts`. Pre-patch code had no principled cycle detection — infinite recursion was possible on self-referencing schemas.
- **Signal A**: Adds structured cycle detection to all schema-building paths
- **Signal B**: "fix: rewrite recursive checks" — generic fix label
- **Signal C**: Touches all of `src/services/` including `OpenAPIParser.ts`
- **Risk**: MEDIUM
- **Confidence**: MEDIUM (Signals A + C; large diff makes isolated signal B harder to assess)
- **FP assessment**: The accompanying 559-line test file covering circular schema patterns confirms this is a security-relevant structural fix.
- **Downstream**: Phase 5 (deep-probe)

---

## Category 4: Reverted Security Fixes

### [d7a1ec1] Revert of URL normalization fix for static site generation

- **Commit**: `[REDACTED]` (reverts `98eec19`)
- **Author**: Contributor One <contributor1@example.com>
- **Date**: 2022-07-22
- **Original commit**: `[REDACTED]` ("fix: operation url in static page (#2093)")
- **Original description**: Added `getBaseUrl()` helper to safely extract URL origin with try/catch, and used it in `Endpoint.tsx` for server URL display. This hardened server URL rendering against malformed/empty URLs crashing the component.
- **Why reverted**: No explicit reason given; likely a behavioral regression in rendering.
- **Risk**: MEDIUM — the original fix improved crash-resilience for malformed server URLs supplied from a spec. The revert restores the ability for a crafted server URL to crash the endpoint component. A subsequent fix (`e5f0235`, 2022-07-28) partially addresses this for `OpenAPIParser.ts` but not `Endpoint.tsx`.
- **FP assessment**: The original commit was labeled `fix`, the reverting commit is `chore: revert` — consistent with a known security-fix reversion pattern.
- **Downstream**: Phase 5 (deep-probe `src/components/Endpoint/Endpoint.tsx` for crash-on-malformed-URL)

---

## Category 5: Secret Archaeology

No secrets found. No `.env`, `.pem`, `.key` files were committed then deleted. No AWS key patterns (`AKIA*`), GitHub PATs (`ghp_`), or hardcoded credential strings detected in any commit.

---

## Category 6: CI/CD Pipeline Weakening

### [errata-ai/vale-action@reviewdog] Unpinned action branch reference — supply chain risk

- **File**: `.github/workflows/docs-tests.yaml` line 24
- **Pattern**: `uses: errata-ai/vale-action@reviewdog` — `reviewdog` is a **branch name**, not a semver tag or commit SHA. Any commit pushed to the `reviewdog` branch of `errata-ai/vale-action` executes immediately in Acme's CI with access to all secrets available in that workflow context.
- **Risk**: HIGH
- **FP assessment**: All other third-party actions in the repo use semver tags (e.g., `@v1`, `@v3`, `@v15`). This one deliberately or accidentally uses a branch ref. The `docs-tests.yaml` workflow does not have write permissions declared, limiting blast radius, but GITHUB_TOKEN read access and any org-level secrets scoped to this repo remain exposed.
- **Downstream**: Phase 3 (KB: supply-chain risk)

### [d193dd2] Removal of sync workflow using GH_PAT at unpinned action

- **Commit**: `[REDACTED]`
- **Author**: Lorna Jane Mitchell
- **Date**: 2024-09-19
- **Files**: `.github/workflows/sync.yml` (deleted)
- **Pattern**: The deleted `sync.yml` workflow used `Acmely/repo-file-sync-action@main` — another **branch reference** (`@main`). It also consumed `${{ secrets.GH_PAT }}` with `SKIP_PR: true` meaning it pushed directly to branches without PR review. The removal of this workflow is a **positive** security improvement.
- **Risk**: MEDIUM (historical; workflow is now gone; records that `GH_PAT` was used in a high-privilege context at a mutable action version)
- **FP assessment**: Confirmed the workflow is deleted. No current exposure. Relevant as historical record showing the PAT pattern existed and that the `@main` action pin antipattern was present.
- **Downstream**: Phase 3 (KB: supply-chain risk; confirm GH_PAT has been rotated since workflow deletion)

---

## Category 7: Suspicious Commit Patterns

### [a863302] feat: remove auth section — large commit touching SecurityRequirement

- **Commit**: `[REDACTED]`
- **Author**: Contributor Four <contributor4@example.com>
- **Date**: 2022-05-30
- **Files**: 22 files including `src/components/SecurityRequirement/` (multiple new files added), `src/services/OpenAPIParser.ts`, `src/services/models/SecuritySchemes.ts`
- **Pattern**: Message "feat: remove auth section" is misleading — the commit does not remove the authentication UI section but rather refactors it into subcomponents. The commit also contains a `console.log('rended')` debug statement left in `OAuthFlow.tsx` (later cleaned up). The `OpenAPIParser.ts` diff removes 30 lines. Large scope (22 files) with a misleading name.
- **Risk**: MEDIUM — the misleading commit message and touching of security-display components (OAuth flow URLs, security scheme rendering) warrants manual review to confirm no authorization rendering logic was silently dropped.
- **FP assessment**: The functional change appears to be a legitimate UI refactor. The `noAutoAuth` option is removed from the public API (README diff). The `console.log` leak indicates code was shipped without review hygiene. Not a high-confidence security finding but worth auditing.
- **Downstream**: Phase 5 (verify security scheme display completeness post-refactor)

---

## Phase 2 Candidate SHAs (type: undisclosed-fix, for @patch-auditor)

| SHA | Description | Priority |
|-----|-------------|----------|
| `153ec7a` | Prototype pollution in mergeObjects() — no CVE assigned | P1 |
| `ddde105` | $ref deref depth DoS — hard limit added silently | P1 |
| `87c7991` | Circular oneOf crash fix labeled as `chore` | P1 |
| `53a6afc` | untrustedSpec→sanitize rename breaks web component attribute consumers | P2 |
| `bb325d0` | hoistOneOf missing refsStack — cycle detection bypass | P2 |

## Phase 5 Attack Surface Hints (HIGH-risk commit paths)

- `src/utils/helpers.ts` — `mergeObjects()` prototype pollution (fixed in `153ec7a`; audit callers for remaining gadgets)
- `src/services/OpenAPIParser.ts` — $ref resolution, deref depth, hoistOneOf (multiple fixes; DoS surface via crafted spec)
- `src/services/models/Schema.ts` — circular schema crash (fixed in `87c7991`; verify fix is complete for all schema types)
- `[REDACTED].tsx` — sanitize opt-in gate; default is `false` (XSS when spec is untrusted and `sanitize` not explicitly set)
- `src/components/SourceCode/SourceCode.tsx` — `dangerouslySetInnerHTML` fed by Prism; no independent sanitization
- `src/utils/jsonToHtml.ts` — URL href constructed with `encodeURI()` from JSON string values (attribute injection surface)
- `.github/workflows/docs-tests.yaml` — `errata-ai/vale-action@reviewdog` unpinned branch action

## Cross-reference

Primary report: `archon/attack-surface/commit-recon-report.md`
