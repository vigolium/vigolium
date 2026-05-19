# Confirmation Report

| Field | Value |
|-------|-------|
| Audit ID | 2026-05-18T17:45:30Z |
| Repository | acme |
| Confirmed at | 2026-05-19T04:42:41Z |
| Environment | dockerfile (http://localhost:80) |
| Original audit mode | deep |
| Findings staging | `archon/confirm-workspace/confirmed-findings/` + `unconfirmed-findings/` (grouped by verdict category) |

## Summary

| Status | Count | Findings |
|--------|-------|----------|
| confirmed-live | 3 | H3, H5, H6 |
| confirmed-test | 12 | H1, H2, H4, M1, M10, M2, M4, M5, M6, M7, M8, M9 |
| confirmed-fp | 0 | — |
| analytical-only | 0 | — |
| unconfirmed | 0 | — |
| inconclusive | 0 | — |
| blocked | 0 | — |
| no-poc | 0 | — |
| error | 0 | — |

**Confirmation rate**: 15/15 findings confirmed (100.0%) — `confirmed-fp` and `analytical-only` are excluded from the denominator.

## Breakdown by Exploitability Class

| Class | Total | confirmed-live | confirmed-test | unconfirmed | blocked | analytical-only |
|-------|-------|----------------|----------------|-------------|---------|-----------------|
| network-exploitable | 4 | 3 | 1 | 0 | 0 | 0 |
| local-exploitable | 11 | 0 | 11 | 0 | 0 | 0 |
| non-exploitable | 0 | 0 | 0 | 0 | 0 | 0 |

## Confirmed Findings (Live)

### H3 — Oauth Url Javascript Injection [High]

- **Vulnerability**: XSS
- **Method**: PoC executed against dockerfile (http://localhost:80)
- **Evidence**: `archon/findings/H3-oauth-url-javascript-injection/confirm-evidence/`
- **Execution time**: n/a
- **Observation**: Live PoC showed multiple spec-controlled URL fields reach href sinks with no scheme validation.

---

### H5 — Ssrf Externalvalue Fetch No Allowlist [High]

- **Vulnerability**: SSRF / Read-Out SSRF
- **Method**: PoC executed against dockerfile (http://localhost:80)
- **Evidence**: `archon/findings/H5-ssrf-externalvalue-fetch-no-allowlist/confirm-evidence/`
- **Execution time**: n/a
- **Observation**: Live PoC showed externalValue triggers bare fetch() to attacker-chosen internal URLs.

---

### H6 — Ssrf Via Ref Customfetch No Allowlist [High]

- **Vulnerability**: SSRF / Bundler-Side
- **Method**: PoC executed against dockerfile (http://localhost:80)
- **Evidence**: `archon/findings/H6-ssrf-via-ref-customfetch-no-allowlist/confirm-evidence`
- **Execution time**: n/a
- **Observation**: Live PoC captured an outbound GET to an attacker-supplied absolute $ref URL.

---

## Confirmed Findings (Test)

### H1 — Spec Href Javascript Scheme Xss [High]

- **Vulnerability**: XSS
- **Method**: Generated Jest/ts-jest reproducer test
- **Test file**: `archon/findings/H1-spec-href-javascript-scheme-xss/confirm-test.ts`
- **Test output**: `archon/findings/H1-spec-href-javascript-scheme-xss/confirm-test-output.log`
- **Observation**: Generated test showed javascript: URLs survive model + rendering paths into href attributes.

---

### H2 — Dompurify Outdated Mxss [High]

- **Vulnerability**: XSS
- **Method**: Generated Jest/ts-jest reproducer test
- **Test file**: `archon/findings/H2-dompurify-outdated-mxss/confirm-test.ts`
- **Test output**: `archon/findings/H2-dompurify-outdated-mxss/confirm-test-output.log`
- **Observation**: Generated test reproduced mXSS with DOMPurify 3.2.4 output re-parsed into an executable sink.

---

### H4 — Html Attribute Overrides Js Options [High]

- **Vulnerability**: hidden-control-channel
- **Method**: Generated Jest/ts-jest reproducer test
- **Test file**: `archon/findings/H4-html-attribute-overrides-js-options/confirm-test.test.ts`
- **Test output**: `archon/findings/H4-html-attribute-overrides-js-options/confirm-test-output.log`
- **Observation**: Generated test showed <acme sanitize="false"> overrides JS options during standalone init.

---

### M1 — Parseprops Redos [Medium]

- **Vulnerability**: ReDoS
- **Method**: Generated Jest/ts-jest reproducer test
- **Test file**: `archon/findings/M1-parseprops-redos/confirm-test.ts`
- **Test output**: `archon/findings/M1-parseprops-redos/confirm-test-output.log`
- **Observation**: Generated test showed parseProps exhibits regex-based slowdown on crafted markdown component props.

---

### M10 — Findderived Quadratic Dos [Medium]

- **Vulnerability**: Parser DoS / Algorithmic Complexity
- **Method**: Generated Jest/ts-jest reproducer test
- **Test file**: `archon/findings/M10-findderived-quadratic-dos/confirm-test.ts`
- **Test output**: `archon/findings/M10-findderived-quadratic-dos/confirm-test-output.log`
- **Observation**: Generated test showed findDerived performs quadratic work as derived schema count increases.

---

### M2 — Component Regexp Cross Line Redos [Medium]

- **Vulnerability**: ReDoS
- **Method**: Generated Jest/ts-jest reproducer test
- **Test file**: `archon/findings/M2-component-regexp-cross-line-redos/confirm-test.test.ts`
- **Test output**: `archon/findings/M2-component-regexp-cross-line-redos/confirm-test-output.log`
- **Observation**: Generated test reproduced regex slowdown in multi-line markdown component parsing.

---

### M4 — Allof Breadth Dos No Limit [Medium]

- **Vulnerability**: Parser DoS / Algorithmic Complexity
- **Method**: Generated Jest/ts-jest reproducer test
- **Test file**: `archon/findings/M4-allof-breadth-dos-no-limit/confirm-test.ts`
- **Test output**: `archon/findings/M4-allof-breadth-dos-no-limit/confirm-test-output.log`
- **Observation**: Generated test demonstrated unbounded allOf breadth drives excessive dereference/merge work.

---

### M5 — Hoistoneofs Exponential Schema Dos [Medium]

- **Vulnerability**: Parser DoS / Exponential Complexity
- **Method**: Generated Jest/ts-jest reproducer test
- **Test file**: `archon/findings/M5-hoistoneofs-exponential-schema-dos/confirm-test.ts`
- **Test output**: `archon/findings/M5-hoistoneofs-exponential-schema-dos/confirm-test-output.log`
- **Observation**: Generated test showed hoistOneOfs work grows sharply on nested schema bombs.

---

### M6 — X Refsstack Injection Cycle Detection Bypass [Medium]

- **Vulnerability**: Integrity / Cycle Detection Bypass
- **Method**: Generated Jest/ts-jest reproducer test
- **Test file**: `archon/findings/M6-x-refsstack-injection-cycle-detection-bypass/confirm-test.ts`
- **Test output**: `archon/findings/M6-x-refsstack-injection-cycle-detection-bypass/confirm-test-output.log`
- **Observation**: Generated test showed x-refsStack pollution can bypass intended cycle-detection assumptions.

---

### M7 — Decodeuri Before Pointer Cross Section Traversal [Medium]

- **Vulnerability**: Pointer Injection / Type Confusion
- **Method**: Generated Jest/ts-jest reproducer test
- **Test file**: `archon/findings/M7-decodeuri-before-pointer-cross-section-traversal/confirm-test.ts`
- **Test output**: `archon/findings/M7-decodeuri-before-pointer-cross-section-traversal/confirm-test-output.log`
- **Observation**: Generated test showed decode-before-split lets encoded pointers cross intended section boundaries.

---

### M8 — Webhooks Parser Bug Parity [Medium]

- **Vulnerability**: Parser DoS / Attack Surface Multiplier
- **Method**: Generated Jest/ts-jest reproducer test
- **Test file**: `archon/findings/M8-webhooks-parser-bug-parity/confirm-test.ts`
- **Test output**: `archon/findings/M8-webhooks-parser-bug-parity/confirm-test-output.log`
- **Observation**: Generated test confirmed webhook parsing inherits the same parser DoS behavior as path operations.

---

### M9 — Searchstore Indexitems Unbounded Dos [Medium]

- **Vulnerability**: Post-Parse DoS / Search Worker
- **Method**: Generated Jest/ts-jest reproducer test
- **Test file**: `archon/findings/M9-searchstore-indexitems-unbounded-dos/confirm-test.ts`
- **Test output**: `archon/findings/M9-searchstore-indexitems-unbounded-dos/confirm-test-output.log`
- **Observation**: Generated test showed SearchStore indexes attacker-expanded item sets without practical bounds.

---

## Unconfirmed Findings

None.

## Blocked Findings

None.

## Environment Details

- **Session UUID**: 00000000-0000-4000-8000-000000000000
- **Provisioning method**: dockerfile
- **Actual port** (after fallback): 80
- **Startup duration**: 52 seconds
- **Healthcheck**: / (passed)
- **Containers/processes**: archon-confirm-app-00000000
- **Setup log**: `archon/confirm-workspace/setup.log`

## Auth Context

No test identities were provisioned; all confirmations ran without seeded auth context.
