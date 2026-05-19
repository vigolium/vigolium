---
name: triage-finding
description: Deduplicate, prioritize, and sanity-check a list of raw scanner findings. Use after a dynamic scan completes or when the user asks to review a findings dump. Produces a triaged list with severity adjustments, false-positive calls, and exploitability notes.
license: MIT
allowed-tools:
  - read_file
  - bash
  - report_finding
---

# Finding Triage

You are triaging scanner findings. The input is a list of raw findings
produced by native scanners or earlier agent passes. Your job is to turn
that noisy list into a decision-quality report.

## What triage means here

For each finding, decide one of:

- **Keep as-is** — concrete bug, severity accurate, ready to report.
- **Keep + adjust** — real bug but severity is wrong given the context
  (e.g., reflected XSS on a login-required admin endpoint isn't critical).
- **Duplicate** — same root cause as another finding. Mark secondary
  copies as duplicates of the canonical one; don't re-report them.
- **False positive** — the scanner was wrong. State the specific reason
  (e.g., "the payload was reflected inside a `<script>` block that is
  JSON-parsed, not executed").
- **Needs PoC** — plausible but unverified. Outline what a proof-of-concept
  would look like; don't fabricate evidence.

## Severity calibration

Use this rubric. Downgrade if the exploit preconditions are not met.

| Severity | Meaning | Preconditions that DOWNGRADE |
|----------|---------|------------------------------|
| critical | Unauthenticated RCE / auth bypass on primary user path | Requires admin; requires ≥2 other bugs chained |
| high     | Auth bypass, stored XSS on primary path, SQLi with data exfil | Requires local access; reflected-only on low-traffic path |
| medium   | Reflected XSS, IDOR with limited blast radius, insecure deserialization | Requires elevated role; narrow path |
| low      | Info leak without sensitive data, weak TLS config | Covered by WAF / CSP in a way that neutralizes it |

## Recommended workflow

1. **Cluster** — group findings by module + URL path + parameter. Same
   module firing on the same endpoint on multiple HTTP records is almost
   always one bug.
2. **Pick canonical** — for each cluster, pick the finding with the
   clearest evidence as the one to keep.
3. **Cross-check** — for each kept finding, open the referenced file(s)
   via `read_file` or check the HTTP request/response body. Validate
   that the evidence actually demonstrates the issue.
4. **Re-emit** — for each triaged finding that survives, call
   `report_finding` with the adjusted severity and a one-line
   rationale in the description (e.g., "Confirmed: payload reflected
   un-encoded in `/search` response body").

## Rules

- Never fabricate evidence. If unsure, mark "Needs PoC" and explain what
  would prove it.
- Duplicates: **do not re-emit via `report_finding`**. Just list them in
  your final message under "Duplicates" with the canonical ID.
- False positives: emit via `report_finding` with `status: false_positive`
  so the DB reflects the triage decision. Include the reason in
  `description`.
- Keep the final summary terse — the database is authoritative; the
  message is for the human reviewer.

## Output expectations

- Every surviving finding persisted via `report_finding`.
- One-paragraph final summary: total input count, kept, duplicates,
  false-positives, needs-PoC.
- No speculative severity bumps — if you can't justify it with evidence
  in the response body or code, don't raise the severity.
