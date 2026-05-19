---
name: vuln-report
description: Draft a single-vulnerability report in GitHub advisory style from an audit finding, bug note, patch diff, PoC, or code review evidence. Use when Codex needs to turn one confirmed security issue into a clean disclosure-ready report with the fixed section set — Summary; Severity, Confidence, Vulnerability Type; Impact; Affected Component; Source to Sink Flow; Vulnerable Code; Proof of concept & Evidence; Preconditions; Remediation — with embedded code snippets, explanatory prose that points to the vulnerable code, and inline GitHub markdown links to source evidence.
---

# vuln-report.md

## Overview

Draft one disclosure-ready report for one confirmed bug. Keep the report evidence-driven, concrete, and concise. Prefer the section order and phrasing rules in [references/report-template.md](references/report-template.md).

## Workflow

1. Confirm the report is about one bug only.
2. Extract the minimum facts needed to prove the issue:
   - vulnerable component or behavior
   - attacker-controlled input or missing validation
   - preconditions and trust boundary
   - exploit result
   - practical impact
   - strongest reproduction path
   - decisive source locations and any relevant fix commit
3. Separate demonstrated facts from inference. State assumptions explicitly.
4. Draft the report using the required section order from [references/report-template.md](references/report-template.md).
5. Always embed at least one fenced code snippet from the decisive code path, and explain what each snippet proves.
6. Always convert repository file references and patch references into GitHub markdown links, and prefer embedding those links directly into the surrounding explanation instead of listing them separately.
7. Keep the nine-section contract exactly; fold any enrichment (CWE/CVSS, preconditions, references) inside the relevant required section rather than adding new H2s.
8. Save the final report as `report.md` inside a folder named with the bug's severity identifier (`C1`, `H1`, `M1`, etc.) followed by a lowercase hyphenated slug derived from the final report title. Use `C` for Critical, `H` for High, `M` for Medium, sequentially numbered if there are multiple bugs of the same severity. Example: `C1-cross-site-websocket-hijacking-re-enabled-by-allow-websocket/report.md`. Also, ensure the bug report title and internal references use this ID (e.g., '[C1] Cross-Site WebSocket Hijacking'). Do not write reports for Low severity findings — document them in the summary table only.
9. Remove filler, hedging, and unproven claims before finalizing.

## Required Sections

The report begins with a single `# <Finding Title>` H1 (prefixed with the
severity ID, e.g. `# [C1] SQL Injection in Login`), then exactly these H2
sections, in this order, with these exact headings:

1. `## Summary`
2. `## Severity, Confidence, Vulnerability Type`
3. `## Impact`
4. `## Affected Component`
5. `## Source to Sink Flow`
6. `## Vulnerable Code`
7. `## Proof of concept & Evidence`
8. `## Preconditions`
9. `## Remediation`

This is a fixed contract — every report uses this exact set and order so the
report-composer and downstream tooling can parse sections deterministically.
Do **not** add a standalone `Details` or `Root Cause` section: the root-cause
analysis is the closing paragraph of `## Source to Sink Flow`. Do not rename,
reorder, merge, or drop any of the nine required sections even if a section is
thin — write `None.` or `Not applicable.` rather than omitting it.

## Evidence Rules

- Include one or more fenced code snippets in the report, primarily in `Vulnerable Code` (and `Source to Sink Flow` where a snippet clarifies the path).
- Use the smallest snippet that proves the bug.
- Introduce each cited code location with a short explanation of why it matters; do not drop raw link lists without commentary.
- Add GitHub markdown links for source files, line anchors, controllers, helpers, patch commits, or affected surfaces whenever the repository is on GitHub and the target URL is known or can be derived.
- When constructing GitHub source links, use the latest commit SHA (from `git rev-parse HEAD` or the most recent commit visible in context) instead of a branch name such as `main` or `master`, so links remain stable after future commits.
- Prefer embedding inline markdown links into explanatory sentences such as `The following code in [build_request](https://github.com/org/repo/blob/main/src/executor.rs#L10) reads attacker-controlled input without validation.`
- Keep non-GitHub standards or spec citations as normal markdown links.

## Self-Contained Rule

`report.md` is a disclosure-ready artefact. The reader must understand the vulnerability, the trace, the impact, and the reproduction without opening any sibling working file (drafts, debate transcripts, review notes, internal metadata).

- Do not write prose pointers such as `See draft.md`, `See debate.md`, `See adversarial-review.md`, `See metadata.json`, `See pN-NNN for full trace`, `See AP-NNN`, `Refer to the draft for impact analysis`, or `for the full trace see ...`. If that content is needed in the report, **inline it**.
- Do not cite internal phase IDs (`pN-NNN`, `p10-NNN`, `AP-NNN`) — these are pipeline bookkeeping, not reader-facing references.
- Sibling-file references are only allowed for runnable evidence artefacts shipped alongside the report (e.g. `poc.<ext>`, `evidence/<file>`), and only inside the `Proof of concept & Evidence` or `Impact` sections. Quote the decisive lines from logs inline rather than telling the reader to open them.
- GitHub links to source code (pinned to a commit SHA) are external evidence, not deferred narrative — those are required, not banned.
- Before finalizing, scan the draft for the banned phrasings above and rewrite any occurrence to inline the content.

## Section Rules

### Summary

One short paragraph: the vulnerable behavior, the attacker control, and the outcome. Name the component only if it improves clarity.

### Severity, Confidence, Vulnerability Type

A compact block, not prose. State **Severity** (Critical/High/Medium with a one-line justification or CVSS vector), **Confidence** (how certain the finding is — e.g. `Confirmed (PoC executed)`, `Firm (code-traced, PoC theoretical)`, `Tentative`), and **Vulnerability Type** (the class, with `CWE-NNN` when known). This is the section that absorbs CWE/CVSS enrichment.

### Impact

Describe exploitability and consequence, not just severity labels: who is exposed, what the attacker gains, and which environments are most at risk. Distinguish observed impact (from `evidence/` logs) from inferred impact.

### Affected Component

Name the concrete component(s), service(s), endpoint(s), or module(s) in scope, with the primary file path(s). Keep it to the surface the bug lives on — not the full trace (that is the next section).

### Source to Sink Flow

Walk the path from attacker-controlled **source** to the dangerous **sink**: the exact entry point, the handlers/parsers/validation gates it passes, and where the protection is missing or bypassed. Name the specific branch, handler, or check. **Close this section with the root cause** — one or two sentences naming the design or implementation mistake in causal language (missing origin validation, unsafe trust in extension-derived MIME, policy enforced only in one execution mode, …). There is no separate Root Cause section; it lives here.

### Vulnerable Code

The smallest fenced code snippet(s) that prove the bug, each introduced by a one-line explanation of why it matters and accompanied by a GitHub markdown link pinned to the commit SHA. This is the decisive-snippet section — keep it tight.

### Proof of concept & Evidence

The shortest reliable reproduction: numbered steps and a runnable request/command/code block, with the expected result. If `poc.<ext>` exists, describe it in prose and reference its path; if `evidence/exploit.log` / `evidence/impact.log` exist, quote the decisive lines inline that prove the security effect. If there is no working PoC (theoretical/blocked finding), state that explicitly as `No working PoC — <PoC-Status>: <reason>` and fall back to the code-level evidence that establishes the bug.

### Preconditions

The conditions an attacker needs: authentication reality (`Auth-Required: yes/no` and which roles), attack vector / network position (remote vs local), non-default configuration, required state, and any exploit constraints. Absorbs the old "attack preconditions / authentication reality" enrichment.

### Remediation

The concrete fix: what to change and why it closes the source-to-sink gap. Include spec/guidance references or the fixing-commit metadata here when relevant. Prefer specific, actionable guidance over generic advice.

## Enrichment Inside Required Sections

There are no extra top-level sections. Anything that used to be an optional
section now lives **inside** one of the nine required sections:

- `CWE`, `CVSS` vector, and the vulnerability class → `## Severity, Confidence, Vulnerability Type`
- authentication reality, non-default assumptions, exploit constraints, deployment qualifiers → `## Preconditions`
- specification / guidance references, patch or fix-commit metadata → `## Remediation` (or inline in `## Source to Sink Flow` where it explains the gap)
- affected surfaces / scope notes → `## Affected Component`

Add this enrichment only when it is supported by evidence and improves triage.
Never promote it to its own H2.

## Quality Bar

- Keep one bug per report.
- Number bugs using severity prefixes (C1, H1, M1) and prefix both the report title and the folder name with this ID. Low severity findings are not reported individually.
- Save each single-bug report to `<ID>-<title-slug>/report.md`.
- Make the exploit story readable without external context — and explicitly without opening any sibling working file (`draft.md`, `debate.md`, `adversarial-review.md`, `metadata.json`). See the Self-Contained Rule.
- No pointer prose to sibling narrative files or internal phase IDs (`pN-NNN`, `AP-NNN`). Inline the content.
- Use exact file paths, endpoints, headers, options, or modes when they matter.
- Distinguish observed behavior from likely impact.
- Prefer measured severity language over inflated claims.
- Preserve repository-specific terminology if the source material already uses it.
- Include fenced code snippets and GitHub markdown links in every report.
- End with a report that can be pasted into an advisory, audit finding, or maintainer issue with minimal cleanup.
