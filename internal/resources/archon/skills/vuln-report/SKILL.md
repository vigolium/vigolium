---
name: vuln-report
description: Draft a single-vulnerability report in GitHub advisory style from an audit finding, bug note, patch diff, PoC, or code review evidence. Use when Codex needs to turn one confirmed security issue into a clean disclosure-ready report with Summary, Details, Root Cause, Proof of Concept, Impact, embedded code snippets, explanatory prose that points to the vulnerable code, inline GitHub markdown links to source evidence, and clearly-scoped optional sections such as CWE, CVSS, references, attack preconditions, or patch metadata.
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
7. Add only the optional sections that materially improve accuracy or triage value.
8. Save the final report as `report.md` inside a folder named with the bug's severity identifier (`C1`, `H1`, `M1`, etc.) followed by a lowercase hyphenated slug derived from the final report title. Use `C` for Critical, `H` for High, `M` for Medium, sequentially numbered if there are multiple bugs of the same severity. Example: `C1-cross-site-websocket-hijacking-re-enabled-by-allow-websocket/report.md`. Also, ensure the bug report title and internal references use this ID (e.g., '[C1] Cross-Site WebSocket Hijacking'). Do not write reports for Low severity findings — document them in the summary table only.
9. Remove filler, hedging, and unproven claims before finalizing.

## Required Sections

Always include these sections in this order:

1. `Summary`
2. `Details`
3. `Root Cause`
4. `Proof of Concept (PoC)`
5. `Impact`

If the repository already uses `Technical Details` with `Root Cause` nested under it, preserve that local pattern. Otherwise keep `Root Cause` as its own section.

## Evidence Rules

- Include one or more fenced code snippets in the report, usually in `Details` or `Root Cause`.
- Use the smallest snippet that proves the bug.
- Introduce each cited code location with a short explanation of why it matters; do not drop raw link lists without commentary.
- Add GitHub markdown links for source files, line anchors, controllers, helpers, patch commits, or affected surfaces whenever the repository is on GitHub and the target URL is known or can be derived.
- When constructing GitHub source links, use the latest commit SHA (from `git rev-parse HEAD` or the most recent commit visible in context) instead of a branch name such as `main` or `master`, so links remain stable after future commits.
- Prefer embedding inline markdown links into explanatory sentences such as `The following code in [build_request](https://github.com/org/repo/blob/main/src/executor.rs#L10) reads attacker-controlled input without validation.`
- Keep non-GitHub standards or spec citations as normal markdown links.

## Section Rules

### Summary

Open with the vulnerable behavior, attacker control, and outcome in one short paragraph. Name the component only if it improves clarity.

### Details

Explain the code path and why the protection fails. Include relevant conditions such as auth mode, stateless mode, parser behavior, MIME confusion, or transport assumptions. Support the explanation with code snippets and GitHub markdown links to the exact source locations.

### Root Cause

State the design or implementation mistake in one focused subsection. Prefer causal language such as missing origin validation, unsafe trust in extension-derived MIME, or policy enforced only in one execution mode.

### Proof of Concept (PoC)

Use the shortest reliable reproduction. Prefer numbered steps and a runnable request, command, or code block. State the expected result.

### Impact

Describe exploitability and consequence, not just severity labels. Cover who is exposed, what an attacker gains, and which environments are most at risk.

## Optional Sections

Include an optional section only when it adds concrete triage value.

Allowed optional sections include:

- short report title at the top
- vulnerability type
- `CWE`
- `CVSS` vector or severity guidance
- attack preconditions or authentication reality
- affected surfaces or scope notes
- specification or guidance references
- patch or fix-commit metadata
- exploit constraints, non-default assumptions, or deployment qualifiers

Do not add `Affected Components` or `Remediation` sections unless the user explicitly asks for them.

## Quality Bar

- Keep one bug per report.
- Number bugs using severity prefixes (C1, H1, M1) and prefix both the report title and the folder name with this ID. Low severity findings are not reported individually.
- Save each single-bug report to `<ID>-<title-slug>/report.md`.
- Make the exploit story readable without external context.
- Use exact file paths, endpoints, headers, options, or modes when they matter.
- Distinguish observed behavior from likely impact.
- Prefer measured severity language over inflated claims.
- Preserve repository-specific terminology if the source material already uses it.
- Include fenced code snippets and GitHub markdown links in every report.
- End with a report that can be pasted into an advisory, audit finding, or maintainer issue with minimal cleanup.
