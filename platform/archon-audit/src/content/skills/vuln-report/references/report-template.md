# Report Template

Use this template for a single confirmed (or theoretical) vulnerability. Remove placeholder notes before final output.

## Required Shape

Save the final report as `report.md` inside the finding directory (`<ID>-<slug>/report.md`). The H1 title is prefixed with the severity ID (e.g. `# [C1] ...`). The nine H2 sections below are a fixed contract — same set, same order, same headings, every time. Never add, rename, reorder, merge, or drop one; if a section is thin write `None.` / `Not applicable.` instead of omitting it.

```md
# [C1] <Finding Title>

## Summary

[One paragraph: vulnerable behavior, attacker control, outcome.]

## Severity, Confidence, Vulnerability Type

- **Severity:** Critical | High | Medium — [one-line justification or CVSS vector]
- **Confidence:** Confirmed (PoC executed) | Firm (code-traced, PoC theoretical) | Tentative
- **Vulnerability Type:** [class, e.g. SQL Injection] (`CWE-NNN`)

## Impact

[Who is affected, under what conditions, and what the attacker achieves. Separate observed impact (evidence/ logs) from inferred impact.]

## Affected Component

[Concrete component / service / endpoint / module in scope, with primary file path(s).]

## Source to Sink Flow

[Walk attacker-controlled source → dangerous sink: entry point, handlers/parsers/validation gates passed, where the protection is missing or bypassed. Name the exact branch/handler/check.]

[Close with the root cause: one or two sentences naming the design or implementation mistake in causal language. There is no separate Root Cause section.]

## Vulnerable Code

[Why this snippet matters:] in [`path/to/file.ext`](https://github.com/org/repo/blob/<sha>/path/to/file.ext#L10):

```language
// Smallest decisive snippet from the vulnerable path
```

## Proof of concept & Evidence

1. [Setup step]
2. [Exploit step]
3. [Observed or expected result]

```bash
# Minimal reproducible command or request
```

[If poc.<ext> exists, name it and quote the decisive evidence/exploit.log or evidence/impact.log lines inline. If there is no working PoC, write: `No working PoC — <PoC-Status>: <reason>` and give the code-level evidence that establishes the bug.]

## Preconditions

[Auth reality (Auth-Required: yes/no + roles), attack vector / network position (remote vs local), non-default config, required state, exploit constraints.]

## Remediation

[Concrete fix: what to change and why it closes the source-to-sink gap. Spec/guidance references or fixing-commit metadata go here when relevant.]
```

## Writing Rules

### Global

- Include fenced code snippets in every report (primarily in `Vulnerable Code`).
- Use GitHub markdown links for repository files, line anchors, and commits, pinned to the commit SHA (`git rev-parse HEAD`), not a branch name.
- Prefer linked file paths over bare URLs.
- Store the finished report at `<ID>-<slug>/report.md`.

### Summary

- One paragraph. Mention the attacker-controlled input or missing validation and the resulting security effect.

### Severity, Confidence, Vulnerability Type

- A compact labelled block, not prose. This is where CWE/CVSS enrichment lives.
- `Confidence` must reflect reality: `Confirmed (PoC executed)` only when a PoC actually ran.

### Impact

- Practical consequence first. Distinguish default exposure from non-default but realistic exposure. Distinguish observed from inferred.

### Affected Component

- The surface the bug lives on (component/endpoint/module + primary path) — not the full trace.

### Source to Sink Flow

- Walk from input to sink; name the exact branch, handler, parser, or validation gate.
- End with the root cause: the fault, not the symptom, tied to the path just described.

### Vulnerable Code

- Smallest snippet(s) that prove the bug, each with a one-line "why it matters" lead-in and a SHA-pinned GitHub link.

### Proof of concept & Evidence

- Highest-confidence, deterministic reproduction. Say what result confirms success (`Expected result:` when not obvious).
- Theoretical/blocked findings: explicitly state `No working PoC — <PoC-Status>: <reason>` then give code-level evidence.

### Preconditions

- Be specific about auth, network position/attack vector, and any non-default requirements.

### Remediation

- Specific, actionable fix tied to the root cause. No generic boilerplate.

## Normalization Rules

Normalize inconsistent source material into this shape:

- Fold any `Details` / `Technical Details` narrative into `Source to Sink Flow`.
- Fold any standalone `Root Cause` content into the closing paragraph of `Source to Sink Flow`.
- Fold `Vulnerability Type` / `CWE` / `CVSS` into `Severity, Confidence, Vulnerability Type`.
- Fold `Authentication Reality` / `Scope` / `Exploit Constraints` into `Preconditions`.
- Fold `Affected Surfaces` into `Affected Component`.
- Convert loose notes into concrete statements with actor, condition, and outcome.
- Remove duplicate impact language repeated across sections.
- Replace plain repository paths with SHA-pinned GitHub markdown links whenever possible.

## Do Not Do This

- Do not combine multiple bugs in one report.
- Do not add, rename, reorder, or drop any of the nine required sections, or introduce extra H2s for enrichment.
- Do not use bare repository paths when a GitHub markdown link is available.
- Do not claim code execution, data exposure, or auth bypass unless the evidence supports it.
- Do not claim `Confirmed (PoC executed)` unless a PoC actually ran.
- Do not bury the main exploit condition inside a long background section.
- Do not point the reader at sibling working files. Phrases like `See draft.md`, `See debate.md`, `See adversarial-review.md`, `See metadata.json`, `See pN-NNN for full trace`, `See AP-NNN`, `Refer to the draft for impact analysis`, or `for the full trace see ...` are banned. If the trace, hypothesis, impact, or adversarial review outcome is needed, inline it. The only sibling files a `report.md` may reference are runnable evidence artefacts (`poc.<ext>`, `evidence/<file>`) shipped alongside it.
- Do not cite internal audit phase IDs (`pN-NNN`, `p10-NNN`, `AP-NNN`) — these are pipeline bookkeeping, not reader-facing references.
