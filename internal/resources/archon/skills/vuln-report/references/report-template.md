# Report Template

Use this template for a single confirmed vulnerability. Remove placeholder notes before final output.

## Required Shape

Save the final report as `report.md` inside a folder named with a lowercase hyphenated slug derived from the final report title.

```md
# Optional short title

## Summary

[One paragraph: vulnerable behavior, attacker control, outcome.]

## Details

[Explain the execution path, validation gap, parser behavior, state assumptions, and why the protection fails.]

Relevant source:
- [`path/to/file.ext`](https://github.com/org/repo/blob/main/path/to/file.ext#L10)
- [`path/to/helper.ext`](https://github.com/org/repo/blob/main/path/to/helper.ext#L22)

```language
// Small decisive snippet from the vulnerable path
```

## Root Cause

[Name the specific implementation or design flaw that makes the bug possible.]

## Proof of Concept (PoC)

1. [Setup step]
2. [Exploit step]
3. [Observed or expected result]

```bash
# Minimal reproducible command or request
```

## Impact

[State who is affected, under what conditions, and what the attacker can achieve.]
```

## Optional Sections

Insert these only when supported by evidence and useful to the reader:

- `Vulnerability Type`
- `CWE`
- `CVSS v3.1`
- `Authentication Reality`
- `Affected Surfaces`
- `Specification and Guidance References`
- `Patch Commit`
- `Scope`
- `Exploit Constraints`

## Writing Rules

### Global

- Include fenced code snippets in every report.
- Use GitHub markdown links for repository files, line anchors, and commits.
- Prefer linked file paths over bare URLs.
- Store the finished report at `<title-slug>/report.md`, where `<title-slug>` is derived from the final title.

### Summary

- Keep it to one paragraph.
- Mention the attacker-controlled input or missing validation.
- State the resulting security effect.

### Details

- Walk from input to sink.
- Name the exact branch, handler, parser, or validation gate when known.
- Include code snippets for the decisive check or omission.
- Add GitHub markdown links next to the source references.
- Record deployment-specific assumptions explicitly.

### Root Cause

- State the fault, not the symptom.
- Tie the fault to the exploit path from `Details`.

### Proof of Concept (PoC)

- Prefer the highest-confidence path.
- Keep steps deterministic.
- Say what result confirms success.
- Use `Expected result:` when the effect is not obvious from the command alone.

### Impact

- Explain practical consequence first.
- Add severity signals such as CVSS only if they help triage.
- Distinguish default exposure from non-default but realistic exposure.

## Normalization Rules

Normalize inconsistent source material into this shape:

- Fold `Technical Details` into `Details` unless the repository clearly prefers the longer heading.
- Keep `Root Cause` nested under `Technical Details` only when matching an established house style.
- Convert loose notes into concrete statements with actor, condition, and outcome.
- Remove duplicate impact language repeated across sections.
- Replace plain repository paths with GitHub markdown links whenever possible.

## Do Not Do This

- Do not combine multiple bugs in one report.
- Do not add `Affected Components` or `Remediation` sections by default.
- Do not use bare repository paths when a GitHub markdown link is available.
- Do not claim code execution, data exposure, or auth bypass unless the evidence supports it.
- Do not bury the main exploit condition inside a long background section.
