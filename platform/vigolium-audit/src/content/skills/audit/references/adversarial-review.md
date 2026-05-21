# Adversarial Review Methodology (P11-LITE Cold Verification)

Protocol for the Phase 11 Stage 2 cold verification agent. Under the Review Chamber model,
the Devil's Advocate already challenged every finding during the Phase 10 debate. Stage 2 is
therefore **scoped to CRITICAL and HIGH findings only** — Medium findings skip Stage 2 entirely.

## Purpose

The Devil's Advocate challenges findings while the debate context is hot, but shares the
chamber's context window with other agents. Cold verification breaks any residual confirmation
bias by spawning a fresh agent with no access to the chamber debate, forcing fully independent
re-derivation. This is reserved for the highest-severity findings where the cost of a false
positive or missed vulnerability is greatest.

## Isolation Rules

The adversarial reviewer agent receives **only**:
- The finding draft file path (`vigolium-results/findings-draft/<phase>-<NNN>-<slug>.md`)

The adversarial reviewer MUST NOT:
- Read Phase 10 working notes or intermediate analysis files
- Read the original agent's conversation history or reasoning chain
- Read any file in `vigolium-results/` other than the single finding draft it was given
- Be told what the finding agent concluded — only what the finding draft states

The agent spawner must construct the task description from only the finding draft path. Do not include summaries, context, or the finding agent's reasoning.

---

## Step 1 — Restate and Decompose

Read only the finding draft. Restate the vulnerability claim in your own words without copying the original description. Then decompose into testable sub-claims:

- Sub-claim A: Attacker controls input X
- Sub-claim B: Input X reaches code point Y without adequate sanitization
- Sub-claim C: Code point Y causes security effect Z

If any sub-claim is incoherent, logically impossible, or unsupported by the draft, record `Sub-claim failure: <which sub-claim and why>` and proceed to the verdict with DISPROVED.

---

## Step 2 — Independent Code Path Trace

Starting from the entry point stated in the finding draft, trace the code path to the claimed sink independently. Do not rely on the finding draft's code snippets as a guide — trace from source yourself.

Document:
- Every validation or sanitization function encountered on the path
- Every transformation applied to the input
- Whether each control is bypassable given realistic attacker input
- Framework-level protections active on this path (ORM, auto-escaping, CSRF tokens, etc.)

If the code path cannot be traced as described, record the discrepancy.

---

## Step 3 — Protection Surface Search

Actively search for controls that could block or mitigate the claimed attack. Check each layer:

| Layer | What to Look For |
|-------|-----------------|
| Language-level | Type system enforcement, memory safety, bounds checking |
| Framework-level | ORM parameterization, template auto-escaping, CSRF middleware, input validation decorators |
| Middleware | WAF rules, proxy normalization, rate limiting, authentication enforcement |
| Application-level | Allowlists, ownership checks, role verification, input length limits |
| Documentation-level | `SECURITY.md`, changelogs, `CONTRIBUTING.md` — does the project explicitly accept this as a known risk? |

Record each protection found and assess whether it blocks the claimed attack path.

---

## Step 4 — Real-Environment Reproduction

Follow the procedures in `real-env-validation.md`. Provision an appropriate environment for the project type and attempt reproduction.

Required:
- Deploy at the same commit referenced in the finding draft
- Verify the environment is working normally (healthcheck) before attempting exploitation
- Attempt the reproduction steps from the finding draft exactly as written
- If the first attempt fails, try up to 3 variations

Record:
- Environment type and provisioning commands used
- Healthcheck result
- Each attempt and its outcome
- Evidence files stored in `vigolium-results/real-env-evidence/<slug>/`

If real-environment reproduction is blocked (see `real-env-validation.md`), document the blocker and continue to Steps 5-7 based on code analysis only. Annotate `PoC-Status: theoretical`.

---

## Step 5 — Prosecution and Defense Briefs

Write two independent arguments. Each must cite specific code locations and evidence from Steps 2-4.

**Prosecution brief**: argue that the finding is a genuine, exploitable vulnerability. State the strongest possible case. Cite code, attacker input path, protection gaps, and reproduction evidence.

**Defense brief**: argue that the finding is a false positive or unexploitable. State the strongest possible case. Cite protections found in Step 3, reproduction failures, and any preconditions that make exploitation unrealistic.

Do not allow one brief to reference the other's reasoning. Write them independently.

---

## Step 6 — Severity Challenge

Apply severity calibration from `triage-and-prereqs.md`. Start at MEDIUM regardless of what the finding draft states.

- Document whether upgrade criteria for HIGH or CRITICAL are met with evidence
- Document whether any downgrade signals apply
- State `Severity-Challenge: <MEDIUM | HIGH | CRITICAL>` with a one-sentence justification

If the challenged severity is lower than `Severity-Original` in the draft, the lower severity wins in the final record.

---

## Step 7 — Verdict

**CONFIRMED** if both:
- The prosecution brief survives the defense (no blocking protection was found)
- AND real-environment reproduction succeeded (or reproduction was blocked with documented reason)

**DISPROVED** if either:
- The defense identifies a protection that blocks the claimed attack path
- OR all reproduction attempts failed (3 variations tried and all failed)

Write the verdict back into the finding draft:
```
Adversarial-Verdict: CONFIRMED | DISPROVED
Adversarial-Rationale: <one sentence citing the decisive evidence>
Severity-Final: <challenged severity if different from original, else same as original>
PoC-Status: executed | theoretical | blocked
```

Write the full adversarial review to `vigolium-results/adversarial-reviews/<slug>-review.md` using the Adversarial Review Template from `report-templates.md`.

If verdict is DISPROVED, also update the finding draft's top-level `Verdict:` field to `FALSE POSITIVE (adversarial)`.

---

## Rationalizations to Reject

The following are not valid grounds for issuing CONFIRMED:

- "The finding agent already verified this" — the finding agent's verification is why Stage 2 exists
- "I cannot reproduce but the code looks vulnerable" — failed reproduction with no documented blocker is a DISPROVED signal
- "Probably exploitable in some configuration" — theoretical exploitability is not confirmed exploitability
- "The severity seems right based on the bug class" — severity must be derived from evidence, not class defaults
- "The defense brief is weaker than the prosecution brief" — a plausible defense is sufficient to require reproduction before confirming
