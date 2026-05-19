---
Phase: 10
Sequence: 6
Slug: agentic-gardener-issue-prompt-injection
Verdict: VALID
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: requires-maintainer-label-gate
Debate: piolium/chamber-workspace/c04-agentic-workflow/debate.md
Origin-Drafts: p4-007-agentic-gardener-issue-prompt-injection.md
id: p10
slug: agentic-gardener-issue-prompt-injection
severity: info
PoC-Block-Reason: runtime exploitation requires live GitHub Actions with Claude/Anthropic secrets and maintainer-applied label; local audit environment cannot execute that external CI path
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous
---

# Gardener Claude workflow lets untrusted issue text steer a write-capable agent

## Summary
The `Gardener - Investigate Issue` workflow runs Claude Code after a label is applied to an issue. The agent is prompted with the issue URL and is allowed to fetch issue text, edit/write files, commit, push branches, and create PRs while the workflow grants `contents: write` and `pull-requests: write`. Issue body/title content is attacker-controlled, so labeling an untrusted issue creates a prompt-injection path into a write-capable CI agent.

## Location
- `.github/workflows/gardener-investigate-issue.yml:5-8` — `issues:labeled` trigger.
- `.github/workflows/gardener-investigate-issue.yml:15-18` — repository write/PR permissions.
- `.github/workflows/gardener-investigate-issue.yml:71-87` — Claude Code Action receives GitHub token, broad write tools, and the issue URL prompt.

## Attacker Control
Any external user who can create issue content controls text that Claude is instructed to retrieve with `gh issue view` after a maintainer applies the investigation label.

## Trust Boundary Crossed
Untrusted GitHub issue text crosses into an AI coding agent with repository write-capable tools and token permissions.

## Impact
Prompt injection can cause unauthorized edits, branch pushes, or PR creation, and can manipulate investigation output delivered to maintainers.

## Evidence
The workflow grants `contents: write` and `pull-requests: write`, passes `github_token`, and allows `Edit`, `Write`, `git add/commit/push`, and `gh pr create` tools while the prompt is `/investigating-github-issues ${{ steps.issue.outputs.url }}`.

## Reproduction Steps
1. Open an issue containing instructions aimed at the AI investigator.
2. Have a maintainer apply `devtools-investigate-for-gardener`.
3. The workflow runs Claude with write tools and the issue URL; the agent can fetch and follow the injected content unless separated into a read-only/human-gated mode.
