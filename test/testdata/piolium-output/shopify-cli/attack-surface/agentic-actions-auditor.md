# Agentic Actions Auditor Report

Analyzed 14 workflows containing 1 Claude Code Action instance. Found 1 Medium finding and 1 informational amplifier in `.github/workflows/gardener-investigate-issue.yml`.

## Medium — Issue content can prompt-inject write-capable Claude workflow

- Trigger: `issues:labeled` with `devtools-investigate-for-gardener` or `workflow_dispatch`.
- Source: attacker-controlled issue body/title, fetched at runtime via allowed `gh issue view`.
- Sink/runtime: Claude Code Action with `github_token`, `Edit`, `Write`, git commit/push, and `gh pr create` tools.
- Permissions: `contents: write`, `pull-requests: write`.
- Boundary: untrusted issue text -> CI AI agent with repository write capability.

## Info — Broad tools amplify injection

The same Claude step grants file-write, git, and PR-creation tools. Split read-only investigation from write-capable fix mode or require a separate human-gated workflow for write tools.
