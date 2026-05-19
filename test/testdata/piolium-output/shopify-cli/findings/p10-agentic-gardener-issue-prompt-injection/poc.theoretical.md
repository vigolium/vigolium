# Theoretical PoC: Gardener issue prompt injection

PoC-Status: theoretical

Runtime exploitation was not executed because it requires a live GitHub Actions run in the target repository with `ANTHROPIC_API_KEY`/Claude Code Action access, the repository `GITHUB_TOKEN`, and a maintainer applying the `devtools-investigate-for-gardener` label. Those external secrets and label-gated CI conditions are not available in this local audit environment.

## Attack chain

1. An external user opens a GitHub issue whose body contains normal issue text plus prompt-injection instructions.
2. A maintainer applies `devtools-investigate-for-gardener` during triage.
3. `.github/workflows/gardener-investigate-issue.yml` starts on `issues:labeled` and builds `https://github.com/${{ github.repository }}/issues/$NUMBER`.
4. The Claude Code Action receives `/investigating-github-issues ${{ steps.issue.outputs.url }}` and is allowed to use `gh issue view`, so the attacker-controlled issue body enters the model context.
5. The same action has `contents: write`, `pull-requests: write`, `github_token: ${{ secrets.GITHUB_TOKEN }}`, and write-capable tools including `Edit`, `Write`, `git add`, `git commit`, `git push`, and `gh pr create`.
6. If the model follows the issue-body injection, the attacker gains unauthorized repository write effects such as a pushed branch and PR created by CI.

## Payload

The minimized malicious issue body is stored at:

- `evidence/injected_issue_body.md`

It instructs the agent to create a branch, write `POC_AGENTIC_INJECTION.md`, commit, push, and open a PR.

## Evidence captured

- `evidence/exploit.log` — local static PoC output showing the full vulnerable workflow configuration is present.
- `evidence/impact.log` — extracted code-path evidence and exploit-chain marker.
- `evidence/healthcheck.log` — confirms the workflow file and relevant lines are present.
- `evidence/setup.log` / `evidence/env-info.txt` — local validation environment details.
