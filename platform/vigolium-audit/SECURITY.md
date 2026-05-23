# Security Policy

`vigolium-audit` is a security tool that runs autonomous agents against your
source code with broad filesystem and (optionally) network access. We take the
security of the tool itself seriously.

## Supported versions

`vigolium-audit` is pre-1.0 and ships as alpha releases. Only the latest
published release on the `main` branch receives security fixes. Please upgrade
before reporting an issue.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately via GitHub's [private vulnerability
reporting](https://github.com/vigolium/vigolium-audit/security/advisories/new)
("Report a vulnerability" under the repository's **Security** tab). If that is
unavailable to you, email **security@vigolium.com**.

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce (a minimal repro, command line, and target if relevant).
- The `vigolium-audit --version` output and your OS/runtime.
- Any logs or proof-of-concept, with sensitive data redacted.

We aim to acknowledge reports within **3 business days** and to provide a
remediation timeline after triage. We'll credit reporters who wish to be
named once a fix ships.

## Scope

In scope:

- The `vigolium-audit` CLI, engine, and adapters in this repository.
- The vendored methodology content under `src/content/` as it affects the
  safety of a run (e.g. an agent prompt that could be coerced into a dangerous
  action).
- The build/release tooling under `scripts/`.

Out of scope:

- Vulnerabilities in `claude` / `codex` themselves or in the underlying model
  providers — report those to the respective vendors.
- Findings produced *by* an audit run about *your* target code (that's the
  tool working as intended).

## Operating the tool safely

A few properties to be aware of when running audits:

- **Permission mode.** Headless runs and the bundled harness agents are
  configured to operate with elevated/bypassed permissions so the agent can
  read the whole target and run scanners. Run against code you trust, or use a
  sandbox/VM for untrusted targets.
- **Network access.** Some phases (advisory lookup, dependency scanning) reach
  out to the network. Disable networking at the OS/container level if you need
  an air-gapped run.
- **Auth overrides.** `--api-key`, `--oauth-token`, and `--oauth-cred-file`
  apply credentials for the lifetime of a run and restore the prior state on
  exit (including on SIGINT/SIGTERM). Prefer ambient subscription auth or
  environment variables over passing secrets on the command line, which can
  land in your shell history.
- **Output.** Audit artifacts under `vigolium-results/` may contain snippets of
  your source and potential vulnerability details. Treat that directory as
  sensitive.
