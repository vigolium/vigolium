# Cold Adversarial Review — p8-068 editor-visual-flag-injection-exec

Reviewer context: zero chamber-debate exposure. Only input was the finding draft
file path.

## Step 1 — Claim decomposition

The REPL editor invocation path reads a user-scoped env var (`OLLAMA_EDITOR`,
`VISUAL`, `EDITOR`), splits it on whitespace with `strings.Fields`, and passes
the split tokens to `exec.Command` as argv. An attacker who controls any of
those env vars can therefore inject additional command-line flags into whichever
editor is launched — every common editor (VSCode, vim, emacs) has at least one
flag that loads arbitrary code from a path.

Sub-claims:
- A: Attacker controls one of OLLAMA_EDITOR / VISUAL / EDITOR / PATH.
- B: Value flows unsanitized from env into exec.Command argv.
- C: Injected flag causes the launched editor to execute attacker code.

## Step 2 — Independent code path trace

cmd/interactive.go (HEAD 57653b8e):

- 643-653: reads env vars in order OLLAMA_EDITOR -> VISUAL -> EDITOR -> defaultEditor.
- 655-659: `strings.Fields(editor)[0]` -> `exec.LookPath(name)` — only checks
  existence, no flag validation.
- 661-673: creates a tmpfile.
- 675-677: `args := strings.Fields(editor); args = append(args, tmpFile.Name());
  cmd := exec.Command(args[0], args[1:]...)` — tokens reach argv unmodified.

Caller: cmd/interactive.go:154 triggers on `readline.ErrEditPrompt`, which is
returned from readline/readline.go:298 when CharBell (0x07, Ctrl+G) is pressed.
Finding draft says `/edit`; actual trigger is Ctrl+G. This is a cosmetic issue
only — the injection path is identical.

## Step 3 — Protection surface

Grep for input validation, argv filtering, allowlists, flag sanitization:
none found in cmd/interactive.go or nearby files. Only control is
`exec.LookPath(name)` which does not inspect flags.

No `OLLAMA_ALLOW_UNSAFE_EDITOR` or similar gate.

## Step 4 — Real-environment reproduction

Executed against the real `editInExternalEditor` function via a temporary Go
test added to the cmd package:

- Fake `code` binary placed in temp dir; PATH prepended with that dir.
- EDITOR='code --extensionDevelopmentPath=/tmp/malicious'
- Called editInExternalEditor("hello") directly.

Result:
```
=== RUN   TestEditorFlagInjection_VerifyFlag
    editor_flag_injection_test.go:47: fake editor argv:
        --extensionDevelopmentPath=/tmp/malicious
        /var/folders/.../T/ollama-prompt-*.txt
--- PASS
```

Attacker flag reached the spawned binary as argv[1]. Confirmed end-to-end.

Temporary test file was removed after verification.

Evidence file: archon/real-env-evidence/editor-flag-injection/reproduction.md

## Step 5 — Briefs

Prosecution: code unconditionally splits env var into argv, reproduction
demonstrates arbitrary flag injection into any editor on PATH, no mitigations
exist, and chain-feasible attacker positions (CI, agent setenv, hostile install
scripts) exist that do not imply full prior shell.

Defense: this is the classic EDITOR-env threat model. An attacker with the
ability to write ~/.bashrc usually already has equivalent or greater local
capability. Trigger requires user interaction (Ctrl+G in an interactive REPL).
Standard tools (git, sudoedit, less) accept the same style of EDITOR value
without being considered vulnerable in isolation.

## Step 6 — Severity challenge

Baseline MEDIUM.
- Not network-reachable.
- Requires user interaction.
- Requires attacker foothold to write env var.
- In common case (dotfile write) attacker already has shell; this is then a
  persistence/privilege-shape primitive, not a new trust boundary.
- In constrained contexts (sandboxed agent tool with setenv only, hardened CI)
  this does convert a narrower capability into full user RCE at editor launch.

Does not qualify for HIGH (no unauthenticated trigger, no mass impact).
Does not drop below MEDIUM (real conversion primitive in at least some realistic
attacker positions).

Severity-Final: MEDIUM (down from HIGH).

## Step 7 — Verdict

CONFIRMED. Prosecution brief survived the defense; reproduction succeeded
against the real function at HEAD. Severity lowered from HIGH to MEDIUM.
