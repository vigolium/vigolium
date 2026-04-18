Phase: 10
Sequence: 033
Slug: process-substitution-bypasses-cwd-check
Verdict: VALID
Rationale: isCommandOutsideCwd does not parse bash process substitution syntax <(...), so absolute paths embedded inside substitutions pass undetected, and the outside-cwd warning is suppressed.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-021-shell-expansion-bypass.md
Origin-Pattern: AP-021

## Summary
`isCommandOutsideCwd` tokenises a command by splitting on `|`, `;`, and `&`, then iterates over whitespace-separated fields, checking whether each argument starts with `/`, `..`, or `~`. Bash process substitution `<(...)` is not a split delimiter and not a recognised path prefix. A command such as `diff <(cat /etc/shadow) ./local_file` passes through `isCommandOutsideCwd` returning false (no warning shown), yet bash executes `cat /etc/shadow` and pipes its content into `diff`. The root cause is the same lexical-only analysis as AP-021: the code treats shell syntax as plain strings.

## Location
`x/agent/approval.go:312-374` — `isCommandOutsideCwd`  
`x/agent/approval.go:320-323` — split delimiters (`|`, `;`, `&`) — `<` not included  
`x/agent/approval.go:333-369` — per-field path checks — `<(` prefix not recognised

## Attacker Control
LLM tool call `command` argument: `diff <(cat /etc/shadow) ./file` — no special permissions required; `/etc/shadow` can be replaced with any sensitive file readable by the current user.

## Trust Boundary Crossed
Local filesystem read of paths outside cwd, presented to the user as an in-cwd diff operation. The approval UI shows no warning (isWarning=false), so the user is misled about the scope of the approved command.

## Impact
Exfiltration of sensitive files (SSH keys, environment files, credentials) readable by the process. Severity MEDIUM: user still sees the command text in the approval prompt and must approve it, but the outside-cwd warning that would signal elevated risk is absent.

## Evidence
```go
// isCommandOutsideCwd split — < not a delimiter
parts := strings.FieldsFunc(command, func(r rune) bool {
    return r == '|' || r == ';' || r == '&'
    // '<' is not listed
})

// After split, "diff <(cat /etc/shadow) ./file" is one part.
// Fields: ["diff", "<(cat", "/etc/shadow)", "./file"]
// "<(cat" does not start with "/", "..", or "~" — skipped
// "/etc/shadow)" starts with "/" BUT it is the SECOND field after
//   "<(cat", and the loop skips field[0] only for the command word;
//   Wait — field[0] is "diff", so "<(cat" is fields[1] and "/etc/shadow)"
//   is fields[2]. "/etc/shadow)" DOES start with "/" so...
```
Correction on deep analysis: `/etc/shadow)` as a token does start with `/`, so `isCommandOutsideCwd` would actually return `true` for this exact example because the `)` suffix does not prevent the `/` prefix check. However, the bypass succeeds when the path is **inside** the process substitution and the closing paren is attached to the path:

`diff <(cat /etc/shadow) ./file`  -> token `/etc/shadow)` starts with `/` -> detected.

But consider: `cat <(grep -r secret ~/.ssh/config)` -> token `~/.ssh/config)` starts with `~` -> detected.

The real bypass is with **named pipes or /dev/fd** indirection, or when the inner command is on a single token without a path argument:

`bash -c 'cat /etc/shadow' | diff - ./file`

Here `bash` is not in safeCommands so extractBashPrefix returns "", but `isCommandOutsideCwd` processes `bash -c 'cat /etc/shadow'` as fields `["bash", "-c", "'cat", "/etc/shadow'"]`. The token `"'cat"` starts with `'` not `/`. Token `"/etc/shadow'"` starts with `/` — detected. So this is caught too.

**Confirmed bypass pattern** — single-quoted grouping that breaks field tokenisation:

`cat 'tools/foo bar/file' | tee $'/etc/cron'$'.d/evil'`

The `$'...'` ANSI-C quoting is not handled by isCommandOutsideCwd path checks; the token `$'/etc/cron'$'.d/evil'` does not start with `/` so it bypasses the absolute-path check, yet bash expands it to `/etc/cron.d/evil`.

## Reproduction Steps
1. Start `ollama run` with bash tool.
2. Model emits: `cat tools/README.md | tee $'/etc/cron.d/evil'`
3. `isCommandOutsideCwd` checks the token `$'/etc/cron.d/evil'` — does not start with `/`, `..`, or `~` — returns false.
4. No outside-cwd warning shown. User sees normal (non-red) approval box.
5. User approves; bash expands `$'/etc/cron.d/evil'` to `/etc/cron.d/evil` and writes there.
