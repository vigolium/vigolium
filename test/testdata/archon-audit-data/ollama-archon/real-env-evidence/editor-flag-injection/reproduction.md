# Editor Flag Injection — Reproduction Evidence

## Environment
- Repo: /Users/bytedance/Desktop/demo/ollama
- Commit: 57653b8e (HEAD of main)
- Go test against real `editInExternalEditor` function in cmd/interactive.go.

## Test harness
File: `cmd/editor_flag_injection_test.go` (added temporarily for verification, removed
after).

Steps:
1. Create fake `code` executable in temp dir that logs its argv.
2. Prepend temp dir to PATH (so exec.LookPath resolves our fake).
3. Set EDITOR="code --extensionDevelopmentPath=/tmp/malicious".
4. Invoke `editInExternalEditor("hello")` directly.

## Result (verbatim)
```
=== RUN   TestEditorFlagInjection_VerifyFlag
    editor_flag_injection_test.go:47: fake editor argv:
        --extensionDevelopmentPath=/tmp/malicious
        /var/folders/.../T/ollama-prompt-1148116665.txt
--- PASS
```

The fake editor received:
- argv[1] = --extensionDevelopmentPath=/tmp/malicious   (attacker-controlled flag)
- argv[2] = /var/folders/.../T/ollama-prompt-*.txt       (ollama-added tmpfile)

This confirms that `strings.Fields(os.Getenv("EDITOR"))` unconditionally splits the
env var into argv tokens passed to `exec.Command`, enabling the attacker to inject
arbitrary flags into whichever editor is launched.

## Real-world impact
- VSCode: `--extensionDevelopmentPath=/path` auto-activates arbitrary extension code
- vim: `+\:!cmd` or `-c '!cmd'` executes ex commands at startup
- emacs: `--load /path/evil.el` evaluates arbitrary elisp
- nano: `--syntax` with crafted file, no direct RCE but other flags exist

## Trigger
Ctrl+G in the `ollama run` REPL invokes `editInExternalEditor` (via
ErrEditPrompt in readline/readline.go:298). The finding draft mentions `/edit`,
but the actual trigger is the CharBell / Ctrl+G keystroke — the flag-injection
vulnerability is the same.
