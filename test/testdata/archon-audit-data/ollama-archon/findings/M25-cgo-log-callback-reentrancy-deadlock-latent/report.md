## Summary

`llama/llama.go:34-56` registers a Go function as the llama.cpp log callback via `C.llama_log_set`. When llama.cpp emits a log line during `C.llama_decode` (or any other cgo call), the C code synchronously invokes the Go callback while the cgo goroutine's OS thread (M) is in a C call and llama.cpp's internal mutex may be held.

The Go callback at line 42-55 invokes `slog.Log(...)`. `slog`'s default handler uses its own internal `sync.Mutex` which is NOT shared with any ollama runner mutex. Current code does NOT exhibit a deadlock.

The finding documents the **architectural hazard**: any future code change that (a) acquires a runner-level mutex inside the log callback, or (b) holds a runner-level mutex across a `C.llama_decode` call that triggers a log line, creates a circular wait and deadlocks all subsequent `/api/generate` / `/api/chat` requests.

Example of future-hazard code that would become exploitable:

```go
// ANTI-PATTERN (does not exist today, but trivially introducible):
func logCallback(level api.LogLevel, text string) {
    runnerState.mu.Lock()       // runner-level mutex
    defer runnerState.mu.Unlock()
    runnerState.logBuffer = append(runnerState.logBuffer, text)
}

// Meanwhile in an HTTP handler:
runnerState.mu.Lock()          // holds mutex
C.llama_decode(ctx, batch)     // C triggers log -> callback tries Lock() -> deadlock
runnerState.mu.Unlock()
```

Severity MEDIUM because the hazard is latent (not exploitable today) but the mitigation cost is trivial: a comment and a single `go_vet`-style lint rule.

## Details

`llama/llama.go:34-56` registers a Go function as the llama.cpp log callback via `C.llama_log_set`. When llama.cpp emits a log line during `C.llama_decode` (or any other cgo call), the C code synchronously invokes the Go callback while the cgo goroutine's OS thread (M) is in a C call and llama.cpp's internal mutex may be held.

The Go callback at line 42-55 invokes `slog.Log(...)`. `slog`'s default handler uses its own internal `sync.Mutex` which is NOT shared with any ollama runner mutex. Current code does NOT exhibit a deadlock.

The finding documents the **architectural hazard**: any future code change that (a) acquires a runner-level mutex inside the log callback, or (b) holds a runner-level mutex across a `C.llama_decode` call that triggers a log line, creates a circular wait and deadlocks all subsequent `/api/generate` / `/api/chat` requests.

Example of future-hazard code that would become exploitable:

```go
// ANTI-PATTERN (does not exist today, but trivially introducible):
func logCallback(level api.LogLevel, text string) {
    runnerState.mu.Lock()       // runner-level mutex
    defer runnerState.mu.Unlock()
    runnerState.logBuffer = append(runnerState.logBuffer, text)
}

// Meanwhile in an HTTP handler:
runnerState.mu.Lock()          // holds mutex
C.llama_decode(ctx, batch)     // C triggers log -> callback tries Lock() -> deadlock
runnerState.mu.Unlock()
```

Severity MEDIUM because the hazard is latent (not exploitable today) but the mitigation cost is trivial: a comment and a single `go_vet`-style lint rule.

### Location

- `llama/llama.go:34-56` -- `SetLogCallback(fn)` registers the exported Go function via `C.llama_log_set`
- `llama/llama.go:42-55` -- log callback body; currently calls `slog.Log` only
- All cgo call sites that may trigger log output: `C.llama_decode`, `C.llama_tokenize`, `C.mtmd_tokenize`, `C.llama_adapter_lora_init`, etc. (any function that can emit warn/error lines)

### Attacker Control

None in current code. Hypothetical: an attacker who can provoke many log lines (via a malformed prompt that triggers internal warnings) AND an unrelated code change introduces a runner-mutex-holding callback — the attacker then triggers the deadlock via a single bad prompt while concurrent requests hang.

### Trust Boundary Crossed

Go/cgo reentrancy boundary; not a network boundary.

### Evidence

Tracer verification (Round 3, H-NEW-43, 2026-04-17T10:19:00Z):

```
llama/llama.go:34-56
    func SetLogCallback(fn func(level api.LogLevel, text string)) {
        logCallback = fn
        C.llama_log_set((C.ggml_log_callback)(C.LlamaLogCallback), nil)
    }
    // Exported Go function invoked from C.

llama/llama.go:42-55 (simplified)
    //export LlamaLogCallback
    func LlamaLogCallback(level C.enum_ggml_log_level, text *C.char, userData unsafe.Pointer) {
        if logCallback != nil {
            logCallback(api.LogLevel(level), C.GoString(text))
        }
    }
```

Tracer analysis: "`slog` default handler uses an internal `sync.Mutex` for its output buffer. This mutex is NOT shared with any ollama runner mutex... The runner's own mutexes (e.g., `s.mu` in llamarunner) are held around HTTP handler processing, NOT around the raw `C.llama_decode` call. The cgo runtime restriction: a goroutine blocked in a C call holds its OS thread (M) but NOT any Go-side mutex. Other goroutines can run freely."

Tracer conclusion: "the cgo-callback architecture creates a potential for deadlock if mutex discipline is violated in a future refactor, but current code does not exhibit the circular wait."

Synth disposition: MEDIUM defense-in-depth. The finding's value is in preventing the foot-gun from being stepped on in future changes.

## Root Cause

Validated rationale: Tracer confirmed the cgo callback architecture at `llama/llama.go:34-56` registers a Go function as `C.llama_log_set` callback; the function path traverses `slog` which uses its own disjoint mutex, so current code does NOT exhibit deadlock — but the pattern (Go-code-callback-from-C-while-C-holds-mutex) is a known foot-gun class; a future caller that acquires a runner mutex inside the log callback creates a circular-wait with any goroutine waiting on `C.llama_decode`.

Primary cited code reference: `llama/llama.go:34`.

Merge extraction sink line: - `llama/llama.go:34-56` -- `SetLogCallback(fn)` registers the exported Go function via `C.llama_log_set`

## Proof of Concept

Merge-normalized status: `pending`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

No current-code reproduction. Hardening validation:

1. Audit `llama/llama.go:42-55` — confirm the callback body does not call into any runner-level code.
2. Document a contract in the source (comment above `LlamaLogCallback`) stating:
   > The log callback is invoked from C while llama.cpp's internal mutex may be held.
   > DO NOT acquire any Go-side mutex in this callback. DO NOT call back into
   > runner state. Only call stateless or mutex-free logging primitives.
3. Consider adding a lint-time check (`go vet` custom pass) that rejects `sync.Mutex` / `sync.RWMutex` calls in any function transitively callable from an `//export` function registered as a cgo callback.
4. Audit all other exported Go functions called from C: `LlamaProgressCallback`, any abort callback.

Fix direction: lightweight — add source comments + vet check. No runtime code change required.

Pattern: register AP-053 `cgo-callback-mutex-hazard` — Go callback registered with cgo must not acquire any Go mutex that can be held by goroutines waiting on the parent C call.

## Impact

Today: none.

Hypothetical future (one code change away): deterministic process-level DoS of the runner subprocess. All concurrent `/api/generate`, `/api/chat`, `/api/embed` hang forever. Scheduler watchdog may detect and restart, but the attacker can re-trigger at will.

_Synthesized during merge normalization from `archon/findings/M25-cgo-log-callback-reentrancy-deadlock-latent/draft.md`._
