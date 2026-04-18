## Summary

`llama/llama.go:264-310` (`LoadModelFromFile`) calls `C.CString(modelPath)` at approximately line 308 without a corresponding `defer C.free(unsafe.Pointer(cPath))`. In Go's cgo model, the C heap is not reachable from the Go GC; the leaked CString persists until process exit.

Subprocess isolation contains the blast radius: each runner process handles one model load and exits on unload, at which point the OS reclaims the entire C heap. The runner's "model already loaded" guard at `runner/llamarunner/runner.go:884-887` also prevents repeated leaks within one subprocess.

The finding's value is:
- Correctness hygiene: every other `C.CString` in `llama/llama.go` is paired with `defer C.free`; line 308 is an anomaly.
- Future-proofing: if the single-load guard is lifted (e.g., to support dynamic model swap within one runner), the leak becomes an unbounded DoS primitive.
- Memory-sanitizer CI: leaks like this break `go run -race` and `leaksanitizer`-instrumented builds.

## Details

`llama/llama.go:264-310` (`LoadModelFromFile`) calls `C.CString(modelPath)` at approximately line 308 without a corresponding `defer C.free(unsafe.Pointer(cPath))`. In Go's cgo model, the C heap is not reachable from the Go GC; the leaked CString persists until process exit.

Subprocess isolation contains the blast radius: each runner process handles one model load and exits on unload, at which point the OS reclaims the entire C heap. The runner's "model already loaded" guard at `runner/llamarunner/runner.go:884-887` also prevents repeated leaks within one subprocess.

The finding's value is:
- Correctness hygiene: every other `C.CString` in `llama/llama.go` is paired with `defer C.free`; line 308 is an anomaly.
- Future-proofing: if the single-load guard is lifted (e.g., to support dynamic model swap within one runner), the leak becomes an unbounded DoS primitive.
- Memory-sanitizer CI: leaks like this break `go run -race` and `leaksanitizer`-instrumented builds.

### Location

- `llama/llama.go:308` (approximately — exact line per tracer trace) -- `cPath := C.CString(modelPath)` with no matching `defer C.free`
- Contrast with `llama/llama.go:346` -- `ApplyLoraFromFile` correctly frees via `defer C.free(unsafe.Pointer(cLoraPath))`

### Attacker Control

Limited. Triggered on every model-load IPC. The modelPath is parent-daemon-controlled (derived from manifest blob digest), not HTTP-attacker-controlled. The leak occurs per runner subprocess launch; bounded by `envconfig.MaxRunners()` and the scheduler.

### Trust Boundary Crossed

Internal memory-safety invariant (cgo ownership); not a network trust boundary.

### Evidence

Tracer verification (Round 2, H-00.02, 2026-04-17T07:04:00Z):

```
llama/llama.go:264-310  // LoadModelFromFile
    ...
    cPath := C.CString(modelPath)
    // NO "defer C.free(unsafe.Pointer(cPath))"
    // ... cPath passed to C.llama_model_load_from_file(cPath, ...) ...
```

Advocate Round 1 H-00.02 defense:
> "Strongest defense: the leak is bounded by subprocess lifetime. `LoadModelFromFile` is invoked once per model load; the runner subprocess is the unit of isolation; when the model is unloaded the entire subprocess exits and the C heap is reclaimed by the OS."

Tracer Round 2 accepted the bound but confirmed the leak is real: "The C heap leak at `llama/llama.go:308` is real and produces one leak per runner subprocess launch."

Synth disposition: MEDIUM. The bounding argument is correct for today's code but is fragile against any future change that lifts the single-load restriction. A one-line fix (`defer C.free(unsafe.Pointer(cPath))`) eliminates the finding permanently.

## Root Cause

Validated rationale: Tracer confirmed `llama/llama.go:308` calls `C.CString(modelPath)` with no `defer C.free` — the allocation is permanently leaked to the C heap; advocate correctly noted subprocess isolation bounds the leak per runner process and the "model already loaded" guard at `runner/llamarunner/runner.go:884-887` prevents re-trigger within one subprocess, so the finding is MEDIUM defense-in-depth rather than a DoS primitive.

Primary cited code reference: `llama/llama.go:308`.

Merge extraction sink line: - `llama/llama.go:308` (approximately — exact line per tracer trace) -- `cPath := C.CString(modelPath)` with no matching `defer C.free`

## Proof of Concept

Merge-normalized status: `pending`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

Memory-sanitizer validation:

1. Build with `-gcflags="all=-N -l"` and run under `valgrind --leak-check=full` (or equivalent cgo leak detector).
2. `curl -X POST http://127.0.0.1:11434/api/generate -d '{"model":"<any>","prompt":"hi"}'` to trigger model load.
3. Observe leak record pointing at `LoadModelFromFile` in the valgrind output.
4. Fix: insert `defer C.free(unsafe.Pointer(cPath))` immediately after the `C.CString(modelPath)` call at `llama/llama.go:308`. Audit all other `C.CString` sites in the runner/cgo layer for parity.

Pattern: register AP-049 `cstring-without-defer-free` — cgo glue functions where `C.CString` is not paired with `defer C.free`. Detection signature:

```
grep: "C\\.CString\\(" with nearby absence of "defer C\\.free"
```

## Impact

- Per runner subprocess: 1 × CString leak = strlen(modelPath) + 1 bytes; trivial.
- Across subprocess lifetime: reclaimed by the OS on subprocess exit.
- As a chain primitive (CHAIN-F in the debate): blocked by the single-load guard; not weaponizable today.

Low-severity memory hygiene. MEDIUM disclosure rating because the anomalous call-site pattern (missing the standard `defer C.free`) is easy to review-miss and the fix is a one-line change.

_Synthesized during merge normalization from `archon/findings/M21-cstring-leak-load-model-from-file/draft.md`._
