Phase: 8
Sequence: 024
Slug: streaming-response-clean-eof-silent-truncation
Verdict: VALID
Rationale: Tracer disproved the original H-NEW-49 claim that the server falsely emits `done_reason:stop` on crash (server actually emits an error JSON line in the NDJSON stream); BUT confirmed a real variant — when `bufio.Scanner` sees a clean EOF boundary (runner crashes exactly at a newline), `scanner.Err()` returns nil and `Completion` returns nil, so the stream closes without any error object and without a final `done:true` chunk, which agentic clients that tolerate missing `done` may interpret as a complete response.
Severity-Original: MEDIUM
Severity-Final: MEDIUM
PoC-Status: pending
Pre-FP-Flag: check-4-partial (requires crash timing aligned to scanner newline boundary; probability-dependent)
Debate: archon/chamber-workspace/chamber-03/debate.md

## Summary

The ollama NDJSON streaming protocol for `/api/generate` and `/api/chat` emits one JSON object per line and ends with `{"done":true,"done_reason":"stop"}`. If the runner subprocess crashes mid-stream, the parent daemon's behavior depends on whether the HTTP connection terminates mid-chunk or at a clean newline boundary.

- **Mid-chunk crash**: `bufio.Scanner.Err()` returns `io.ErrUnexpectedEOF`; `Completion` returns an error; `streamResponse` at `server/routes.go:1922` emits `{"error":"<msg>"}` in the stream. **Correctly observable.**
- **Clean-EOF-at-newline crash**: `scanner.Scan()` returns false with `scanner.Err() == nil`; `Completion` returns nil; the parent treats the stream as complete and stops emitting chunks. **No error is emitted, AND no final `done:true` is emitted.**

Agentic clients differ in how they handle this terminal state. Many tolerate missing `done:true` (treating the stream-end as success) because ollama itself occasionally omits the sentinel in edge cases. For those clients, a crash-timed truncation is indistinguishable from a normal short completion.

The attack: an adversary with prompt-injection access to an agentic pipeline that calls ollama can craft prompts that trigger a crash (via any of the other findings in this chamber: p8-040 null-deref, p8-042 OOM, p8-043 OOB read) at a point of their choosing. The agent receives a truncated response as if it were authoritative and takes actions based on the partial output — e.g., a summarization agent whose final "decision: approve/deny" token is truncated to just "approve".

## Location

- `llm/server.go:1619-1626` -- `http.DefaultClient.Do(serverReq)` opens streaming connection to runner
- `llm/server.go:1694-1707` -- `scanner.Err()` post-loop check; `if err.Contains("unexpected EOF")` branch (the mid-chunk path)
- `llm/server.go` -- clean-EOF path: `scanner.Scan()` returns false with nil error; loop exits; `Completion` returns nil; **no error emitted downstream**
- `server/routes.go:1899-1928` -- `streamResponse` emits `{"error":...}` only when `Completion` returns error
- `server/routes.go:622-628` -- `Completion` error is wrapped and sent; nil error = silent success

## Attacker Control

Prompt-injection reaching any agent that calls ollama. The attacker does not need direct HTTP access to ollama; they need control over input to the agent (user message, retrieved document, tool output, etc.).

Combined with any crash primitive (p8-040, p8-042, p8-043) → truncation at controlled point in the stream.

## Trust Boundary Crossed

Agent-to-model trust: the agent trusts that a stream that ended without an error is a complete response. Crash-induced truncation violates this trust.

## Impact

Agentic decision manipulation. Examples:
- A summarization agent whose final token determines an action (approve/deny, route-to-human/auto-process) has that token truncated.
- A code-generation agent returns partial code that is syntactically incomplete; downstream executor may handle partial code by padding with default behavior.
- A RAG agent's retrieved-source citation is truncated, hiding attribution.

Not a memory-safety impact. Not a direct information-disclosure. Correctness-level exploit amplification on top of any crash primitive.

## Evidence

Tracer verification (Round 3, H-NEW-49, 2026-04-17T10:29:00Z):

```
llm/server.go:1694-1707
    for scanner.Scan() {
        ...
    }
    if err := scanner.Err(); err != nil {
        if strings.Contains(err.Error(), "unexpected EOF") || strings.Contains(err.Error(), "forcibly closed") {
            s.Close()
            return fmt.Errorf("an error was encountered while running the model: %w", err)
        }
        return fmt.Errorf("error reading llm response: %w", err)
    }
    return nil   // <-- clean EOF path; no error emitted
```

Tracer analysis: "If `scanner.Err() == nil` (clean EOF from scanner), the loop exits normally and `Completion` returns `nil`. The parent then returns no more chunks to the channel, and `streamResponse` sees channel close → `c.Stream` returns false → response ends. The client sees a clean NDJSON stream that ends WITHOUT a final `{"done": true}` chunk."

The hypothesis's original claim that the server falsely emits `done_reason:stop` is INCORRECT (tracer rejected). The refined finding is the absence of any terminal marker when scanner sees a clean EOF at a newline boundary.

Synth disposition: MEDIUM. This is an agentic-AI era finding — classical threat models don't treat truncation as security-relevant, but in agent pipelines the silent truncation is a real decision-manipulation vector.

## Reproduction Steps

1. Set up a crash trigger that fires deterministically after N tokens of output (e.g., a prompt that causes the runner to process a specific OOM-triggering action mid-generation).
2. Have an agent call `/api/generate` with streaming; log the raw NDJSON response.
3. Observe that some fraction of runs end without a `{"done":true,...}` line AND without any `{"error":...}` line.
4. Demonstrate agent-decision divergence between truncated and complete responses.
5. Fix direction: (a) at `llm/server.go:1707` replace `return nil` with a check for whether the last-seen chunk had `done:true` — if not, return a synthetic error indicating unclean termination; (b) emit a final `{"error":"stream terminated unexpectedly"}` in `streamResponse` whenever the channel closes without having emitted a `done:true` chunk; (c) document the contract that streaming clients MUST treat missing `done:true` as a failure.

Pattern: register AP-052 `streaming-terminates-without-sentinel` — a stream protocol requires a terminal sentinel but the server can close the stream cleanly without emitting it under crash/EOF timing.
