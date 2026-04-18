Phase: 8
Sequence: 045
Slug: intermediate-blobs-race
Verdict: VALID
Rationale: Unprotected concurrent map access on package-level intermediateBlobs causes unrecoverable Go runtime fatal error (not a panic); remotely triggerable via concurrent blob upload requests. Narrow race window prevents severity upgrade to HIGH.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-C/debate.md

## Summary

The `intermediateBlobs` variable in `server/model.go:21` is a package-level `map[string]string` that is read, written, and deleted from HTTP handler goroutines without any synchronization primitives (no mutex, no sync.Map, no channel). When two concurrent `POST /api/blobs/:digest` requests access this map simultaneously, Go's runtime detects the concurrent map access and issues a fatal `throw` -- not a recoverable panic. This kills the server process regardless of any panic recovery middleware.

## Location

- **Declaration**: `server/model.go:21` -- `var intermediateBlobs map[string]string = make(map[string]string)`
- **Read**: `server/routes.go:1501` -- `if ib, ok := intermediateBlobs[c.Param("digest")]; ok {`
- **Delete**: `server/routes.go:1510` -- `delete(intermediateBlobs, c.Param("digest"))`

## Attacker Control

The attacker sends two or more concurrent `POST /api/blobs/:digest` requests. The digest parameter determines which map key is accessed. Concurrent requests with the same or different digests can trigger the race.

## Trust Boundary Crossed

Network (unauthenticated HTTP) -> Go runtime concurrent map detection -> process fatal error.

## Impact

- **Availability**: Server process crash (DoS). Unrecoverable by middleware.
- **Attack complexity**: MEDIUM. Requires hitting a narrow race window, but can be automated with concurrent requests.
- **Authentication**: None required.
- **Note**: Go's `throw` on concurrent map access is a runtime safety check, not undefined behavior. The process terminates cleanly but cannot be caught by `recover()`.

## Evidence

1. `server/model.go:21` -- package-level map without synchronization
2. `server/routes.go:1501` -- map read in HTTP handler goroutine
3. `server/routes.go:1510` -- map delete in HTTP handler goroutine (potentially concurrent)
4. Go runtime behavior: concurrent map read+write causes fatal `throw("concurrent map read and map write")`
5. Deep probe PH-08/PH-13 validated the race condition

## Reproduction Steps

1. Start the Ollama server
2. In parallel, send multiple `POST /api/blobs/sha256:0000...0000` requests with dummy body content
3. Use a tool like `hey` or `ab` to generate concurrent requests: `hey -n 1000 -c 50 -m POST -d '@dummy.bin' http://localhost:11434/api/blobs/sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
4. Monitor the server process. Under sufficient concurrency, the process crashes with: `fatal error: concurrent map read and map write`
5. Verify the server process has exited (not just request failures)
