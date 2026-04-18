Phase: 8
Sequence: 009
Slug: content-range-not-validated
Verdict: VALID
Rationale: downloadChunk sends a Range request but does not verify resp.StatusCode == 206 or parse Content-Range; io.CopyN unconditionally copies `part.Size - completed` bytes from the body; Advocate confirmed no downstream validation.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-01/debate.md

## Summary

`server/download.go:331-389 downloadChunk` sends a `Range: bytes=<start>-<end>` request but does not validate:
- that `resp.StatusCode == http.StatusPartialContent` (a 200 OK is silently accepted)
- that the response's `Content-Range` header matches the requested range

`io.CopyN(w, io.TeeReader(resp.Body, part), part.Size-part.Completed.Load())` reads from the body's offset 0 regardless of what bytes the server actually sent. A MITM on the blob CDN path can return a 200 OK with the entire blob body for each Range request. Each part slot then contains the blob's prefix (or whatever the server sent), causing each part to write overlapping/wrong bytes into the sparse file. The streaming SHA-256 over the reassembled file detects the mismatch, so no silent content substitution occurs — but the `-partial` file persists, and the retry loop endlessly redownloads without ever succeeding. This is a persistent stuck-download DoS requiring user intervention (delete `-partial*` files).

## Location

- `server/download.go:331-389` — `downloadChunk`
- Line 334-338 — builds Range header
- Line 339 — `resp, err := http.DefaultClient.Do(req)` (no CheckRedirect customization here)
- Line 345 — `io.CopyN(...)` without validating `resp.StatusCode` or `Content-Range`

## Attacker Control

MITM on the CDN path (can be achieved via Finding 010 scheme downgrade if HTTPS→HTTP redirect is followed, or directly if the CDN is itself HTTP).

## Trust Boundary Crossed

Network (untrusted CDN) → local file / state.

## Impact

Persistent stuck downloads; user-visible DoS of pulls. The hash check prevents silent corruption, so this is classified MEDIUM (availability only, not integrity).

## Evidence

```go
// server/download.go:331-359
func (b *blobDownload) downloadChunk(ctx context.Context, requestURL *url.URL, w io.Writer, part *blobDownloadPart) error {
    g, ctx := errgroup.WithContext(ctx)
    g.Go(func() error {
        req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
        ...
        req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", part.StartsAt(), part.StopsAt()-1))
        resp, err := http.DefaultClient.Do(req)
        ...
        defer resp.Body.Close()

        // No resp.StatusCode check.
        // No Content-Range parse.

        n, err := io.CopyN(w, io.TeeReader(resp.Body, part), part.Size-part.Completed.Load())
        ...
    })
    ...
}
```

## Reproduction Steps

1. Configure a victim to pull a >200 MB blob via a transparent proxy that responds 200 OK with the full body to every Range request.
2. Observe that each part writes the prefix bytes to its offset slot, making the assembled file garbled; SHA-256 fails; download loops indefinitely; `-partial` file persists on disk.

Debate context: Advocate confirmed no status or Content-Range check anywhere in the chain. Fix: after `resp, err := client.Do(req)`, assert `resp.StatusCode == 206` (and optionally parse `Content-Range`), fail fast otherwise.
