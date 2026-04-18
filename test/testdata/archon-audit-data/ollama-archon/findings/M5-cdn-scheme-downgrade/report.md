## Summary

When a blob is fetched, `server/download.go:229-270` issues an initial request to the registry and, via a `CheckRedirect` hook, stops at the first redirect whose hostname differs from the original. `resp.Location()` is returned as `directURL` without any check on its scheme. If the registry (or a MITM on the registry response) returns `302 Location: http://cdn.attacker.com/blob/...`, all subsequent Range requests are sent over plaintext HTTP. Combined with Finding 009 (no 206/Content-Range validation), attacker on the HTTP path can stall downloads; combined with a hash collision or prior substitution (Finding 013 in shared-cache configs), bytes are exfiltrated or replaced.

## Details

When a blob is fetched, `server/download.go:229-270` issues an initial request to the registry and, via a `CheckRedirect` hook, stops at the first redirect whose hostname differs from the original. `resp.Location()` is returned as `directURL` without any check on its scheme. If the registry (or a MITM on the registry response) returns `302 Location: http://cdn.attacker.com/blob/...`, all subsequent Range requests are sent over plaintext HTTP. Combined with Finding 009 (no 206/Content-Range validation), attacker on the HTTP path can stall downloads; combined with a hash collision or prior substitution (Finding 013 in shared-cache configs), bytes are exfiltrated or replaced.

### Location

- `server/download.go:229-270` — redirect resolution and `directURL` storage
- `server/download.go:240-254` — `CheckRedirect` hook (Hostname-only)
- `server/download.go:268` — `return resp.Location()` (no scheme validation)
- `server/download.go:287` — `downloadChunk(inner, directURL, w, part)` uses directURL for all parts

### Attacker Control

Malicious registry OR MITM at the 302 response. In both cases, the attacker chooses the Location URL's scheme.

### Trust Boundary Crossed

HTTPS-protected channel → plaintext HTTP.

### Evidence

```go
// server/download.go:229-270
directURL, err := func() (*url.URL, error) {
    ...
    newOpts.CheckRedirect = func(req *http.Request, via []*http.Request) error {
        if len(via) > 10 { return errMaxRedirectsExceeded }
        // if the hostname is the same, allow the redirect
        if req.URL.Hostname() == requestURL.Hostname() { return nil }
        // stop at the first redirect that is not the same hostname as the original request.
        return http.ErrUseLastResponse
    }
    resp, err := makeRequestWithRetry(ctx, http.MethodGet, requestURL, nil, nil, newOpts)
    ...
    if resp.StatusCode != http.StatusTemporaryRedirect && resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
    }
    return resp.Location()   // <-- scheme not validated
}()
```

## Root Cause

Validated rationale: blobDownload.Prepare stores resp.Location() directly as directURL with no scheme validation; all subsequent downloadChunk calls use whatever scheme the registry redirected to — Advocate found no Scheme assertion and the CheckRedirect hook only checks Hostname.

Primary cited code reference: `server/download.go:229`.

Merge extraction sink line: - `server/download.go:229-270` — redirect resolution and `directURL` storage

## Proof of Concept

Merge-normalized status: `pending`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

1. Stand up `registry.attacker.com` (HTTPS) that returns `302 Location: http://cdn.attacker.com/blob/<digest>` for `GET /v2/x/blobs/<digest>`.
2. Victim: `ollama pull registry.attacker.com/x:latest`.
3. Observe all chunk fetches go to `http://cdn.attacker.com/...` — visible via plain pcap.

Debate context: Advocate confirmed no scheme validation on the Location result. Fix: after obtaining `directURL`, assert `directURL.Scheme == requestURL.Scheme` (or at minimum, if `requestURL.Scheme == "https"`, require `directURL.Scheme == "https"`).

## Impact

- Blob bytes travel plaintext — observable by any network-adjacent party.
- In concert with Finding 009 (no 206 check), attacker on HTTP path forces stuck downloads (DoS).
- Integrity preserved only by the streaming hash; attacker cannot substitute known-good bytes without a SHA-256 collision.

_Synthesized during merge normalization from `archon/findings/M5-cdn-scheme-downgrade/draft.md`._
