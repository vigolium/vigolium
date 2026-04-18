Phase: 10
Sequence: p10-023-a
Slug: fsgguf-lazy-count-uncapped-iter
Verdict: VALID
Rationale: fs/gguf/lazy.go newLazy reads a raw uint64 count from wire and iterates it without a cap, appending one TensorInfo or KeyValue struct per iteration to it.values, causing unbounded heap growth identical in mechanism to the confirmed AP-023 finding in fs/ggml/gguf.go.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-023-gguf-numtensor-uncapped.md
Origin-Pattern: AP-023

## Summary

`fs/gguf/lazy.go:19-43` (`newLazy`) reads an 8-byte little-endian `uint64` directly from the file as `it.count` and then drives a goroutine loop `for i := range it.count` with no cap. Each iteration calls the supplied `fn()` callback — either `readTensor` (returning a `TensorInfo` struct containing a name string and shape slice) or `readKeyValue` (returning a `KeyValue` struct containing a string key and `any` value) — and unconditionally appends the result to `it.values`. There is no check of the form `if count > fileSize / minEntrySize { return error }` before the loop starts.

This is a structurally identical variant of the confirmed AP-023 finding in `fs/ggml/gguf.go:194` (`for range llm.numTensor()`). The `fs/gguf/` package is a separate, newer GGUF parser used by `server/images.go` via `gguf.Open()`; the `fs/ggml/` package is the older parser used by `ggml.Decode()`. Both parsers share the root cause: an uncapped wire-sourced count that drives a per-iteration allocation loop.

The structural bound (file-size / minEntrySize) reduces but does not eliminate the attack: a 500 MB GGUF with count=30M produces roughly 1.2 GB of `TensorInfo` allocation (each struct holds a string name ≥1 byte + 32-byte shape header + pointer), enough to exhaust RAM on a 2 GB container.

## Location

`fs/gguf/lazy.go:19-43` — `newLazy[T]`

```go
func newLazy[T any](f *File, fn func() (T, error)) (*lazy[T], error) {
    it := lazy[T]{}
    if err := binary.Read(f.reader, binary.LittleEndian, &it.count); err != nil {
        return nil, err
    }                                        // it.count is raw uint64 from wire — no cap

    it.values = make([]T, 0)
    it.next, it.stop = iter.Pull(func(yield func(T) bool) {
        for i := range it.count {            // iterates up to 2^64 times
            t, err := fn()
            if err != nil {
                slog.Error("error reading tensor", "index", i, "error", err)
                return
            }

            it.values = append(it.values, t) // unbounded heap growth
            if !yield(t) {
                break
            }
        }
        ...
    })
    return &it, nil
}
```

Called from `fs/gguf/gguf.go:72` and `fs/gguf/gguf.go:85`:

```go
f.tensors, err = newLazy(f, f.readTensor)    // count = numTensor from wire
...
f.keyValues, err = newLazy(f, f.readKeyValue) // count = numKV from wire
```

## Attacker Control

`gguf.Open` is called from `server/images.go:89` inside `(*Model).Capabilities()`:

```go
f, err := gguf.Open(m.ModelPath)
if err == nil {
    defer f.Close()
    if f.KeyValue("pooling_type").Valid() { ... }
    ...
}
```

`Capabilities()` is invoked from:
- `server/routes.go` — `/api/show`, `/api/ps`, and model-load paths.
- Each call triggers lazy iteration of KV entries and tensor metadata.

An attacker who can cause the server to load or inspect a crafted GGUF (via `/api/pull`, `/api/create FROM <crafted>`, or pushing a malicious model to a registry the server trusts) can reach this code. The model path is on-disk but is derived from a user-controlled model name/digest, and no trust boundary separates the file bytes from the allocation size.

## Trust Boundary Crossed

Network API (unauthenticated by default) / pulled model blob -> process heap -> kernel OOM-killer.

## Impact

Memory exhaustion DoS. A 500 MB malicious GGUF declaring numTensor=30M (each tensor record consuming ~17 bytes from file) produces ~1.2 GB of TensorInfo allocations before file-EOF terminates the loop. On a 4 GB server this is sufficient to drive swap or OOM-kill. Because `Capabilities()` is called on every `/api/show` request for a loaded model, the model need only be pulled once; subsequent `/api/show` requests each trigger a fresh full loop (the lazy iterator resets on each `Open`).

Unlike the `fs/ggml/` AP-023 finding, there is no `maxArraySize` guard in this path — the `fs/gguf` package has no equivalent parameter.

## Evidence

```
// fs/gguf/lazy.go:19-43
func newLazy[T any](f *File, fn func() (T, error)) (*lazy[T], error) {
    it := lazy[T]{}
    binary.Read(f.reader, binary.LittleEndian, &it.count)  // raw uint64
    // NO: if it.count > fileSize/minEntrySize { return nil, fmt.Errorf(...) }
    it.values = make([]T, 0)
    it.next, it.stop = iter.Pull(func(yield func(T) bool) {
        for i := range it.count {           // iterates count times, bounded only by EOF
            t, err := fn()
            ...
            it.values = append(it.values, t)  // heap grows with every iteration
```

Contrast with the confirmed AP-023 fix direction: `if numTensor > (fileSize - headerSize) / minTensorInfoSize { return error }` before the loop.

The `fs/gguf/gguf.go:Open` function does NOT apply any such check before calling `newLazy`.

## Reproduction Steps

1. Craft a GGUF v3 file: magic `GGUF`, version 3, numTensor = `0x1C9C380` (30M), numKV = 0, then enough minimal tensor records to keep the loop running (each: 1-byte name length, 1 byte name, dims=0, kind=0, offset=0 = ~14 bytes each).
2. Upload the model blob via `POST /api/blobs/:digest` and reference it via `POST /api/pull` or `POST /api/create FROM <name>`.
3. Issue `GET /api/show?name=<model>` to trigger `Capabilities()`.
4. Observe RSS growth during the `newLazy` goroutine loop before EOF is hit.

Fix direction: in `newLazy`, add a pre-loop sanity check:
```go
if f.reader.offset+int64(it.count)*minEntryBytes > fileSize {
    return nil, fmt.Errorf("count %d exceeds file size", it.count)
}
```
or apply a hard cap (e.g., 10M tensors).
