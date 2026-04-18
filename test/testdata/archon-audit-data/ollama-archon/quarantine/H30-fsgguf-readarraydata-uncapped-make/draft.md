Phase: 10
Sequence: 000
Slug: fsgguf-readarraydata-uncapped-make
Verdict: VALID
Rationale: fs/gguf/gguf.go readArrayData and readArrayString call make([]T, n) where n is a raw uint64 from wire with no cap, enabling single-call heap exhaustion for any GGUF KV entry whose value is an array type.
Severity-Original: HIGH
Severity-Final: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-023-gguf-numtensor-uncapped.md
Origin-Pattern: AP-023

## Summary

`fs/gguf/gguf.go:248-273` defines two functions — `readArrayData[T]` and `readArrayString` — that are called from `readArray` (line 207) whenever a GGUF key-value entry carries an array-typed value. Both functions read a `uint64 n` from the wire (the array count) and immediately pass it to `make([]T, n)` and `make([]string, n)` respectively, with no cap against file size or a hard ceiling. A single crafted GGUF KV entry of type `typeArray` with a declared count of, e.g., `0x7FFFFFFFFFFFFFFF` (int64 max as uint64) causes `runtime.mallocgc` to request ~2^63 bytes — an instantly fatal allocation.

The root cause is the same as AP-023 (count from wire drives allocation without a fileSize/minEntrySize pre-check), but the exploitation shape here is a single-record OOM (analogous also to AP-021) rather than an iterative loop. The allocation is upfront: the entire slice is pre-allocated before the per-element read loop begins.

This is in `fs/gguf/` — the newer GGUF parser package (distinct from the `fs/ggml/` package). The `fs/ggml/` package has a `maxArraySize` guard via `newArray`; `fs/gguf/` has no equivalent.

## Location

`fs/gguf/gguf.go:248-273`

```go
func readArrayData[T any](f *File, n uint64) (s []T, err error) {
    s = make([]T, n)          // n is raw uint64 from wire — no cap
    for i := range n {
        e, err := read[T](f)
        if err != nil {
            return nil, err
        }
        s[i] = e
    }
    return s, nil
}

func readArrayString(f *File, n uint64) (s []string, err error) {
    s = make([]string, n)     // n is raw uint64 from wire — no cap
    for i := range n {
        e, err := readString(f)
        if err != nil {
            return nil, err
        }
        s[i] = e
    }
    return s, nil
}
```

Called from `readArray` at line 207:

```go
func readArray(f *File) (any, error) {
    t, err := read[uint32](f)   // type tag
    n, err := read[uint64](f)   // count — raw, uncapped
    switch t {
    case typeUint8:
        return readArrayData[uint8](f, n)
    ...
    case typeString:
        return readArrayString(f, n)
    }
}
```

`readArray` is called from `readKeyValue` (line 167) for any KV entry of type `typeArray`. `readKeyValue` is the `fn` callback passed to `newLazy` for the `f.keyValues` iterator, so it is triggered on every KV iteration in `gguf.Open`.

## Attacker Control

Same as p10-023-a: `gguf.Open` is called from `server/images.go:89` inside `(*Model).Capabilities()`, reachable from `/api/show`, `/api/ps`, and model-load paths. An attacker-controlled GGUF (via `/api/pull`, `/api/create FROM`, or a malicious registry) that contains a KV entry of type `typeArray` with a large count field triggers the uncapped allocation.

A single such KV entry is sufficient: `count = 0x1FFFFFFF` (`uint64` ≈ 512M) for `typeFloat32` arrays requests 2 GB in one `make([]float32, 0x1FFFFFFF)` call.

## Trust Boundary Crossed

Network API (unauthenticated by default) / model blob -> process heap -> kernel OOM-killer.

## Impact

Instant unrecoverable OOM for the process. Unlike p10-023-a (which exhausts memory gradually across `count` iterations), this variant allocates the full slice upfront before any elements are read, so the OOM occurs at `make` time — before the read loop can encounter EOF. The attack succeeds even with a tiny file (8 bytes for the count field, then the parser crashes before reading a single element).

This is more severe than p10-023-a in that it requires a smaller crafted file and produces a faster OOM.

## Evidence

```
// fs/gguf/gguf.go:248-259
func readArrayData[T any](f *File, n uint64) (s []T, err error) {
    s = make([]T, n)  // NO CAP — n up to 2^64-1
    for i := range n {
        e, err := read[T](f)
        ...
    }
}
```

Contrast with the safe pattern in `fs/ggml/gguf.go:416-421`:
```go
func newArray[T any](size, maxSize int) *array[T] {
    a := array[T]{size: size}
    if maxSize < 0 || size <= maxSize {
        a.values = make([]T, size)  // only allocates if below maxSize cap
    }
    return &a
}
```
The `fs/gguf` package does not use `newArray` and has no equivalent guard.

## Reproduction Steps

1. Craft a GGUF v3 file: magic, version=3, numTensor=0, numKV=1.
   KV entry: key="general.test" (valid UTF-8), type=typeArray (0x09 = 9),
   then array type=typeFloat32 (0x06 = 6), array count=0x1FFFFFFF (512M).
   Total file size: ~50 bytes.
2. Upload as a model blob and pull/create a model pointing to it.
3. Issue `GET /api/show?name=<model>`.
4. `gguf.Open` → `readKeyValue` → `readArray` → `readArrayData[float32](f, 0x1FFFFFFF)` →
   `make([]float32, 536870911)` = 2 GB allocation.
5. Process OOM-kills before returning from `make`.

Fix direction: in `readArray`, add before the switch:
```go
if uint64(n) > uint64(maxArrayElements) {
    return nil, fmt.Errorf("array count %d exceeds limit", n)
}
```
where `maxArrayElements` matches `llm.maxArraySize` semantics from `fs/ggml/`.
