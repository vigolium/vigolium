## Summary

`fs/gguf/tensor.go:19-29` defines `TensorInfo.NumValues()` which iterates over
`TensorInfo.Shape []uint64` and accumulates the product using a signed `int64`
accumulator.  Any dimension value >= 2^63 causes `int64(dim)` to wrap
immediately to a large negative number; any pair of dimensions whose product
exceeds 2^63 likewise wraps.  `NumBytes()` converts that negative `int64`
through `float64` back to `int64`, producing an unpredictable negative or
small-positive result.

`fs/gguf/gguf.go:338-346` (`TensorReader`) calls `t.NumBytes()` in two places:

1. The guard `t.NumBytes() == 0` at line 340 — a negative value is NOT zero,
   so the guard passes.
2. `io.NewSectionReader(f.file, f.offset+int64(t.Offset), t.NumBytes())` at
   line 346 — a negative `size` argument is accepted by `io.NewSectionReader`
   without error but causes every `Read` call on the returned reader to return
   `io.EOF` immediately or, for values that wrap back positive, to declare an
   incorrect window into the underlying file.

This is a structural sibling of AP-020.  AP-020 uses *unsigned* uint64
overflow in `fs/ggml/ggml.go:Elements()/Size()`.  This finding uses *signed*
int64 overflow in the separate `fs/gguf` package's equivalent, and the bounds
guard (`== 0`) is weaker than AP-020's file-size compare.

## Details

`fs/gguf/tensor.go:19-29` defines `TensorInfo.NumValues()` which iterates over
`TensorInfo.Shape []uint64` and accumulates the product using a signed `int64`
accumulator.  Any dimension value >= 2^63 causes `int64(dim)` to wrap
immediately to a large negative number; any pair of dimensions whose product
exceeds 2^63 likewise wraps.  `NumBytes()` converts that negative `int64`
through `float64` back to `int64`, producing an unpredictable negative or
small-positive result.

`fs/gguf/gguf.go:338-346` (`TensorReader`) calls `t.NumBytes()` in two places:

1. The guard `t.NumBytes() == 0` at line 340 — a negative value is NOT zero,
   so the guard passes.
2. `io.NewSectionReader(f.file, f.offset+int64(t.Offset), t.NumBytes())` at
   line 346 — a negative `size` argument is accepted by `io.NewSectionReader`
   without error but causes every `Read` call on the returned reader to return
   `io.EOF` immediately or, for values that wrap back positive, to declare an
   incorrect window into the underlying file.

This is a structural sibling of AP-020.  AP-020 uses *unsigned* uint64
overflow in `fs/ggml/ggml.go:Elements()/Size()`.  This finding uses *signed*
int64 overflow in the separate `fs/gguf` package's equivalent, and the bounds
guard (`== 0`) is weaker than AP-020's file-size compare.

### Location

- `fs/gguf/tensor.go:19-25` — `NumValues()` unchecked int64 multiply
- `fs/gguf/tensor.go:28-29` — `NumBytes()` propagates the overflow through float64
- `fs/gguf/gguf.go:340` — guard `NumBytes() == 0` does not catch negative
- `fs/gguf/gguf.go:346` — `io.NewSectionReader` created with negative/wrong size

### Attacker Control

A crafted GGUF file read by `fs/gguf.Open()` → `TensorReader()` reaches this
path.  `server/images.go:89` calls `gguf.Open(m.ModelPath)` during
`Capabilities()`, which is invoked on every blob enumerated at startup and on
`/api/show`.  Any model delivered via `POST /api/create`, `POST /api/pull`, or
`POST /api/blobs/:digest` that reaches the blob store can trigger this on the
next enumeration.

### Trust Boundary Crossed

Network API (unauthenticated loopback default) → Go heap and mmap'd file
regions; the incorrect SectionReader window may expose bytes from adjacent
file regions when the computed offset+size lands within the file's extent.

### Evidence

```go
// fs/gguf/tensor.go:19-29
func (ti TensorInfo) NumValues() int64 {
    var numItems int64 = 1
    for _, dim := range ti.Shape {
        numItems *= int64(dim)   // uint64 -> int64 cast: wraps negative for dim >= 2^63
    }
    return numItems
}

func (ti TensorInfo) NumBytes() int64 {
    return int64(float64(ti.NumValues()) * ti.Type.NumBytes())
    // float64 round-trip loses precision; negative NumValues produces negative result
}

// fs/gguf/gguf.go:338-346
func (f *File) TensorReader(name string) (TensorInfo, io.Reader, error) {
    t := f.TensorInfo(name)
    if t.NumBytes() == 0 {           // GUARD: negative passes this check
        return TensorInfo{}, nil, fmt.Errorf("tensor %s not found", name)
    }
    _ = f.tensors.rest()
    return t, io.NewSectionReader(f.file, f.offset+int64(t.Offset), t.NumBytes()), nil
    //                                                                ^^^^^^^^^^^^^^^^^
    //  Negative NumBytes() passed as size; window is wrong/invalid
}
```

Craft: `Shape = [0x8000000000000001]` → `int64(0x8000000000000001) = -9223372036854775807` → `NumValues() = -9223372036854775807` → `NumBytes() = int64(float64(-9223372036854775807)*4.0)` = very large negative.

## Root Cause

Validated rationale: fs/gguf/tensor.go TensorInfo.NumValues() multiplies attacker-supplied uint64 Shape dimensions as int64, wrapping signed-negative on any dimension >= 2^63 or on product overflow, producing a negative NumBytes() that corrupts the io.NewSectionReader length and silently defeats bounds validation in TensorReader.

Primary cited code reference: `fs/gguf/tensor.go:19`.

Merge extraction sink line: - `fs/gguf/tensor.go:19-25` — `NumValues()` unchecked int64 multiply

This finding was retained as a variant during merge normalization. Origin finding: `C2`. Origin pattern: `AP-020`.

## Proof of Concept

Merge-normalized status: `pending`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

1. Craft a GGUF file (fs/gguf format, version >= 2) with one tensor whose
   `Shape = [0x8000000000000001]` and `Type = TensorTypeF32`.
2. Place the file in the blob store and add a model reference.
3. Call `GET /api/show` or restart the server to trigger `Capabilities()` →
   `gguf.Open()` → `TensorReader()`.
4. Observe: either (a) no error despite malformed metadata propagating, or (b)
   the returned reader delivers bytes from outside the intended tensor region.

Fix: Use `math/bits.Mul64` (or `math.MaxInt64` guard) in `NumValues()`;
rewrite `NumBytes()` to operate on uint64 throughout; gate `TensorReader` on
`t.Offset + uint64(computedSize) <= fileSize`.

## Impact

- **Information disclosure**: `io.NewSectionReader` with an attacker-controlled
  offset reads bytes from the wrong region of the model file; if the
  `TensorReader` result is piped into an API response the caller sees data from
  outside the intended tensor.
- **Bypass of bounds guard**: The `Valid()` check (`NumBytes() > 0`) passes for
  any non-zero (including negative) value, allowing invalid tensor metadata to
  propagate into downstream readers without triggering an error path.
- **Denial of service**: When the negative int64 is re-interpreted as a large
  unsigned value by the SectionReader implementation, subsequent IO operations
  stall waiting for bytes that do not exist.

_Synthesized during merge normalization from `archon/findings/H25-fsgguf-numvalues-int64-signed-overflow/draft.md`._
