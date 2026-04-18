package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// Simulates the exact pattern in convert/reader_safetensors.go:34-42
// to verify what happens with MaxInt64 as the header length.
func simulate(hdrBytes []byte) {
	fmt.Println("--- Starting simulation ---")
	f := bytes.NewReader(hdrBytes)

	var n int64
	if err := binary.Read(f, binary.LittleEndian, &n); err != nil {
		fmt.Println("binary.Read error:", err)
		return
	}
	fmt.Printf("n = %d (0x%x)\n", n, uint64(n))

	// This is the vulnerable line:
	fmt.Println("About to call make([]byte, 0, n)...")
	b := bytes.NewBuffer(make([]byte, 0, n))
	fmt.Println("make succeeded, buffer cap:", b.Cap())

	// io.CopyN from an EOF-ed reader with n = MaxInt64 would eventually error
	_, err := io.CopyN(b, f, n)
	fmt.Println("io.CopyN err:", err)
}

func main() {
	// Case 1: MaxInt64 (0x7FFFFFFFFFFFFFFF) as 8 little-endian bytes
	hdr1 := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F}
	fmt.Printf("Case 1: header = %x (MaxInt64)\n", hdr1)

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered from panic:", r)
		}
	}()
	simulate(hdr1)

	// If we get here without crash, try negative
	hdr2 := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	fmt.Printf("\nCase 2: header = %x (-1 as int64)\n", hdr2)
	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("Recovered from panic (case 2):", r)
			}
		}()
		simulate(hdr2)
	}()

	os.Exit(0)
}
