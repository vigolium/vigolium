package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func main() {
	hdr2 := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	f := bytes.NewReader(hdr2)

	var n int64
	binary.Read(f, binary.LittleEndian, &n)
	fmt.Printf("n = %d\n", n)

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered:", r)
		}
	}()

	b := bytes.NewBuffer(make([]byte, 0, n))
	fmt.Println("cap:", b.Cap())
}
