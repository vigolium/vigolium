package main

import (
	"fmt"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered:", r)
		}
	}()

	// Allocate 1 PB - this exceeds typical kernel mmap limits
	n := int64(1) << 50
	fmt.Printf("Allocating %d bytes (1 PB)...\n", n)
	b := make([]byte, 0, n)
	fmt.Println("Allocated, cap:", cap(b))
}
