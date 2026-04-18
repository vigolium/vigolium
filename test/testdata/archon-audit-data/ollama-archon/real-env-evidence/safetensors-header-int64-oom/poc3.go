package main

import (
	"fmt"
	"runtime"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered:", r)
		}
	}()

	n := int64(1) << 40 // 1 TB
	fmt.Printf("Allocating %d bytes...\n", n)
	b := make([]byte, 0, n)
	fmt.Println("Allocated, cap:", cap(b))

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("HeapSys: %d bytes\n", m.HeapSys)
}
