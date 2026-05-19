package httpmsg_test

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// Example demonstrating FindBodyOffset with CRLF line endings
func ExampleFindBodyOffset() {
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\nBODY DATA")

	offset := httpmsg.FindBodyOffset(request)
	fmt.Printf("Body starts at offset: %d\n", offset)
	fmt.Printf("Body content: %s\n", string(request[offset:]))

	// Output:
	// Body starts at offset: 55
	// Body content: BODY DATA
}

// Example demonstrating FindBodyOffset with LF line endings
func ExampleFindBodyOffset_lf() {
	request := []byte("GET / HTTP/1.1\nHost: example.com\nUser-Agent: test\n\nBODY DATA")

	offset := httpmsg.FindBodyOffset(request)
	fmt.Printf("Body starts at offset: %d\n", offset)
	fmt.Printf("Body content: %s\n", string(request[offset:]))

	// Output:
	// Body starts at offset: 51
	// Body content: BODY DATA
}

// Example demonstrating FindBodyEnd with trailing separators
func ExampleFindBodyEnd() {
	response := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nBODY DATA\r\n\r\n")

	bodyStart := httpmsg.FindBodyOffset(response)
	bodyEnd := httpmsg.FindBodyEnd(response, bodyStart)

	fmt.Printf("Body starts at: %d\n", bodyStart)
	fmt.Printf("Body ends at: %d\n", bodyEnd)
	fmt.Printf("Body content: %s\n", string(response[bodyStart:bodyEnd]))

	// Output:
	// Body starts at: 44
	// Body ends at: 53
	// Body content: BODY DATA
}

// Example demonstrating SliceBytes for safe byte slicing
func ExampleSliceBytes() {
	data := []byte("Hello, World!")

	// Normal slice
	slice1 := httpmsg.SliceBytes(data, 0, 5)
	fmt.Printf("Slice [0:5]: %s\n", string(slice1))

	// Slice with end beyond length (automatically capped)
	slice2 := httpmsg.SliceBytes(data, 7, 100)
	fmt.Printf("Slice [7:100]: %s\n", string(slice2))

	// Output:
	// Slice [0:5]: Hello
	// Slice [7:100]: World!
}

// Example demonstrating IndexOfByte
func ExampleIndexOfByte() {
	data := []byte("hello world")

	// Find first 'o'
	idx1 := httpmsg.IndexOfByte(data, 'o', 0)
	fmt.Printf("First 'o' at index: %d\n", idx1)

	// Find second 'o' (start searching after first)
	idx2 := httpmsg.IndexOfByte(data, 'o', idx1+1)
	fmt.Printf("Second 'o' at index: %d\n", idx2)

	// Not found
	idx3 := httpmsg.IndexOfByte(data, 'x', 0)
	fmt.Printf("'x' found at: %d\n", idx3)

	// Output:
	// First 'o' at index: 4
	// Second 'o' at index: 7
	// 'x' found at: -1
}

// Example demonstrating IndexOfBytes for finding byte sequences
func ExampleIndexOfBytes() {
	data := []byte("The quick brown fox jumps over the lazy dog")

	// Find "quick"
	idx1 := httpmsg.IndexOfBytes(data, []byte("quick"), 0)
	fmt.Printf("'quick' found at: %d\n", idx1)

	// Find "the" (case sensitive)
	idx2 := httpmsg.IndexOfBytes(data, []byte("the"), 0)
	fmt.Printf("'the' found at: %d\n", idx2)

	// Not found
	idx3 := httpmsg.IndexOfBytes(data, []byte("cat"), 0)
	fmt.Printf("'cat' found at: %d\n", idx3)

	// Output:
	// 'quick' found at: 4
	// 'the' found at: 31
	// 'cat' found at: -1
}

// Example showing complete HTTP request parsing workflow
func ExampleFindBodyOffset_httpWorkflow() {
	// HTTP request with body
	request := []byte("POST /api/data HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 18\r\n" +
		"\r\n" +
		"{\"key\":\"value\"}")

	// Find where body starts
	bodyOffset := httpmsg.FindBodyOffset(request)

	// Extract headers (everything before body)
	headers := httpmsg.SliceBytes(request, 0, bodyOffset-4) // -4 to exclude \r\n\r\n
	fmt.Printf("Headers length: %d bytes\n", len(headers))

	// Extract body
	body := httpmsg.SliceBytes(request, bodyOffset, len(request))
	fmt.Printf("Body: %s\n", string(body))

	// Find Content-Type in headers
	ctIdx := httpmsg.IndexOfBytes(headers, []byte("Content-Type:"), 0)
	if ctIdx != -1 {
		fmt.Println("Content-Type header found")
	}

	// Output:
	// Headers length: 94 bytes
	// Body: {"key":"value"}
	// Content-Type header found
}
