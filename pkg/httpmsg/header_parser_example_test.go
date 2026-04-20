package httpmsg_test

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// Example_extractHeaders demonstrates extracting HTTP headers with byte offsets
func Example_extractHeaders() {
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\nBODY")

	// Extract headers manually
	bodyStart := httpmsg.FindHeaderBodySeparator(request, 0)
	headers, offsets, _ := httpmsg.ExtractHeaders(request, 0, bodyStart)

	fmt.Println("Headers:")
	for i, header := range headers {
		fmt.Printf("  [%d] Offset %d: %s\n", i, offsets[i], header)
	}

	// Output:
	// Headers:
	//   [0] Offset 0: GET / HTTP/1.1
	//   [1] Offset 16: Host: example.com
	//   [2] Offset 35: User-Agent: Mozilla/5.0
}

// Example_extractAllHeaders demonstrates the convenience function
func Example_extractAllHeaders() {
	request := []byte("GET /api/users HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n{\"user\":\"test\"}")

	headers, offsets, bodyStart, _ := httpmsg.ExtractAllHeaders(request)

	fmt.Println("Request line:", headers[0])
	fmt.Println("Header count:", len(headers))
	fmt.Println("Body starts at:", bodyStart)
	fmt.Println("First header offset:", offsets[0])

	// Output:
	// Request line: GET /api/users HTTP/1.1
	// Header count: 3
	// Body starts at: 82
	// First header offset: 0
}

// Example_getHeader demonstrates case-insensitive header lookup
func Example_getHeader() {
	headers := []string{
		"POST /upload HTTP/1.1",
		"Host: example.com",
		"Content-Type: multipart/form-data; boundary=----WebKit",
		"Content-Length: 1234",
	}

	// Case-insensitive lookup
	host := httpmsg.Header(headers, "host")
	contentType := httpmsg.Header(headers, "CONTENT-TYPE")
	missing := httpmsg.Header(headers, "Authorization")

	fmt.Println("Host:", host)
	fmt.Println("Content-Type:", contentType)
	fmt.Println("Missing header:", missing)

	// Output:
	// Host: example.com
	// Content-Type: multipart/form-data; boundary=----WebKit
	// Missing header:
}

// Example_parseContentType demonstrates parsing Content-Type header
func Example_parseContentType() {
	headers := []string{
		"POST /upload HTTP/1.1",
		"Host: example.com",
		"Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
	}

	mimeType, boundary := httpmsg.ParseContentType(headers)

	fmt.Println("MIME type:", mimeType)
	fmt.Println("Boundary:", boundary)

	// Output:
	// MIME type: multipart/form-data
	// Boundary: ----WebKitFormBoundary7MA4YWxkTrZu0gW
}

// Example_parseContentTypeSimple demonstrates simple Content-Type without parameters
func Example_parseContentTypeSimple() {
	headers := []string{
		"POST /api HTTP/1.1",
		"Content-Type: application/json",
	}

	mimeType, boundary := httpmsg.ParseContentType(headers)

	fmt.Println("MIME type:", mimeType)
	fmt.Println("Has boundary:", boundary != "")

	// Output:
	// MIME type: application/json
	// Has boundary: false
}

// Example_findHeaderBodySeparator demonstrates finding where body begins
func Example_findHeaderBodySeparator() {
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBODY DATA HERE")

	bodyStart := httpmsg.FindHeaderBodySeparator(request, 0)

	if bodyStart != -1 {
		body := string(request[bodyStart:])
		fmt.Println("Body:", body)
	}

	// Output:
	// Body: BODY DATA HERE
}

// Example_lfLineEndings demonstrates handling LF-only line endings
func Example_lfLineEndings() {
	request := []byte("GET / HTTP/1.1\nHost: example.com\n\nBODY")

	bodyStart := httpmsg.FindHeaderBodySeparator(request, 0)
	headers, _, _ := httpmsg.ExtractHeaders(request, 0, bodyStart)

	fmt.Println("Headers extracted:", len(headers))

	// Output:
	// Headers extracted: 2
}

// Example_multipleHeaders demonstrates working with multiple headers
func Example_multipleHeaders() {
	headers := []string{
		"GET /api HTTP/1.1",
		"Host: api.example.com",
		"Accept: application/json",
		"Accept-Language: en-US,en;q=0.9",
		"User-Agent: CustomClient/1.0",
	}

	// Extract specific headers
	host := httpmsg.Header(headers, "Host")
	accept := httpmsg.Header(headers, "Accept")
	userAgent := httpmsg.Header(headers, "User-Agent")

	fmt.Println("Host:", host)
	fmt.Println("Accept:", accept)
	fmt.Println("User-Agent:", userAgent)

	// Output:
	// Host: api.example.com
	// Accept: application/json
	// User-Agent: CustomClient/1.0
}

// Example_headerOffsets demonstrates using header offsets for modification
func Example_headerOffsets() {
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n")

	headers, offsets, _ := httpmsg.ExtractHeaders(request, 0, len(request))

	// Find Content-Length header
	for i, header := range headers {
		if httpmsg.EqualsCaseInsensitive(header[:len("Content-Length")], "Content-Length") {
			fmt.Printf("Found at offset %d: %s\n", offsets[i], header)
		}
	}

	// Output:
	// Found at offset 35: Content-Length: 0
}

// Example_caseInsensitiveComparison demonstrates case-insensitive string comparison
func Example_caseInsensitiveComparison() {
	result1 := httpmsg.EqualsCaseInsensitive("Content-Type", "content-type")
	result2 := httpmsg.EqualsCaseInsensitive("Host", "HOST")
	result3 := httpmsg.EqualsCaseInsensitive("Accept", "Reject")

	fmt.Println("Content-Type == content-type:", result1)
	fmt.Println("Host == HOST:", result2)
	fmt.Println("Accept == Reject:", result3)

	// Output:
	// Content-Type == content-type: true
	// Host == HOST: true
	// Accept == Reject: false
}
