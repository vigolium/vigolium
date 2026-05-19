package httpmsg_test

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// ExampleParseURL demonstrates parsing an absolute HTTP URL with all components
func ExampleParseURL() {
	url := []byte("http://example.com:8080/api/users?id=123&page=1#results")

	parsed, err := httpmsg.ParseURL(url)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Protocol: %s\n", parsed.Protocol)
	fmt.Printf("Host: %s\n", parsed.Host)
	fmt.Printf("Port: %d\n", parsed.Port)
	fmt.Printf("Path: %s\n", parsed.Path)
	fmt.Printf("Query: %s\n", parsed.Query)
	fmt.Printf("Fragment: %s\n", parsed.Fragment)

	// Output:
	// Protocol: http
	// Host: example.com
	// Port: 8080
	// Path: /api/users
	// Query: id=123&page=1
	// Fragment: results
}

// ExampleParseURL_httpsDefaultPort demonstrates HTTPS URL with default port
func ExampleParseURL_httpsDefaultPort() {
	url := []byte("https://secure.example.com/login")

	parsed, err := httpmsg.ParseURL(url)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Protocol: %s\n", parsed.Protocol)
	fmt.Printf("Host: %s\n", parsed.Host)
	fmt.Printf("Port: %d\n", parsed.Port)
	fmt.Printf("Path: %s\n", parsed.Path)

	// Output:
	// Protocol: https
	// Host: secure.example.com
	// Port: 443
	// Path: /login
}

// ExampleParseURL_ipAddress demonstrates parsing URL with IP address
func ExampleParseURL_ipAddress() {
	url := []byte("http://192.168.1.1:3000/admin")

	parsed, err := httpmsg.ParseURL(url)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Host: %s\n", parsed.Host)
	fmt.Printf("Port: %d\n", parsed.Port)
	fmt.Printf("Path: %s\n", parsed.Path)

	// Output:
	// Host: 192.168.1.1
	// Port: 3000
	// Path: /admin
}

// ExampleParseURL_relativePath demonstrates parsing relative URL
func ExampleParseURL_relativePath() {
	url := []byte("/api/search?q=test&limit=10")

	parsed, err := httpmsg.ParseURL(url)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Protocol: %q (empty for relative)\n", parsed.Protocol)
	fmt.Printf("Path: %s\n", parsed.Path)
	fmt.Printf("Query: %s\n", parsed.Query)

	// Output:
	// Protocol: "" (empty for relative)
	// Path: /api/search
	// Query: q=test&limit=10
}

// ExampleExtractURLFromRequest demonstrates extracting URL from HTTP request
func ExampleExtractURLFromRequest() {
	request := []byte("GET /api/users?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n")

	urlBytes, start, end, err := httpmsg.ExtractURLFromRequest(request)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("URL: %s\n", string(urlBytes))
	fmt.Printf("Start: %d\n", start)
	fmt.Printf("End: %d\n", end)

	// Output:
	// URL: /api/users?id=123
	// Start: 4
	// End: 21
}

// ExampleExtractURLFromRequest_post demonstrates POST request URL extraction
func ExampleExtractURLFromRequest_post() {
	request := []byte("POST /api/create HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n{}")

	urlBytes, _, _, err := httpmsg.ExtractURLFromRequest(request)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("URL: %s\n", string(urlBytes))

	// Output:
	// URL: /api/create
}

// ExampleParsedURL_String demonstrates reconstructing a full URL
func ExampleParsedURL_String() {
	url := []byte("http://example.com:8080/path?query=1#section")

	parsed, err := httpmsg.ParseURL(url)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Reconstruct full URL
	fullURL := parsed.String()
	fmt.Printf("Full URL: %s\n", fullURL)

	// Output:
	// Full URL: http://example.com:8080/path?query=1#section
}

// ExampleParsedURL_PathWithQuery demonstrates getting path with query string
func ExampleParsedURL_PathWithQuery() {
	url := []byte("http://example.com/search?q=golang&page=2")

	parsed, err := httpmsg.ParseURL(url)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Get path with query string
	pathWithQuery := parsed.PathWithQuery()
	fmt.Printf("Path with query: %s\n", pathWithQuery)

	// Output:
	// Path with query: /search?q=golang&page=2
}

// ExampleFindQueryStringBounds demonstrates finding query string boundaries
func ExampleFindQueryStringBounds() {
	path := []byte("/api/users?id=123&status=active#results")

	start, end := httpmsg.FindQueryStringBounds(path)

	fmt.Printf("Query starts at: %d\n", start)
	fmt.Printf("Query ends at: %d\n", end)
	fmt.Printf("Query string: %s\n", string(path[start+1:end]))

	// Output:
	// Query starts at: 10
	// Query ends at: 31
	// Query string: id=123&status=active
}

// ExampleIsAbsoluteURL demonstrates checking if URL is absolute
func ExampleIsAbsoluteURL() {
	absoluteURL := []byte("http://example.com/path")
	relativeURL := []byte("/path")

	fmt.Printf("http://example.com/path is absolute: %v\n", httpmsg.IsAbsoluteURL(absoluteURL))
	fmt.Printf("/path is absolute: %v\n", httpmsg.IsAbsoluteURL(relativeURL))

	// Output:
	// http://example.com/path is absolute: true
	// /path is absolute: false
}

// ExampleIsRelativeURL demonstrates checking if URL is relative
func ExampleIsRelativeURL() {
	absoluteURL := []byte("https://example.com/path")
	relativeURL := []byte("/api/users")

	fmt.Printf("https://example.com/path is relative: %v\n", httpmsg.IsRelativeURL(absoluteURL))
	fmt.Printf("/api/users is relative: %v\n", httpmsg.IsRelativeURL(relativeURL))

	// Output:
	// https://example.com/path is relative: false
	// /api/users is relative: true
}

// ExampleGetDefaultPort demonstrates getting default port for protocol
func ExampleGetDefaultPort() {
	fmt.Printf("HTTP default port: %d\n", httpmsg.GetDefaultPort("http"))
	fmt.Printf("HTTPS default port: %d\n", httpmsg.GetDefaultPort("https"))
	fmt.Printf("WS default port: %d\n", httpmsg.GetDefaultPort("ws"))
	fmt.Printf("WSS default port: %d\n", httpmsg.GetDefaultPort("wss"))

	// Output:
	// HTTP default port: 80
	// HTTPS default port: 443
	// WS default port: 80
	// WSS default port: 443
}

// ExampleParseURL_complexQueryString demonstrates parsing URL with complex query
func ExampleParseURL_complexQueryString() {
	url := []byte("https://api.example.com/search?q=golang+tutorial&category=web&sort=relevance&page=1")

	parsed, err := httpmsg.ParseURL(url)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Host: %s\n", parsed.Host)
	fmt.Printf("Path: %s\n", parsed.Path)
	fmt.Printf("Query: %s\n", parsed.Query)

	// Output:
	// Host: api.example.com
	// Path: /search
	// Query: q=golang+tutorial&category=web&sort=relevance&page=1
}

// ExampleParseURL_localhost demonstrates parsing localhost URL
func ExampleParseURL_localhost() {
	url := []byte("http://localhost:8080/debug/pprof")

	parsed, err := httpmsg.ParseURL(url)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Protocol: %s\n", parsed.Protocol)
	fmt.Printf("Host: %s\n", parsed.Host)
	fmt.Printf("Port: %d\n", parsed.Port)
	fmt.Printf("Path: %s\n", parsed.Path)

	// Output:
	// Protocol: http
	// Host: localhost
	// Port: 8080
	// Path: /debug/pprof
}

// ExampleParseURL_rootPath demonstrates parsing URL with root path
func ExampleParseURL_rootPath() {
	url := []byte("https://example.com/")

	parsed, err := httpmsg.ParseURL(url)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Protocol: %s\n", parsed.Protocol)
	fmt.Printf("Host: %s\n", parsed.Host)
	fmt.Printf("Port: %d\n", parsed.Port)
	fmt.Printf("Path: %s\n", parsed.Path)

	// Output:
	// Protocol: https
	// Host: example.com
	// Port: 443
	// Path: /
}

// ExampleParseURL_fragmentOnly demonstrates URL with only fragment
func ExampleParseURL_fragmentOnly() {
	url := []byte("https://example.com/docs#section-intro")

	parsed, err := httpmsg.ParseURL(url)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Path: %s\n", parsed.Path)
	fmt.Printf("Query: %q (empty)\n", parsed.Query)
	fmt.Printf("Fragment: %s\n", parsed.Fragment)

	// Output:
	// Path: /docs
	// Query: "" (empty)
	// Fragment: section-intro
}

// ExampleParseHostPort demonstrates parsing host and port
func ExampleParseHostPort() {
	hostBytes := []byte("api.example.com:8443")

	host, port := httpmsg.ParseHostPort(hostBytes)

	fmt.Printf("Host: %s\n", host)
	fmt.Printf("Port: %d\n", port)

	// Output:
	// Host: api.example.com
	// Port: 8443
}

// ExampleParseHostPort_noPort demonstrates parsing host without port
func ExampleParseHostPort_noPort() {
	hostBytes := []byte("example.com")

	host, port := httpmsg.ParseHostPort(hostBytes)

	fmt.Printf("Host: %s\n", host)
	fmt.Printf("Port: %d (not specified)\n", port)

	// Output:
	// Host: example.com
	// Port: -1 (not specified)
}
