package httpmsg_test

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// ExampleParseQueryString demonstrates parsing query parameters from a URL
func ExampleParseQueryString() {
	url := []byte("http://example.com/api?name=John%20Doe&age=30&active")

	params, err := httpmsg.ParseQueryString(url)
	if err != nil {
		panic(err)
	}

	for _, p := range params {
		fmt.Printf("Name: %s, Value: %s\n", p.Name(), p.Value())
	}

	// Output:
	// Name: name, Value: John Doe
	// Name: age, Value: 30
	// Name: active, Value:
}

// ExampleParseQueryString_multipleParameters demonstrates parsing multiple parameters
func ExampleParseQueryString_multipleParameters() {
	url := []byte("http://example.com/search?q=golang&page=1&sort=desc")

	params, err := httpmsg.ParseQueryString(url)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Found %d parameters:\n", len(params))
	for i, p := range params {
		fmt.Printf("%d: %s=%s\n", i+1, p.Name(), p.Value())
	}

	// Output:
	// Found 3 parameters:
	// 1: q=golang
	// 2: page=1
	// 3: sort=desc
}

// ExampleParseQueryString_withFragment demonstrates parsing with URL fragment
func ExampleParseQueryString_withFragment() {
	url := []byte("http://example.com/page?tab=overview&section=intro#details")

	params, err := httpmsg.ParseQueryString(url)
	if err != nil {
		panic(err)
	}

	for _, p := range params {
		fmt.Printf("%s: %s\n", p.Name(), p.Value())
	}

	// Output:
	// tab: overview
	// section: intro
}

// ExampleExtractQueryParameters demonstrates extracting query params from HTTP request
func ExampleExtractQueryParameters() {
	request := []byte("GET /api/users?status=active&limit=10 HTTP/1.1\r\nHost: example.com\r\n\r\n")

	// URL is between position 4 and the space before HTTP/1.1
	// "GET /api/users?status=active&limit=10 HTTP/1.1"
	//      ^                                 ^
	//      4                                38
	params, err := httpmsg.ExtractQueryParameters(request, 4, 38)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Query parameters found: %d\n", len(params))
	for _, p := range params {
		fmt.Printf("  %s = %s (offsets: %d-%d)\n", p.Name(), p.Value(), p.NameStart(), p.ValueEnd())
	}

	// Output:
	// Query parameters found: 2
	//   status = active (offsets: 15-28)
	//   limit = 10 (offsets: 29-37)
}

// ExampleFindQueryStart demonstrates finding the query string start position
func ExampleFindQueryStart() {
	url := []byte("http://example.com/path?foo=bar&name=value")

	pos := httpmsg.FindQueryStart(url)
	if pos != -1 {
		fmt.Printf("Query string starts at position: %d\n", pos)
		fmt.Printf("Query string: %s\n", url[pos:])
	}

	// Output:
	// Query string starts at position: 23
	// Query string: ?foo=bar&name=value
}

// ExampleFindQueryEnd demonstrates finding the query string end position
// Note: FindQueryEnd is from url_parser.go
func ExampleFindQueryEnd() {
	url := []byte("http://example.com/path?foo=bar#anchor")

	start := httpmsg.FindQueryStart(url)
	// FindQueryEnd expects queryStart to be AFTER the '?', so we add 1
	end := httpmsg.FindQueryEnd(url, start+1)

	if start != -1 && end != -1 {
		fmt.Printf("Query string: %s\n", url[start+1:end])
	}

	// Output:
	// Query string: foo=bar
}

// ExampleDecodeQueryValue demonstrates URL decoding
func ExampleDecodeQueryValue() {
	// Example 1: Percent encoding
	encoded1 := "John%20Doe"
	decoded1 := httpmsg.DecodeQueryValue(encoded1)
	fmt.Printf("Decoded: %s\n", decoded1)

	// Example 2: Plus encoding
	encoded2 := "hello+world"
	decoded2 := httpmsg.DecodeQueryValue(encoded2)
	fmt.Printf("Decoded: %s\n", decoded2)

	// Example 3: Mixed encoding
	encoded3 := "search+term%3A+golang%2Bpython"
	decoded3 := httpmsg.DecodeQueryValue(encoded3)
	fmt.Printf("Decoded: %s\n", decoded3)

	// Output:
	// Decoded: John Doe
	// Decoded: hello world
	// Decoded: search term: golang+python
}

// ExampleDecodeQueryValue_specialCharacters demonstrates decoding special characters
func ExampleDecodeQueryValue_specialCharacters() {
	examples := []string{
		"hello%2Bworld",   // Plus sign
		"a%3Db%26c%3Dd",   // Equals and ampersand
		"100%25+complete", // Percent sign
	}

	for _, encoded := range examples {
		decoded := httpmsg.DecodeQueryValue(encoded)
		fmt.Printf("%s -> %s\n", encoded, decoded)
	}

	// Output:
	// hello%2Bworld -> hello+world
	// a%3Db%26c%3Dd -> a=b&c=d
	// 100%25+complete -> 100% complete
}

// ExampleEncodeQueryValue demonstrates URL encoding
func ExampleEncodeQueryValue() {
	// Example 1: Space to plus
	decoded1 := "John Doe"
	encoded1 := httpmsg.EncodeQueryValue(decoded1)
	fmt.Printf("Encoded: %s\n", encoded1)

	// Example 2: Special characters
	decoded2 := "hello+world"
	encoded2 := httpmsg.EncodeQueryValue(decoded2)
	fmt.Printf("Encoded: %s\n", encoded2)

	// Example 3: Equals and ampersand
	decoded3 := "a=b&c=d"
	encoded3 := httpmsg.EncodeQueryValue(decoded3)
	fmt.Printf("Encoded: %s\n", encoded3)

	// Output:
	// Encoded: John+Doe
	// Encoded: hello%2Bworld
	// Encoded: a%3Db%26c%3Dd
}

// ExampleEncodeQueryValue_roundTrip demonstrates encode/decode round trip
func ExampleEncodeQueryValue_roundTrip() {
	original := "Hello World & Friends!"

	// Encode
	encoded := httpmsg.EncodeQueryValue(original)
	fmt.Printf("Original: %s\n", original)
	fmt.Printf("Encoded:  %s\n", encoded)

	// Decode
	decoded := httpmsg.DecodeQueryValue(encoded)
	fmt.Printf("Decoded:  %s\n", decoded)
	fmt.Printf("Match:    %t\n", original == decoded)

	// Output:
	// Original: Hello World & Friends!
	// Encoded:  Hello+World+%26+Friends%21
	// Decoded:  Hello World & Friends!
	// Match:    true
}

// ExampleHexCharToValue demonstrates hex character conversion
func ExampleHexCharToValue() {
	chars := []byte{'0', '9', 'A', 'F', 'a', 'f', 'G'}

	for _, ch := range chars {
		value := httpmsg.HexCharToValue(ch)
		if value != -1 {
			fmt.Printf("'%c' = %d\n", ch, value)
		} else {
			fmt.Printf("'%c' = invalid\n", ch)
		}
	}

	// Output:
	// '0' = 0
	// '9' = 9
	// 'A' = 10
	// 'F' = 15
	// 'a' = 10
	// 'f' = 15
	// 'G' = invalid
}

// ExampleParseQueryString_offsets demonstrates accessing parameter offsets
func ExampleParseQueryString_offsets() {
	url := []byte("http://example.com?foo=bar&name=value")

	params, err := httpmsg.ParseQueryString(url)
	if err != nil {
		panic(err)
	}

	// Show how to extract parameter segments using offsets
	for i, p := range params {
		nameBytes := url[p.NameStart():p.NameEnd()]
		valueBytes := url[p.ValueStart():p.ValueEnd()]

		fmt.Printf("Param %d:\n", i+1)
		fmt.Printf("  Name:  %s (bytes %d-%d)\n", nameBytes, p.NameStart(), p.NameEnd())
		fmt.Printf("  Value: %s (bytes %d-%d)\n", valueBytes, p.ValueStart(), p.ValueEnd())
	}

	// Output:
	// Param 1:
	//   Name:  foo (bytes 19-22)
	//   Value: bar (bytes 23-26)
	// Param 2:
	//   Name:  name (bytes 27-31)
	//   Value: value (bytes 32-37)
}

// ExampleParseQueryString_emptyAndMissing demonstrates handling empty and missing values
func ExampleParseQueryString_emptyAndMissing() {
	url := []byte("http://example.com?key1=value1&key2=&key3&key4=")

	params, err := httpmsg.ParseQueryString(url)
	if err != nil {
		panic(err)
	}

	for _, p := range params {
		if p.Value() == "" {
			fmt.Printf("%s: (empty)\n", p.Name())
		} else {
			fmt.Printf("%s: %s\n", p.Name(), p.Value())
		}
	}

	// Output:
	// key1: value1
	// key2: (empty)
	// key3: (empty)
	// key4: (empty)
}

// ExampleParseQueryString_complex demonstrates complex real-world scenario
func ExampleParseQueryString_complex() {
	// Real-world example: search query with filters
	url := []byte("http://api.example.com/v1/search?q=golang+tutorial&category=programming&sort=date&page=1&limit=20")

	params, err := httpmsg.ParseQueryString(url)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Search API Parameters:\n")
	fmt.Printf("----------------------\n")
	for _, p := range params {
		// Decode value for display
		decodedValue := httpmsg.DecodeQueryValue(p.Value())
		fmt.Printf("%-10s: %s\n", p.Name(), decodedValue)
	}

	// Output:
	// Search API Parameters:
	// ----------------------
	// q         : golang tutorial
	// category  : programming
	// sort      : date
	// page      : 1
	// limit     : 20
}
