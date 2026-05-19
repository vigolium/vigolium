package httpmsg_test

import (
	"fmt"
	"sort"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// Example demonstrating analyzing a simple GET request
func Example_analyzeRequest_GET() {
	request := []byte("GET /api/users?id=123&name=john HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"User-Agent: TestClient/1.0\r\n" +
		"\r\n")

	info, err := httpmsg.AnalyzeRequest(request)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Method: %s\n", info.Method)
	fmt.Printf("URL: %s\n", info.URL)
	fmt.Printf("HTTP Version: %d\n", info.HTTPVersion)
	fmt.Printf("Headers: %d\n", len(info.Headers))

	// Extract URL parameters
	urlParams := info.ParametersByType(httpmsg.ParamURL)
	fmt.Printf("URL Parameters: %d\n", len(urlParams))
	for _, param := range urlParams {
		fmt.Printf("  %s=%s\n", param.Name(), param.Value())
	}

	// Output:
	// Method: GET
	// URL: /api/users?id=123&name=john
	// HTTP Version: 11
	// Headers: 3
	// URL Parameters: 2
	//   id=123
	//   name=john
}

// Example demonstrating analyzing a POST request with URL-encoded body
func Example_analyzeRequest_POST() {
	request := []byte("POST /api/login HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"\r\n" +
		"username=admin&password=secret123")

	info, err := httpmsg.AnalyzeRequest(request)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Method: %s\n", info.Method)
	fmt.Printf("URL: %s\n", info.URL)
	fmt.Printf("Content-Type: %d\n", info.ContentType)
	fmt.Printf("Has Body: %t\n", info.HasBody)

	// Extract body parameters
	bodyParams := info.ParametersByType(httpmsg.ParamBody)
	fmt.Printf("Body Parameters: %d\n", len(bodyParams))
	for _, param := range bodyParams {
		fmt.Printf("  %s=%s\n", param.Name(), param.Value())
	}

	// Output:
	// Method: POST
	// URL: /api/login
	// Content-Type: 1
	// Has Body: true
	// Body Parameters: 2
	//   username=admin
	//   password=secret123
}

// Example demonstrating analyzing a POST request with JSON body
func Example_analyzeRequest_JSON() {
	request := []byte("POST /api/users HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"name":"Alice","age":30,"active":true}`)

	info, err := httpmsg.AnalyzeRequest(request)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Method: %s\n", info.Method)
	fmt.Printf("Content-Type: %d\n", info.ContentType)

	// Extract JSON parameters
	jsonParams := info.ParametersByType(httpmsg.ParamJSON)
	fmt.Printf("JSON Parameters: %d\n", len(jsonParams))

	// Sort parameters by name for consistent output
	sort.Slice(jsonParams, func(i, j int) bool {
		return jsonParams[i].Name() < jsonParams[j].Name()
	})

	for _, param := range jsonParams {
		fmt.Printf("  %s=%s\n", param.Name(), param.Value())
	}

	// Output:
	// Method: POST
	// Content-Type: 4
	// JSON Parameters: 3
	//   active=true
	//   age=30
	//   name=Alice
}

// Example demonstrating analyzing a request with cookies
func Example_analyzeRequest_WithCookies() {
	request := []byte("GET /api/profile HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"Cookie: session_id=abc123xyz; user_id=456; preferences=dark_mode\r\n" +
		"\r\n")

	info, err := httpmsg.AnalyzeRequest(request)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Method: %s\n", info.Method)
	fmt.Printf("URL: %s\n", info.URL)

	// Extract cookie parameters
	cookieParams := info.ParametersByType(httpmsg.ParamCookie)
	fmt.Printf("Cookie Parameters: %d\n", len(cookieParams))
	for _, param := range cookieParams {
		fmt.Printf("  %s=%s\n", param.Name(), param.Value())
	}

	// Output:
	// Method: GET
	// URL: /api/profile
	// Cookie Parameters: 3
	//   session_id=abc123xyz
	//   user_id=456
	//   preferences=dark_mode
}

// Example demonstrating analyzing a complex request with multiple parameter types
func Example_analyzeRequest_Combined() {
	request := []byte("POST /api/search?category=books&limit=10 HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"Cookie: session=xyz789; lang=en\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"query":"golang","sort":"relevance"}`)

	info, err := httpmsg.AnalyzeRequest(request)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Method: %s\n", info.Method)
	fmt.Printf("URL: %s\n", info.URL)
	fmt.Printf("Total Parameters: %d\n", len(info.Parameters))

	// Extract different parameter types
	urlParams := info.ParametersByType(httpmsg.ParamURL)
	cookieParams := info.ParametersByType(httpmsg.ParamCookie)
	jsonParams := info.ParametersByType(httpmsg.ParamJSON)

	fmt.Printf("\nURL Parameters (%d):\n", len(urlParams))
	for _, param := range urlParams {
		fmt.Printf("  %s=%s\n", param.Name(), param.Value())
	}

	fmt.Printf("\nCookie Parameters (%d):\n", len(cookieParams))
	for _, param := range cookieParams {
		fmt.Printf("  %s=%s\n", param.Name(), param.Value())
	}

	// Sort JSON parameters by name for consistent output
	sort.Slice(jsonParams, func(i, j int) bool {
		return jsonParams[i].Name() < jsonParams[j].Name()
	})

	fmt.Printf("\nJSON Parameters (%d):\n", len(jsonParams))
	for _, param := range jsonParams {
		fmt.Printf("  %s=%s\n", param.Name(), param.Value())
	}

	// Output:
	// Method: POST
	// URL: /api/search?category=books&limit=10
	// Total Parameters: 8
	//
	// URL Parameters (2):
	//   category=books
	//   limit=10
	//
	// Cookie Parameters (2):
	//   session=xyz789
	//   lang=en
	//
	// JSON Parameters (2):
	//   query=golang
	//   sort=relevance
}

// Example demonstrating using RequestInfo helper methods
func Example_analyzeRequest_HelperMethods() {
	request := []byte("POST /api/update?id=123 HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"Cookie: session=abc123\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"status":"active"}`)

	info, err := httpmsg.AnalyzeRequest(request)
	if err != nil {
		panic(err)
	}

	// Using GetHeader method
	host := info.Header("Host")
	fmt.Printf("Host: %s\n", host)

	contentType := info.Header("Content-Type")
	fmt.Printf("Content-Type: %s\n", contentType)

	// Using GetParameter method
	idParam := info.Parameter("id")
	if idParam != nil {
		fmt.Printf("ID Parameter: %s=%s (type: %d)\n", idParam.Name(), idParam.Value(), idParam.Type())
	}

	// Using HasParameter method
	hasSession := info.HasParameter("session")
	fmt.Printf("Has session cookie: %t\n", hasSession)

	hasPassword := info.HasParameter("password")
	fmt.Printf("Has password param: %t\n", hasPassword)

	// Output:
	// Host: api.example.com
	// Content-Type: application/json
	// ID Parameter: id=123 (type: 0)
	// Has session cookie: true
	// Has password param: false
}

// Example demonstrating accessing parameter byte offsets
func Example_analyzeRequest_ParameterOffsets() {
	request := []byte("POST /api HTTP/1.1\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"\r\n" +
		"username=alice&password=secret")

	info, err := httpmsg.AnalyzeRequest(request)
	if err != nil {
		panic(err)
	}

	bodyParams := info.ParametersByType(httpmsg.ParamBody)
	for _, param := range bodyParams {
		fmt.Printf("Parameter: %s\n", param.Name())
		fmt.Printf("  Name offsets: [%d:%d]\n", param.NameStart(), param.NameEnd())
		fmt.Printf("  Value offsets: [%d:%d]\n", param.ValueStart(), param.ValueEnd())
		fmt.Printf("  Actual name bytes: %s\n", string(request[param.NameStart():param.NameEnd()]))
		fmt.Printf("  Actual value bytes: %s\n", string(request[param.ValueStart():param.ValueEnd()]))
	}

	// Output:
	// Parameter: username
	//   Name offsets: [71:79]
	//   Value offsets: [80:85]
	//   Actual name bytes: username
	//   Actual value bytes: alice
	// Parameter: password
	//   Name offsets: [86:94]
	//   Value offsets: [95:101]
	//   Actual name bytes: password
	//   Actual value bytes: secret
}

// Example demonstrating HTTP version detection
func Example_analyzeRequest_HTTPVersions() {
	requests := [][]byte{
		[]byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"),
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		[]byte("GET / HTTP/2.0\r\nHost: example.com\r\n\r\n"),
		[]byte("GET / HTTP/2\r\nHost: example.com\r\n\r\n"),
	}

	for _, req := range requests {
		info, err := httpmsg.AnalyzeRequest(req)
		if err != nil {
			continue
		}
		fmt.Printf("Request line: %s → HTTP Version: %d\n", info.Headers[0], info.HTTPVersion)
	}

	// Output:
	// Request line: GET / HTTP/1.0 → HTTP Version: 10
	// Request line: GET / HTTP/1.1 → HTTP Version: 11
	// Request line: GET / HTTP/2.0 → HTTP Version: 20
	// Request line: GET / HTTP/2 → HTTP Version: 20
}

// Example demonstrating handling requests without body
func Example_analyzeRequest_EmptyBody() {
	request := []byte("GET /api/status HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"\r\n")

	info, err := httpmsg.AnalyzeRequest(request)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Method: %s\n", info.Method)
	fmt.Printf("Has Body: %t\n", info.HasBody)
	fmt.Printf("Body Offset: %d\n", info.BodyOffset)
	fmt.Printf("Request Length: %d\n", len(request))
	fmt.Printf("Parameters: %d\n", len(info.Parameters))

	// Output:
	// Method: GET
	// Has Body: false
	// Body Offset: 51
	// Request Length: 51
	// Parameters: 2
}
