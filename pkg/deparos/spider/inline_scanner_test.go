package spider

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInlineURLScanner_Extract(t *testing.T) {
	resolver := NewURLResolver()

	scanner := NewInlineURLScanner(resolver)

	tests := []struct {
		name         string
		baseURL      string
		body         string
		expectedURLs []string
	}{
		{
			name:    "HTTP URL",
			baseURL: "https://example.com/page",
			body:    "Check out http://example.com/resource for more info",
			expectedURLs: []string{
				"http://example.com/resource",
			},
		},
		{
			name:    "HTTPS URL",
			baseURL: "https://example.com/page",
			body:    "Visit https://example.com/secure",
			expectedURLs: []string{
				"https://example.com/secure",
			},
		},
		{
			name:    "WebSocket URLs",
			baseURL: "https://example.com/page",
			body:    "Connect to ws://example.com/socket or wss://example.com/secure-socket",
			expectedURLs: []string{
				"ws://example.com/socket",
				"wss://example.com/secure-socket",
			},
		},
		{
			name:    "Multiple URLs",
			baseURL: "https://example.com/page",
			body:    "Links: https://example.com/one and http://example.com/two",
			expectedURLs: []string{
				"https://example.com/one",
				"http://example.com/two",
			},
		},
		{
			name:    "URL in JavaScript",
			baseURL: "https://example.com/page",
			body:    `var url = "https://example.com/api/endpoint";`,
			expectedURLs: []string{
				"https://example.com/api/endpoint",
			},
		},
		{
			name:    "URL in HTML",
			baseURL: "https://example.com/page",
			body:    `<a href="https://example.com/link">Click</a>`,
			expectedURLs: []string{
				"https://example.com/link",
			},
		},
		{
			name:    "URL terminated by angle bracket",
			baseURL: "https://example.com/page",
			body:    "URL: <https://example.com/resource>",
			expectedURLs: []string{
				"https://example.com/resource",
			},
		},
		{
			name:    "URL terminated by quote",
			baseURL: "https://example.com/page",
			body:    `url="https://example.com/resource"`,
			expectedURLs: []string{
				"https://example.com/resource",
			},
		},
		{
			name:    "URL terminated by single quote",
			baseURL: "https://example.com/page",
			body:    "url='https://example.com/resource'",
			expectedURLs: []string{
				"https://example.com/resource",
			},
		},
		{
			name:    "URL terminated by parenthesis",
			baseURL: "https://example.com/page",
			body:    "fetch(https://example.com/api)",
			expectedURLs: []string{
				"https://example.com/api",
			},
		},
		{
			name:    "URL terminated by bracket",
			baseURL: "https://example.com/page",
			body:    "urls[https://example.com/item]",
			expectedURLs: []string{
				"https://example.com/item",
			},
		},
		{
			name:    "URL terminated by brace",
			baseURL: "https://example.com/page",
			body:    "obj{https://example.com/key}",
			expectedURLs: []string{
				"https://example.com/key",
			},
		},
		{
			name:    "URL terminated by HTML entity &quot;",
			baseURL: "https://example.com/page",
			body:    "url=https://example.com/page&quot;",
			expectedURLs: []string{
				"https://example.com/page",
			},
		},
		{
			name:    "URL terminated by HTML entity &gt;",
			baseURL: "https://example.com/page",
			body:    "link=https://example.com/next&gt;",
			expectedURLs: []string{
				"https://example.com/next",
			},
		},
		{
			name:    "URL terminated by space",
			baseURL: "https://example.com/page",
			body:    "See https://example.com/docs for details",
			expectedURLs: []string{
				"https://example.com/docs",
			},
		},
		{
			name:    "URL terminated by newline",
			baseURL: "https://example.com/page",
			body:    "URL:\nhttps://example.com/resource\nEnd",
			expectedURLs: []string{
				"https://example.com/resource",
			},
		},
		{
			name:    "HTTPS before HTTP (longest match first)",
			baseURL: "https://example.com/page",
			body:    "Protocol: https://example.com/secure",
			expectedURLs: []string{
				"https://example.com/secure",
			},
		},
		{
			name:    "URL with query parameters (stops at &)",
			baseURL: "https://example.com/page",
			body:    "API: https://example.com/api?key=value",
			expectedURLs: []string{
				"https://example.com/api?key=value",
			},
		},
		{
			name:    "URL with fragment",
			baseURL: "https://example.com/page",
			body:    "Section: https://example.com/docs#introduction",
			expectedURLs: []string{
				"https://example.com/docs",
			},
		},
		{
			name:         "Empty body",
			baseURL:      "https://example.com/page",
			body:         "",
			expectedURLs: []string{},
		},
		{
			name:         "No URLs",
			baseURL:      "https://example.com/page",
			body:         "This is plain text with no URLs",
			expectedURLs: []string{},
		},
		{
			name:    "Out of scope URL returned (scope check happens at engine level)",
			baseURL: "https://example.com/page",
			body:    "External: https://other.com/resource",
			expectedURLs: []string{
				"https://other.com/resource",
			},
		},
		{
			name:    "Subdomain in scope",
			baseURL: "https://example.com/page",
			body:    "API: https://api.example.com/v1/endpoint",
			expectedURLs: []string{
				"https://api.example.com/v1/endpoint",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseURL, err := url.Parse(tt.baseURL)
			require.NoError(t, err)

			response := &HTTPResponse{
				URL:       baseURL,
				Body:      []byte(tt.body),
				BodyStart: 0,
			}

			discovered := []*DiscoveredLink{}
			callback := func(link *DiscoveredLink) {
				discovered = append(discovered, link)
			}

			err = scanner.Extract(context.Background(), baseURL, response, callback)
			require.NoError(t, err)

			// Validate exact count
			require.Len(t, discovered, len(tt.expectedURLs), "Unexpected number of discovered URLs")

			// Build discovered set for comparison
			discoveredSet := make(map[string]bool)
			for _, link := range discovered {
				discoveredSet[link.URL.String()] = true
				require.Equal(t, SourceInlineURL, link.SourceType)
			}

			// Validate every expected URL is present
			for _, expectedURL := range tt.expectedURLs {
				require.True(t, discoveredSet[expectedURL], "Expected URL not found: %s", expectedURL)
			}
		})
	}
}

func TestInlineURLScanner_ScanBytes(t *testing.T) {
	resolver := NewURLResolver()

	scanner := NewInlineURLScanner(resolver)

	tests := []struct {
		name        string
		baseURL     string
		data        string
		offset      int
		expectFound bool
	}{
		{
			name:        "Absolute HTTP URL",
			baseURL:     "https://example.com/page",
			data:        "http://example.com/resource",
			offset:      0,
			expectFound: true,
		},
		{
			name:        "Absolute HTTPS URL",
			baseURL:     "https://example.com/page",
			data:        "https://example.com/secure",
			offset:      0,
			expectFound: true,
		},
		{
			name:        "WebSocket URL",
			baseURL:     "https://example.com/page",
			data:        "wss://example.com/socket",
			offset:      0,
			expectFound: true,
		},
		{
			name:        "Too short (< 6 bytes)",
			baseURL:     "https://example.com/page",
			data:        "http:",
			offset:      0,
			expectFound: false,
		},
		{
			name:        "No URL",
			baseURL:     "https://example.com/page",
			data:        "plain text",
			offset:      0,
			expectFound: false,
		},
		{
			name:        "Relative path",
			baseURL:     "https://example.com/page",
			data:        "/api/endpoint",
			offset:      0,
			expectFound: true,
		},
		{
			name:        "Relative dot-slash",
			baseURL:     "https://example.com/dir/page",
			data:        "./resource",
			offset:      0,
			expectFound: true,
		},
		{
			name:        "Relative dot-dot-slash",
			baseURL:     "https://example.com/dir/page",
			data:        "../parent",
			offset:      0,
			expectFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseURL, err := url.Parse(tt.baseURL)
			require.NoError(t, err)

			found := scanner.ScanBytes(context.Background(), baseURL, []byte(tt.data), tt.offset)
			require.Equal(t, tt.expectFound, found)
		})
	}
}

func TestInlineURLScanner_FindProtocolPositions(t *testing.T) {
	scanner := NewInlineURLScanner(nil)

	tests := []struct {
		name              string
		data              string
		offset            int
		expectedPositions []int
	}{
		{
			name:              "Single HTTP",
			data:              "Visit http://example.com/",
			offset:            0,
			expectedPositions: []int{6},
		},
		{
			name:              "Single HTTPS",
			data:              "Visit https://example.com/",
			offset:            0,
			expectedPositions: []int{6},
		},
		{
			name:              "Multiple protocols",
			data:              "http://one.com/ and https://two.com/",
			offset:            0,
			expectedPositions: []int{0, 20},
		},
		{
			name:              "WebSocket protocols",
			data:              "ws://sock.com/ and wss://secure.com/",
			offset:            0,
			expectedPositions: []int{0, 19},
		},
		{
			name:              "No protocols",
			data:              "No URLs here",
			offset:            0,
			expectedPositions: []int{},
		},
		{
			name:              "Just :// without valid protocol",
			data:              "Invalid ://test",
			offset:            0,
			expectedPositions: []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			positions := scanner.findProtocolPositions([]byte(tt.data), tt.offset)
			require.Equal(t, tt.expectedPositions, positions)
		})
	}
}

func TestInlineURLScanner_FindProtocolStart(t *testing.T) {
	scanner := NewInlineURLScanner(nil)

	tests := []struct {
		name          string
		data          string
		colonSlashPos int
		expectedStart int
	}{
		{
			name:          "HTTPS protocol",
			data:          "Visit https://example.com/",
			colonSlashPos: 11,
			expectedStart: 6,
		},
		{
			name:          "HTTP protocol",
			data:          "Visit http://example.com/",
			colonSlashPos: 10,
			expectedStart: 6,
		},
		{
			name:          "WSS protocol",
			data:          "Connect wss://socket.com/",
			colonSlashPos: 11,
			expectedStart: 8,
		},
		{
			name:          "WS protocol",
			data:          "Connect ws://socket.com/",
			colonSlashPos: 10,
			expectedStart: 8,
		},
		{
			name:          "Invalid protocol",
			data:          "Invalid xyz://test",
			colonSlashPos: 11,
			expectedStart: -1,
		},
		{
			name:          "No protocol before ://",
			data:          "Just ://test",
			colonSlashPos: 5,
			expectedStart: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := scanner.findProtocolStart([]byte(tt.data), 0, tt.colonSlashPos)
			require.Equal(t, tt.expectedStart, start)
		})
	}
}

func TestInlineURLScanner_ExtractURLAt(t *testing.T) {
	scanner := NewInlineURLScanner(nil)

	tests := []struct {
		name        string
		data        string
		pos         int
		offset      int
		expectedURL string
		expectedEnd int
	}{
		{
			name:        "Simple HTTP URL",
			data:        "http://example.com/path",
			pos:         0,
			offset:      0,
			expectedURL: "http://example.com/path",
			expectedEnd: 23,
		},
		{
			name:        "URL with space terminator",
			data:        "http://example.com/path more text",
			pos:         0,
			offset:      0,
			expectedURL: "http://example.com/path",
			expectedEnd: 23,
		},
		{
			name:        "URL with quote terminator",
			data:        `url="https://example.com/api"`,
			pos:         5,
			offset:      0,
			expectedURL: "https://example.com/api",
			expectedEnd: 28,
		},
		{
			name:        "URL with angle bracket",
			data:        "<https://example.com/link>",
			pos:         1,
			offset:      0,
			expectedURL: "https://example.com/link",
			expectedEnd: 25,
		},
		{
			name:        "URL too short (< protocol + 3)",
			data:        "http://ab",
			pos:         0,
			offset:      0,
			expectedURL: "",
			expectedEnd: 9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urlStr, _, endPos := scanner.extractURLAt([]byte(tt.data), tt.pos, tt.offset)
			require.Equal(t, tt.expectedURL, urlStr)
			require.Equal(t, tt.expectedEnd, endPos)
		})
	}
}

func TestInlineURLScanner_GetProtocolLength(t *testing.T) {
	scanner := NewInlineURLScanner(nil)

	tests := []struct {
		name           string
		data           string
		pos            int
		expectedLength int
	}{
		{
			name:           "HTTPS (8 bytes)",
			data:           "https://example.com",
			pos:            0,
			expectedLength: 8,
		},
		{
			name:           "HTTP (7 bytes)",
			data:           "http://example.com",
			pos:            0,
			expectedLength: 7,
		},
		{
			name:           "WSS (6 bytes)",
			data:           "wss://socket.com",
			pos:            0,
			expectedLength: 6,
		},
		{
			name:           "WS (5 bytes)",
			data:           "ws://socket.com",
			pos:            0,
			expectedLength: 5,
		},
		{
			name:           "Unknown protocol",
			data:           "xyz://test",
			pos:            0,
			expectedLength: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			length := scanner.getProtocolLength([]byte(tt.data), tt.pos)
			require.Equal(t, tt.expectedLength, length)
		})
	}
}

func TestInlineURLScanner_IsTerminator(t *testing.T) {
	scanner := NewInlineURLScanner(nil)

	tests := []struct {
		name         string
		data         string
		pos          int
		isTerminator bool
	}{
		{
			name:         "Less-than",
			data:         "test<end",
			pos:          4,
			isTerminator: true,
		},
		{
			name:         "Greater-than",
			data:         "test>end",
			pos:          4,
			isTerminator: true,
		},
		{
			name:         "Single quote",
			data:         "test'end",
			pos:          4,
			isTerminator: true,
		},
		{
			name:         "Double quote",
			data:         `test"end`,
			pos:          4,
			isTerminator: true,
		},
		{
			name:         "Parenthesis",
			data:         "test)end",
			pos:          4,
			isTerminator: true,
		},
		{
			name:         "Bracket",
			data:         "test]end",
			pos:          4,
			isTerminator: true,
		},
		{
			name:         "Brace",
			data:         "test}end",
			pos:          4,
			isTerminator: true,
		},
		{
			name:         "Space",
			data:         "test end",
			pos:          4,
			isTerminator: true,
		},
		{
			name:         "Newline",
			data:         "test\nend",
			pos:          4,
			isTerminator: true,
		},
		{
			name:         "HTML entity &quot;",
			data:         "test&quot;end",
			pos:          4,
			isTerminator: true,
		},
		{
			name:         "HTML entity &gt;",
			data:         "test&gt;end",
			pos:          4,
			isTerminator: true,
		},
		{
			name:         "Regular character",
			data:         "testAend",
			pos:          4,
			isTerminator: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.isTerminator([]byte(tt.data), tt.pos)
			require.Equal(t, tt.isTerminator, result)
		})
	}
}

func TestInlineURLScanner_FindAbsoluteURL(t *testing.T) {
	scanner := NewInlineURLScanner(nil)

	tests := []struct {
		name        string
		data        string
		offset      int
		expectedURL string
	}{
		{
			name:        "HTTP URL",
			data:        "Visit http://example.com/page",
			offset:      0,
			expectedURL: "http://example.com/page",
		},
		{
			name:        "HTTPS URL",
			data:        "Link: https://example.com/secure",
			offset:      0,
			expectedURL: "https://example.com/secure",
		},
		{
			name:        "First of multiple URLs",
			data:        "http://one.com/ and https://two.com/",
			offset:      0,
			expectedURL: "http://one.com/",
		},
		{
			name:        "No URL",
			data:        "No URLs here",
			offset:      0,
			expectedURL: "",
		},
		{
			name:        "Too short",
			data:        "http",
			offset:      0,
			expectedURL: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urlStr, _, _ := scanner.findAbsoluteURL([]byte(tt.data), tt.offset)
			require.Equal(t, tt.expectedURL, urlStr)
		})
	}
}

func TestInlineURLScanner_FindRelativeURL(t *testing.T) {
	scanner := NewInlineURLScanner(nil)
	baseURL, _ := url.Parse("https://example.com/dir/page")

	tests := []struct {
		name        string
		data        string
		offset      int
		expectedURL string
	}{
		{
			name:        "Absolute path",
			data:        "/api/endpoint",
			offset:      0,
			expectedURL: "/api/endpoint",
		},
		{
			name:        "Relative dot-slash",
			data:        "./resource",
			offset:      0,
			expectedURL: "./resource",
		},
		{
			name:        "Relative dot-dot-slash",
			data:        "../parent",
			offset:      0,
			expectedURL: "../parent",
		},
		{
			name:        "No relative prefix",
			data:        "resource",
			offset:      0,
			expectedURL: "",
		},
		{
			name:        "Too short",
			data:        "/api",
			offset:      0,
			expectedURL: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urlStr, _, _ := scanner.findRelativeURL(baseURL, []byte(tt.data), tt.offset)
			require.Equal(t, tt.expectedURL, urlStr)
		})
	}
}

func TestInlineURLScanner_StartsWithRelativePrefix(t *testing.T) {
	scanner := NewInlineURLScanner(nil)

	tests := []struct {
		name      string
		data      string
		pos       int
		hasPrefix bool
	}{
		{
			name:      "Starts with /",
			data:      "/path/to/resource",
			pos:       0,
			hasPrefix: true,
		},
		{
			name:      "Starts with ./",
			data:      "./relative/path",
			pos:       0,
			hasPrefix: true,
		},
		{
			name:      "Starts with ../",
			data:      "../parent/path",
			pos:       0,
			hasPrefix: true,
		},
		{
			name:      "No prefix",
			data:      "resource",
			pos:       0,
			hasPrefix: false,
		},
		{
			name:      "Absolute URL",
			data:      "https://example.com/",
			pos:       0,
			hasPrefix: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.startsWithRelativePrefix([]byte(tt.data), tt.pos)
			require.Equal(t, tt.hasPrefix, result)
		})
	}
}

func TestInlineURLScanner_InferResourceType(t *testing.T) {
	scanner := NewInlineURLScanner(nil)

	tests := []struct {
		path         string
		expectedType ResourceType
	}{
		{"/image.jpg", ResourceJPEG},
		{"/photo.jpeg", ResourceJPEG},
		{"/logo.png", ResourcePNG},
		{"/icon.gif", ResourceGIF},
		{"/bitmap.bmp", ResourceBMP},
		{"/image.tiff", ResourceTIFF},
		{"/script.js", ResourceScript},
		{"/page.html", ResourceHTML},
		{"/index.htm", ResourceHTML},
		{"/song.mp3", ResourceAudio},
		{"/sound.wav", ResourceAudio},
		{"/audio.ogg", ResourceAudio},
		{"/video.mp4", ResourceVideo},
		{"/movie.avi", ResourceVideo},
		{"/clip.mov", ResourceVideo},
		{"/unknown.xyz", ResourceUnknown},
		{"/path", ResourceUnknown},
		{"/", ResourceUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			resourceType := scanner.inferResourceType(tt.path)
			require.Equal(t, tt.expectedType, resourceType)
		})
	}
}

func BenchmarkInlineURLScanner_Extract(b *testing.B) {
	resolver := NewURLResolver()
	scanner := NewInlineURLScanner(resolver)

	baseURL, _ := url.Parse("https://example.com/page")
	body := []byte(`
		This is a sample page with multiple URLs:
		https://example.com/resource1
		http://example.com/resource2
		Visit https://example.com/docs for more information.
		API endpoint: https://example.com/api/v1/endpoint
	`)

	response := &HTTPResponse{
		URL:       baseURL,
		Body:      body,
		BodyStart: 0,
	}

	callback := func(link *DiscoveredLink) {
		// No-op
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = scanner.Extract(context.Background(), baseURL, response, callback)
	}
}

func BenchmarkInlineURLScanner_ScanBytes(b *testing.B) {
	resolver := NewURLResolver()
	scanner := NewInlineURLScanner(resolver)

	baseURL, _ := url.Parse("https://example.com/page")
	data := []byte("https://example.com/resource")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = scanner.ScanBytes(context.Background(), baseURL, data, 0)
	}
}
