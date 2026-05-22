package infra

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// makeCtx builds an HttpRequestResponse for the given method and path so the
// filter predicate can be exercised against realistic request shapes.
func makeCtx(t *testing.T, method, path string) *httpmsg.HttpRequestResponse {
	t.Helper()
	raw := []byte(fmt.Sprintf("%s %s HTTP/1.1\r\nHost: example.com\r\n\r\n", method, path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		raw,
	)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"))
	ctx := httpmsg.NewHttpRequestResponse(req, resp)
	return ctx
}

func TestIsValidForInjectionVulns(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		want   bool
	}{
		{"plain GET endpoint", "GET", "/api/users", true},
		{"query path with dynamic param", "GET", "/search?q=test", true},
		{"POST endpoint", "POST", "/login", true},
		{"PUT endpoint", "PUT", "/items/1", true},
		{"path with no extension", "GET", "/products/42", true},
		{"OPTIONS method rejected", "OPTIONS", "/api/users", false},
		{"CONNECT method rejected", "CONNECT", "/api/users", false},
		{"static js file rejected", "GET", "/assets/app.js", false},
		{"css file rejected", "GET", "/styles/main.css", false},
		{"png image rejected", "GET", "/images/logo.png", false},
		{"jpg image rejected", "GET", "/photo.jpg", false},
		{"woff font rejected", "GET", "/fonts/icon.woff", false},
		{"svg rejected", "GET", "/icon.svg", false},
		{"pdf rejected", "GET", "/doc.pdf", false},
		{"json file rejected", "GET", "/data.json", false},
		{"zip archive rejected", "GET", "/archive.zip", false},
		{"media URL with OPTIONS still rejected", "OPTIONS", "/icon.svg", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := makeCtx(t, tc.method, tc.path)
			urlx, err := ctx.URL()
			require.NoError(t, err)

			got := IsValidForInjectionVulns(urlx, ctx)
			require.Equal(t, tc.want, got)
		})
	}
}
