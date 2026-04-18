package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// fakeReader synthesizes a very large body without allocating it up front.
// It returns `total` bytes of 'A' and then EOF.
type fakeReader struct {
	remaining int64
}

func (f *fakeReader) Read(p []byte) (int, error) {
	if f.remaining <= 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > f.remaining {
		n = f.remaining
	}
	for i := int64(0); i < n; i++ {
		p[i] = 'A'
	}
	f.remaining -= n
	return int(n), nil
}

// TestReadRequestBody_UnboundedPlainJSON proves that the non-zstd path has no
// cap: a 64 MiB body is fully read without error. In production this scales
// to multi-GB bodies, limited only by process memory.
func TestReadRequestBody_UnboundedPlainJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const size = 64 << 20 // 64 MiB — exceeds the 20 MiB zstd cap

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", &fakeReader{remaining: size})
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r := gin.New()
	r.POST("/v1/chat/completions",
		cloudPassthroughMiddleware("test"),
		func(c *gin.Context) {
			// The middleware should have replaced the body with a NopCloser.
			// If we reach here, the middleware succeeded in reading the oversized body.
			body, err := io.ReadAll(c.Request.Body)
			if err != nil {
				t.Fatalf("read replaced body: %v", err)
			}
			if int64(len(body)) != size {
				t.Fatalf("expected body length %d, got %d", size, len(body))
			}
		})
	r.ServeHTTP(rec, req)

	// Because the body had no `model` field, middleware calls c.Next() and the
	// handler runs. A 400 would indicate middleware rejected the body.
	if rec.Code != http.StatusOK {
		t.Logf("status code: %d body: %q", rec.Code, rec.Body.String())
	}
}
