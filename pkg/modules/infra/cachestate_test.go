package infra

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// getter returns a case-exact header getter backed by m (sufficient for these
// tests, which use the canonical names CacheState queries).
func getter(m map[string]string) func(string) string {
	return func(name string) string { return m[name] }
}

func TestCacheState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		headers   map[string]string
		wantHit   bool
		wantLayer bool
		wantAge   int
	}{
		{"empty", map[string]string{}, false, false, -1},
		{"x-cache hit", map[string]string{"X-Cache": "HIT"}, true, true, -1},
		{"x-cache miss", map[string]string{"X-Cache": "MISS"}, false, true, -1},
		{"cf hit", map[string]string{"CF-Cache-Status": "HIT"}, true, true, -1},
		{"age positive", map[string]string{"Age": "42"}, true, true, 42},
		{"age zero", map[string]string{"Age": "0"}, false, true, 0},
		{"via only is a layer, not a hit", map[string]string{"Via": "1.1 vegur"}, false, true, -1},
		{"no cache headers", map[string]string{"Content-Type": "text/html"}, false, false, -1},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := CacheState(getter(tt.headers))
			assert.Equal(t, tt.wantHit, got.Hit, "Hit")
			assert.Equal(t, tt.wantLayer, got.Layer, "Layer")
			assert.Equal(t, tt.wantAge, got.Age, "Age")
		})
	}

	assert.Equal(t, CacheInfo{Age: -1}, CacheState(nil), "nil getter is safe")
}

func respFromRaw(rawResp string) *httpmsg.HttpResponse {
	return httpmsg.NewHttpResponse([]byte(rawResp))
}

func TestRQPAmplification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{
			name: "http1.1 keep-alive behind cache layer",
			raw:  "HTTP/1.1 200 OK\r\nX-Cache: MISS\r\nContent-Type: text/html\r\n\r\nhi",
			want: true,
		},
		{
			name: "http1.1 keep-alive behind proxy server",
			raw:  "HTTP/1.1 200 OK\r\nServer: cloudflare\r\n\r\nhi",
			want: true,
		},
		{
			name: "http2 excluded",
			raw:  "HTTP/2.0 200 OK\r\nX-Cache: MISS\r\nServer: cloudflare\r\n\r\nhi",
			want: false,
		},
		{
			name: "connection close excluded",
			raw:  "HTTP/1.1 200 OK\r\nConnection: close\r\nX-Cache: MISS\r\n\r\nhi",
			want: false,
		},
		{
			name: "no proxy layer excluded",
			raw:  "HTTP/1.1 200 OK\r\nServer: gunicorn\r\nContent-Type: text/html\r\n\r\nhi",
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ev := RQPAmplification(respFromRaw(tt.raw))
			assert.Equal(t, tt.want, got)
			if got {
				assert.NotEmpty(t, ev, "amplified findings carry evidence")
			}
		})
	}

	got, _ := RQPAmplification(nil)
	assert.False(t, got, "nil response is safe")
}
