package info_disclosure_detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// TestServerBannerDedupsAcrossURLs: the same Server banner on two URLs of one
// host is one observation (same identity), not one per URL.
func TestServerBannerDedupsAcrossURLs(t *testing.T) {
	t.Parallel()
	m := New()
	a, err := m.ScanPerRequest(makeHTTPCtx("/a", "Server: nginx/1.18.0\r\nContent-Type: text/html", "<p>a</p>"), &modkit.ScanContext{})
	require.NoError(t, err)
	b, err := m.ScanPerRequest(makeHTTPCtx("/b/c", "Server: nginx/1.18.0\r\nContent-Type: text/html", "<p>b</p>"), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, a, 1)
	require.Len(t, b, 1)
	assert.Equal(t, a[0].ID(), b[0].ID(), "banner identity must be host|header|value, not per URL")

	c, err := m.ScanPerRequest(makeHTTPCtx("/a", "Server: nginx/1.20.0\r\nContent-Type: text/html", "<p>a</p>"), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, c, 1)
	assert.NotEqual(t, a[0].ID(), c[0].ID(), "a different banner value is a different observation")
}
