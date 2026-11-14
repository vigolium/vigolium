package software_version_header

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// The host is claimed only once a version header matched (MISS-19): a first
// response without one must not hide a later response that discloses it, and
// a host already reported stays reported once.
func TestScanPerRequest_ClaimsHostOnlyOnMatch(t *testing.T) {
	mgr := dedup.NewManager()
	t.Cleanup(mgr.Close)
	sc := &modkit.ScanContext{DedupManager: mgr}
	m := New()

	results, err := m.ScanPerRequest(makeHTTPCtx("Server: nginx\r\n"), sc)
	require.NoError(t, err)
	assert.Empty(t, results)

	results, err = m.ScanPerRequest(makeHTTPCtx("Server: Apache/2.4.41\r\n"), sc)
	require.NoError(t, err)
	assert.Len(t, results, 1, "a later response with a version must still be reported")

	results, err = m.ScanPerRequest(makeHTTPCtx("Server: Apache/2.4.41\r\n"), sc)
	require.NoError(t, err)
	assert.Empty(t, results, "the host is reported once")
}
