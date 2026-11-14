package jwt_weak_secret

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// The same weak-secret token carried by requests to many URLs is reported
// once per scan (ECON-14).
func TestOneFindingPerToken(t *testing.T) {
	mgr := dedup.NewManager()
	t.Cleanup(mgr.Close)
	sc := &modkit.ScanContext{DedupManager: mgr}
	m := New()
	token := signHS256(`{"typ":"JWT","alg":"HS256"}`, `{"sub":"1234567890"}`, []byte("secret"))

	total := 0
	for i := 0; i < 3; i++ {
		raw := fmt.Sprintf("GET /api/p%d HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer %s\r\n\r\n", i, token)
		res, err := m.ScanPerRequest(modtest.RawCtx(raw, defaultResp), sc)
		require.NoError(t, err)
		total += len(res)
	}
	require.Equal(t, 1, total, "one finding for one token across three URLs")
}
