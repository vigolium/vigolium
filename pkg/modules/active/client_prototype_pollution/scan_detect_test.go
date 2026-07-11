package client_prototype_pollution

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestScanPerRequest_StaticFlowRemainsCandidate(t *testing.T) {
	t.Parallel()
	html := `<html><script>var params={};location.search.slice(1).split('&').forEach(function(pair){var k=pair.split('=')[0];params[k]=decodeURIComponent(pair.split('=')[1])});</script></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(html))
	}))
	defer srv.Close()

	ctx := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", html)
	results, err := New().ScanPerRequest(ctx, modtest.Requester(t), nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, results[0].EvidenceGrade)
	assert.False(t, results[0].IsFinding(), "runtime prototype mutation was not observed")
}
