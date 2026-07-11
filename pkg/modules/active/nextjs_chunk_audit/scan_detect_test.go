package nextjs_chunk_audit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

// nextShellReferencing returns a Next.js HTML shell that references chunkPath, so
// the module's LooksLikeNextJS gate fires (the "/_next/" marker) and
// ExtractChunkPaths picks the chunk up for fetching.
func nextShellReferencing(chunkPath string) string {
	return `<html><head><script src="` + chunkPath + `"></script></head>` +
		`<body><div id="__next"></div></body></html>`
}

// TestScanPerRequest_CatchAllHTMLChunk_NoFalsePositive reproduces the catch-all /
// echo-server false positive with body truncation: the host answers a chunk path
// with a 200 text/html shell (here a truncated TAIL fragment with no leading
// <!DOCTYPE, echoing the path) that happens to carry a secret-shaped token. A real
// Next.js chunk is JavaScript, never an HTML document, so the fetched "chunk" must
// be rejected on Content-Type before secret/route analysis and yield no finding.
func TestScanPerRequest_CatchAllHTMLChunk_NoFalsePositive(t *testing.T) {
	t.Parallel()
	const chunkPath = "/_next/static/chunks/main-abc123.js"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every path (including the chunk fetch) returns a truncated HTML tail that
		// echoes the request path and embeds a secret-shaped token — the exact shape
		// a weak body scan would flag.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`app boot ` + r.URL.Path +
			` config={apiKey:"AKIAIOSFODNN7EXAMPLE"}</div></body></html>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", nextShellReferencing(chunkPath))

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a catch-all HTML shell returned for a chunk path must not forge a secret/intel finding")
}

// An AWS access-key ID identifies a principal but is not the secret access key.
// Keep it visible as an observation without calling it a leaked credential.
func TestScanPerRequest_AWSAccessKeyIDIsPublicIdentifier(t *testing.T) {
	t.Parallel()
	const chunkPath = "/_next/static/chunks/main-abc123.js"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == chunkPath {
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
			_, _ = w.Write([]byte(`(()=>{const cfg={awsKey:"AKIA1234AB` + `CD5678EFGH"};return cfg})();`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", nextShellReferencing(chunkPath))

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a client identifier should remain visible")

	var identifier *output.ResultEvent
	for _, ev := range res {
		if ev.Info.Name == "Public Client Identifier in Next.js Bundle" {
			identifier = ev
		}
	}
	require.NotNil(t, identifier)
	assert.Equal(t, output.RecordKindObservation, identifier.RecordKind)
	assert.False(t, identifier.IsFinding())
}

func TestScanPerRequest_PrivateTokenIsCandidateUntilValidated(t *testing.T) {
	t.Parallel()
	const chunkPath = "/_next/static/chunks/main-private.js"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == chunkPath {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`const token="ghp_123456` + `7890abcdef` + `ghijklmnop` + `qrstuvwxyz";`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(
		modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", nextShellReferencing(chunkPath)),
		modtest.Requester(t),
		&modkit.ScanContext{},
	)
	require.NoError(t, err)

	var candidate *output.ResultEvent
	for _, event := range res {
		if event.Info.Name == "Potential Private Credential in Next.js Bundle" {
			candidate = event
		}
	}
	require.NotNil(t, candidate)
	assert.Equal(t, output.RecordKindCandidate, candidate.RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, candidate.EvidenceGrade)
	assert.False(t, candidate.IsFinding(), "provider validity was not tested")
}
