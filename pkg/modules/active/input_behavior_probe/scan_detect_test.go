package input_behavior_probe

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestTagDistance(t *testing.T) {
	a := extractTagCounts("<html><body><div></div><div></div></body></html>")

	// Reordering the same tags must register zero distance — exact string
	// comparison would have flagged this.
	reordered := extractTagCounts("<div><div></div></div><body></body><html></html>")
	assert.Equal(t, 0, tagDistance(a, reordered), "reordered identical tag set must be distance 0")

	// One added <div> is distance 1.
	added := extractTagCounts("<html><body><div></div><div></div><div></div></body></html>")
	assert.Equal(t, 1, tagDistance(a, added), "one added tag must be distance 1")

	// Empty vs populated counts every tag.
	assert.Equal(t, 4, tagDistance(nil, a))
}

func TestDetectChange_JitterWithinCalibrationNotInteresting(t *testing.T) {
	base := &detectionBaseline{
		tagCounts:  extractTagCounts("<html><body><div></div></body></html>"),
		statusCode: 200,
		tagJitter:  5, // the page naturally swings by up to 5 tags per request
	}
	// Probe differs by 3 tags — within jitter+margin, so it is ambient noise.
	fuzz := "<html><body><div></div><div></div><div></div><div></div></body></html>"
	ch := detectChange(base, fuzz, 200)
	assert.False(t, ch.IsInteresting, "a tag delta within the calibrated jitter must not be interesting")
}

func TestDetectChange_StructuralBreakInteresting(t *testing.T) {
	base := &detectionBaseline{
		tagCounts:  extractTagCounts("<html><body></body></html>"),
		statusCode: 200,
		tagJitter:  1,
	}
	fuzz := "<html><body>" + strings.Repeat("<script>x</script>", 10) + "</body></html>"
	ch := detectChange(base, fuzz, 200)
	assert.True(t, ch.TagsChanged, "a 10-tag structural break well beyond jitter must register")
	assert.True(t, ch.IsInteresting)
	assert.False(t, ch.statusInteresting, "this interest is tag-driven, not status-driven")
}

func TestDetectChange_StatusTransitionStandsAlone(t *testing.T) {
	base := &detectionBaseline{
		tagCounts:  extractTagCounts("<html></html>"),
		statusCode: 200,
		tagJitter:  0,
	}
	ch := detectChange(base, "<html></html>", 500) // identical tags, 200→500
	assert.True(t, ch.IsInteresting)
	assert.True(t, ch.statusInteresting, "200→500 is an independent status signal")
}

func TestDetectChange_ProbeBlockedSuppressed(t *testing.T) {
	base := &detectionBaseline{
		tagCounts:  extractTagCounts("<html></html>"),
		statusCode: 200,
		tagJitter:  0,
	}
	// Probe blocked (200→403) with a totally different block-page body: suppressed.
	ch := detectChange(base, "<html><body>"+strings.Repeat("<div></div>", 40)+"</body></html>", 403)
	assert.False(t, ch.IsInteresting, "a probe blocked by a WAF/auth layer must be suppressed")
}

// TestScanPerRequest_DynamicBodyNoFalsePositive reproduces the reported false
// positive: a page whose body structure jitters every request (here the tag count
// alternates, standing in for rotating ads / CDN-injected challenge scripts) while
// ignoring all probe input. Exact tag-string comparison flagged every probe; the
// calibrated, jitter-tolerant comparison must now stay silent.
func TestScanPerRequest_DynamicBodyNoFalsePositive(t *testing.T) {
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Alternate the <div> count every request, independent of any header or
		// query — pure ambient variance.
		extra := 0
		if atomic.AddInt64(&n, 1)%2 == 0 {
			extra = 10
		}
		var b strings.Builder
		b.WriteString("<html><body>")
		for range 5 + extra {
			b.WriteString("<div>x</div>")
		}
		b.WriteString("</body></html>")
		_, _ = w.Write([]byte(b.String()))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a page whose body naturally jitters must not be reported as a behavior change")
}

// TestScanPerRequest_ServerErrorIsReported is the status-signal positive: a probe
// (any appended query param) drives the server to a 500, an independent signal
// that stands on its own without tag reproduction.
func TestScanPerRequest_ServerErrorIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.NotEmpty(t, res, "a probe that drives the server to a 500 must be reported")
}

// TestScanPerInsertionPoint_ReflectedStructureIsReported is the tag-signal
// positive: the server consistently injects many new tags when it reflects the
// fuzz payload, a reproducible structural break far beyond the (zero) jitter.
func TestScanPerInsertionPoint_ReflectedStructureIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("q"), "<'\"") {
			_, _ = w.Write([]byte("<html><body>" + strings.Repeat("<script>x</script>", 30) + "</body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body>clean</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.NotEmpty(t, res, "a reproducible reflected structural change must be reported")
}
