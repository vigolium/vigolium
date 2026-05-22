package lfi_path_traversal

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// passwdBody is a realistic /etc/passwd dump carrying the module's markers
// (`root:`, `:0:0:`, `/bin/`).
const passwdBody = "root:x:0:0:root:/root:/bin/bash\n" +
	"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
	"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n" +
	"sys:x:3:3:sys:/dev:/usr/sbin/nologin\n" +
	"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"

// cleanBaseline is a marker-free baseline page, comfortably shorter than
// passwdBody so the traversal response clears the minimum body-delta gate.
const cleanBaseline = "<html><body>Welcome — choose a document to view.</body></html>"

// TestScanPerInsertionPoint_DetectsPasswd drives the real scan method against a
// server that returns passwd content on traversal. The clean baseline (attached
// as the captured response) carries none of the markers, so countNewMarkers
// counts all three as new and a finding is produced.
func TestScanPerInsertionPoint_DetectsPasswd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("file")
		if strings.Contains(v, "..") || strings.Contains(v, "etc/passwd") {
			_, _ = io.WriteString(w, passwdBody)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/?file=welcome"), "text/html", cleanBaseline)
	ip := modtest.InsertionPoint(t, rr, "file")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an LFI finding: passwd markers absent from baseline, present after traversal")
}

// TestScanPerInsertionPoint_NoMarkersNoFinding exercises the marker-count gate:
// the traversal response is long enough to clear the body-delta gate but
// contains none of the passwd markers, so countNewMarkers returns 0 and no
// finding is produced. (A delta-only test would pass even with broken marker
// logic; this one reaches countNewMarkers.)
func TestScanPerInsertionPoint_NoMarkersNoFinding(t *testing.T) {
	longNoMarkerBody := "<html><body>" + strings.Repeat("error: file not found. ", 20) + "</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, longNoMarkerBody) // long, but no root:/:0:0:/bin/ markers
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/?file=welcome"), "text/html", cleanBaseline)
	ip := modtest.InsertionPoint(t, rr, "file")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a long response without passwd markers must not yield an LFI finding")
}

// TestScanPerInsertionPoint_MarkersAlreadyInBaseline exercises the
// baseline-subtraction false-positive defense: the markers are already present
// in the captured baseline (a page that legitimately documents /etc/passwd), so
// even though the traversal response is longer (clears the delta gate) and still
// contains them, countNewMarkers subtracts the baseline occurrences and reports
// zero NEW markers — no finding.
func TestScanPerInsertionPoint_MarkersAlreadyInBaseline(t *testing.T) {
	// Baseline already contains all three markers (e.g. a docs page).
	const markerBaseline = "<html><body>The passwd format: root:x:0:0:root:/root:/bin/bash is the superuser line.</body></html>"
	// Traversal response = same marker-bearing content + >=50 bytes of padding,
	// so it clears the body-delta gate but introduces no NEW markers.
	body := markerBaseline + strings.Repeat("x", 80)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/?file=welcome"), "text/html", markerBaseline)
	ip := modtest.InsertionPoint(t, rr, "file")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "markers already present in the baseline must be subtracted, not reported as LFI")
}
