package xxe_generic

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// fakeOAST is a minimal modkit.OASTProvider stub: it hands out a fixed callback
// host and records the injection type and every planted payload so a test can
// assert the blind-XXE leg planted external-entity XML pointing at the OAST host.
type fakeOAST struct {
	host           string
	injectionTypes []string
	payloads       []string
}

func (f *fakeOAST) GenerateURL(_, _, injectionType, _, _ string) string {
	f.injectionTypes = append(f.injectionTypes, injectionType)
	return f.host
}
func (f *fakeOAST) RecordPayload(_, payload string) { f.payloads = append(f.payloads, payload) }
func (f *fakeOAST) Enabled() bool                   { return true }

// TestScanPerRequest_BlindXXEPlantsOASTPayloads verifies the out-of-band leg:
// with an enabled OAST provider, the module sends XML bodies carrying external
// entity/DTD references to the unique OAST host, labelled with an "xxe" injection
// type so a callback classifies as blind XXE. No in-band marker is involved.
func TestScanPerRequest_BlindXXEPlantsOASTPayloads(t *testing.T) {
	t.Parallel()

	const oastHost = "abc123nonce.oast.example"
	var (
		mu     sync.Mutex
		bodies []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(body))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<result>ok</result>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/api/orders", seedXML)
	oast := &fakeOAST{host: oastHost}

	_, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{OASTProvider: oast})
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	var planted string
	for _, b := range bodies {
		if strings.Contains(b, oastHost) && (strings.Contains(b, "<!ENTITY") || strings.Contains(b, "xi:include")) {
			planted = b
			break
		}
	}
	require.NotEmpty(t, planted, "expected an out-of-band XXE body referencing the OAST host, got %v", bodies)
	require.NotEmpty(t, oast.injectionTypes)
	for _, it := range oast.injectionTypes {
		assert.Contains(t, it, "xxe", "injection type must contain 'xxe' so callbacks classify as blind XXE")
	}
}

const seedXML = `<?xml version="1.0" encoding="UTF-8"?><order><item>1</item></order>`

// TestScanPerRequest_DetectsXXE drives the real scan method against an endpoint
// whose XML parser resolves external entities. When the injected payload
// references file:///etc/passwd, the server (simulating a vulnerable parser)
// returns the file contents, so the module observes the "root:" marker that was
// absent from the original response — confirming in-band XXE.
func TestScanPerRequest_DetectsXXE(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		if strings.Contains(string(body), "etc/passwd") {
			// Vulnerable parser expands the entity into the response.
			_, _ = w.Write([]byte("<result>root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin</result>"))
			return
		}
		_, _ = w.Write([]byte("<result>ok</result>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/api/orders", seedXML)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an XXE finding when /etc/passwd is reflected")
	// The extracted marker is now the structural passwd root line (uid:gid 0:0),
	// not a bare "root:" substring.
	assert.Contains(t, res[0].ExtractedResults[0], "root:x:0:0:")
}

// TestScanPerRequest_NotFoundShellNotXXE reproduces the false-positive class that
// motivated the status gate and the structural passwd marker: a catch-all/SPA
// 404 shell whose inline CSS carries a custom property like "--dxp-g-root:" (so a
// bare "root:" substring is present) must NOT be reported as an /etc/passwd read.
// Two independent guards suppress it — the 404 is not an error surface, and
// "--dxp-g-root:" does not match the "root:...:0:0:" passwd shape.
func TestScanPerRequest_NotFoundShellNotXXE(t *testing.T) {
	t.Parallel()
	const sfdcShell = `<!DOCTYPE html><html><head><style>:root{` +
		`--dxp-g-root:var(--lwc-dxpGRoot,#FFFFFF);` +
		`--dxp-g-root-contrast:var(--lwc-dxpGRootContrast,#4f4f4f)}` +
		`</style></head><body>Page Not Found</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html;charset=UTF-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, sfdcShell)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/api/orders", seedXML)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 404 catch-all shell containing a --dxp-g-root: CSS var must not be reported as XXE")
}

// TestScanPerRequest_ReflectedPayloadNotXXE is the struts-class reflection FP: the
// internal-entity probe carries its OWN success marker as the entity value, and an
// endpoint that rejects the XML with a 400 while ECHOING the document back would
// otherwise self-trigger a High XXE finding — even though no entity was ever
// expanded. Stripping the reflected payload before marker matching keeps it quiet.
func TestScanPerRequest_ReflectedPayloadNotXXE(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/xml")
		// 400 is an error surface (passes IsErrorSurfaceStatus) and reflects the
		// rejected document verbatim, exactly like a validation error page.
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "<error>Invalid XML document: "+string(body)+"</error>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/api/orders", seedXML)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 400 error that reflects the injected XML (marker inside the echoed payload) must not be reported as XXE")
}

// TestScanPerRequest_DetectsInternalEntityExpansion confirms the strip does not
// cause a false NEGATIVE: a parser that genuinely expands the internal entity
// emits the marker where &xxe; stood — as element content, NOT as part of the
// echoed <!ENTITY ...> definition — so it survives the payload strip and is
// correctly reported.
func TestScanPerRequest_DetectsInternalEntityExpansion(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		// Vulnerable parser expands &xxe; into the entity value and returns it as
		// element content, without echoing the raw DTD/entity definition.
		if strings.Contains(string(body), `<!ENTITY xxe "vigolium-xxe-test-entity">`) {
			_, _ = w.Write([]byte("<result>vigolium-xxe-test-entity</result>"))
			return
		}
		_, _ = w.Write([]byte("<result>ok</result>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/api/orders", seedXML)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a genuine internal-entity expansion must still be reported")
	assert.Contains(t, res[0].ExtractedResults[0], "vigolium-xxe-test-entity")
}

// TestScanPerRequest_NoFalsePositive ensures a hardened parser that never
// resolves external entities (returns a fixed benign body) yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<result>order accepted</result>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/api/orders", seedXML)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a parser that ignores external entities must not yield an XXE finding")
}

// TestCanProcess gates on XML-ish requests: XML content types, XML Accept
// headers, or XML-looking bodies are processable; plain JSON is not.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()

	xmlReq := modtest.RequestMethod(t, "POST", "http://example.com/api", seedXML)
	assert.True(t, m.CanProcess(xmlReq), "an XML body should be processable")

	jsonReq := modtest.RequestMethod(t, "POST", "http://example.com/api", `{"id":1}`)
	assert.False(t, m.CanProcess(jsonReq), "a plain JSON body should not be processable")
}
