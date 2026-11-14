package php_path_info_misconfig

import (
	"crypto/sha256"
	"fmt"
	"math"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// pathInfoTest defines a test case for PATH_INFO misconfiguration.
type pathInfoTest struct {
	path string
	name string
	desc string
}

var tests = []pathInfoTest{
	{
		path: "/index.php/vigolium-pathinfo-test",
		name: "PATH_INFO on index.php",
		desc: "PATH_INFO routing active on index.php, requests with arbitrary PATH_INFO are processed instead of rejected",
	},
	{
		path: "/index.php%2Fvigolium-pathinfo-test",
		name: "Encoded slash PATH_INFO",
		desc: "Encoded slash PATH_INFO accepted on index.php, potentially bypassing path-based security rules",
	},
	{
		path: "/vigolium-nonexistent-" + "script.php/some/path",
		name: "Non-existent script with PATH_INFO",
		desc: "Non-existent PHP script with PATH_INFO returns valid response, indicating cgi.fix_pathinfo=1 routing misconfiguration",
	},
}

// notFoundFingerprint stores characteristics of a custom 404 page.
type notFoundFingerprint struct {
	status      int
	bodyHash    string
	bodyLen     int
	contentType string
}

// catchAllRounds is how many distinct random `*.php`/PATH_INFO control probes the
// blanket catch-all check issues. Multiple rounds turn a single flaky
// WAF/CDN/cache response into a majority vote, and — crucially — key the verdict
// on status alone, so it survives the gzip/Content-Length:0 body-truncation quirk
// that defeats a body-similarity compare (the acme trace.acme.com echo server,
// which returned 200 for every path but a differently-truncated body each time).
const catchAllRounds = 3

// catchAllProbe records the aggregate result of several random, definitely-non-
// existent `*.php`/PATH_INFO control probes. count200 is how many of rounds
// returned 200. A majority means the host serves a generic body for ANY script-
// shaped path (an SPA/catch-all router, a blanket rewrite, a reflecting/echo
// server), so a 200 on the real PATH_INFO tests proves nothing about
// cgi.fix_pathinfo routing. body is one representative 200 body, kept for the
// similarity-tolerant per-test compare on hosts that are not blanket catch-alls.
type catchAllProbe struct {
	rounds   int
	count200 int
	body     string
}

// blanket reports whether a majority of the control rounds returned 200 — the
// host answers every script-shaped path, so no PATH_INFO test can distinguish a
// real cgi.fix_pathinfo acceptance from the catch-all. Status-only, so it is
// robust to per-request body truncation/reflection.
func (c *catchAllProbe) blanket() bool {
	return c != nil && c.rounds > 0 && c.count200*2 > c.rounds
}

// Module implements the PHP PATH_INFO Misconfiguration active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new PHP PATH_INFO Misconfiguration module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("php_path_info_misconfig"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false to bypass default URL/media/method checks.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess returns true if the request has a response (host is live).
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

// ScanPerRequest tests the host for PHP PATH_INFO routing misconfiguration.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	// Dedup by host
	if !modkit.BeginHostProbeFor(scanCtx, httpClient, &m.ds, ctx) {
		return nil, nil
	}

	// Fingerprint 404 page
	fp := m.fingerprint404(ctx, httpClient)

	// Probe several random script-shaped paths to learn whether the host blanket-
	// serves 200 for any `*.php`/PATH_INFO URL (a catch-all that no PATH_INFO test
	// can distinguish from a real cgi.fix_pathinfo routing acceptance). When a
	// majority answer 200, the whole host is a catch-all — abandon every test.
	catchAll := m.probeCatchAll(ctx, httpClient)
	if catchAll.blanket() {
		return nil, nil
	}

	var results []*output.ResultEvent
	for _, test := range tests {
		if result := m.runTest(ctx, httpClient, test, fp, catchAll); result != nil {
			results = append(results, result)
		}
	}
	return results, nil
}

// probeCatchAll requests catchAllRounds distinct random, definitely-non-existent
// `*.php` scripts each WITH a random PATH_INFO segment, and tallies how many
// return 200. On a genuine cgi.fix_pathinfo host, a non-existent `*.php` is
// rejected (FPM "No input file specified" / 404), so a 200 across a majority of
// these controls is the signature of a host that returns a generic body for any
// script-shaped path. The first 200 body is retained as a representative for the
// similarity-tolerant per-test compare. Each round uses a fresh random path and
// NoClustering so a per-path response cache cannot alias the rounds together.
func (m *Module) probeCatchAll(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *catchAllProbe {
	baseRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return &catchAllProbe{}
	}

	res := &catchAllProbe{}
	for i := 0; i < catchAllRounds; i++ {
		randomPath := "/vigolium-pathinfo-catchall-" + utils.RandomString(8) + ".php/" + utils.RandomString(8)
		modifiedRaw, err := httpmsg.SetPath(baseRaw, randomPath)
		if err != nil {
			continue
		}
		res.rounds++

		// SetMethod/SetPath produce well-formed raw, so wrap directly instead of
		// re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())
		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoClustering: true})
		if err != nil {
			continue
		}
		if resp.Response() != nil && resp.Response().StatusCode == 200 {
			res.count200++
			if res.body == "" {
				res.body = resp.Body().String()
			}
		}
		resp.Close()
	}
	return res
}

// fingerprint404 fetches a non-existent path to learn what a 404 looks like.
func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-pathinfo-404-" + utils.RandomString(8)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}

	// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	body := resp.Body().String()
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))

	status := 0
	contentType := ""
	if resp.Response() != nil {
		status = resp.Response().StatusCode
		contentType = strings.ToLower(resp.Response().Header.Get("Content-Type"))
	}

	return &notFoundFingerprint{
		status:      status,
		bodyHash:    hash,
		bodyLen:     len(body),
		contentType: contentType,
	}
}

// baseScriptPath returns the base PHP script of a PATH_INFO test path — the
// substring up to and including the first ".php" — e.g. "/index.php" for
// "/index.php/vigolium-pathinfo-test" or "/index.php%2Fvigolium-pathinfo-test".
// Returns "" when the path carries no ".php".
func baseScriptPath(p string) string {
	idx := strings.Index(strings.ToLower(p), ".php")
	if idx < 0 {
		return ""
	}
	return p[:idx+len(".php")]
}

// runTest sends a PATH_INFO test request and validates the response.
func (m *Module) runTest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	test pathInfoTest,
	fp *notFoundFingerprint,
	catchAll *catchAllProbe,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, test.path)
	if err != nil {
		return nil
	}

	// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	status := resp.Response().StatusCode

	// Only interested in 200 responses (PATH_INFO was accepted)
	if status != 200 {
		return nil
	}

	body := resp.Body().String()

	// Check against 404 fingerprint - if it matches 404, this is not a real PATH_INFO issue
	if fp != nil {
		bodyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
		if bodyHash == fp.bodyHash {
			return nil
		}
		if fp.bodyLen > 0 {
			ratio := math.Abs(float64(len(body)-fp.bodyLen)) / float64(fp.bodyLen)
			if ratio < 0.05 {
				return nil
			}
		}
	}

	// For the non-existent script test, a 200 is a strong indicator
	// For PATH_INFO on valid scripts, we need additional confirmation
	// that the response differs from the base script response
	if !strings.Contains(test.path, "nonexistent") {
		// For valid script + PATH_INFO, skip if the response looks like an error page
		if strings.Contains(body, "404") || strings.Contains(body, "Not Found") {
			return nil
		}
	}

	// Catch-all guard: if a random non-existent `*.php`/PATH_INFO control also
	// returned 200 with a body similar to this candidate, the host serves a
	// generic body for any script-shaped path — the PATH_INFO "acceptance" is an
	// artifact of that catch-all (an SPA router, a blanket rewrite, a prefixed
	// handler), not a cgi.fix_pathinfo routing bug. Mirrors the off-by-slash
	// suffix-invariance gate; uses similarity-tolerant comparison so per-request
	// volatile content (timestamps, tokens) does not mask the match.
	if catchAll != nil && catchAll.body != "" && modkit.BodiesSimilar(catchAll.body, body) {
		return nil
	}

	// Clean-canonical (base-script) control: the PATH_INFO test path is the base
	// PHP script with a trailing PATH_INFO segment. Fetch that base script plain
	// (no PATH_INFO); if it returns 200 with a body similar to the candidate, the
	// trailing path produced no observable routing change — the script is served
	// regardless of the suffix and is already publicly reachable, so no
	// cgi.fix_pathinfo routing boundary was demonstrably crossed (a front
	// controller / Apache AcceptPathInfo serving the home page for /index.php and
	// /index.php/anything alike). This is a no-op for the non-existent-script
	// test, whose bare base script 404s, and for a genuine misconfig where the
	// PATH_INFO response diverges from the base script.
	if base := baseScriptPath(test.path); base != "" && base != test.path {
		if bStatus, bBody, ok := modkit.FetchPath(ctx, httpClient, base); ok && bStatus == 200 && modkit.BodiesSimilar(bBody, body) {
			return nil
		}
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + test.path

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: []string{test.path},
		Info: output.Info{
			Name:        fmt.Sprintf("PHP PATH_INFO Misconfiguration: %s", test.name),
			Description: test.desc,
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        []string{"php", "pathinfo", "misconfiguration"},
			Reference:   []string{"https://www.php.net/manual/en/ini.core.php#ini.cgi.fix-pathinfo"},
		},
	}
}
