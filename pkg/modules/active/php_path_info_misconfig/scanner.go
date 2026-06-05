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

// catchAllProbe records the response to a random, definitely-non-existent
// `*.php`/PATH_INFO control path. When the host answers it with a 200, it serves
// a generic body for any script-shaped path (an SPA/catch-all router or a
// blanket rewrite), so a 200 on the real PATH_INFO tests proves nothing about
// cgi.fix_pathinfo routing.
type catchAllProbe struct {
	is200 bool
	body  string
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

	host := service.Host()

	// Dedup by host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	// Fingerprint 404 page
	fp := m.fingerprint404(ctx, httpClient)

	// Probe a random script-shaped path to learn whether the host blanket-serves
	// 200 for any `*.php`/PATH_INFO URL (a catch-all that no PATH_INFO test can
	// distinguish from a real cgi.fix_pathinfo routing acceptance).
	catchAll := m.probeCatchAll(ctx, httpClient)

	var results []*output.ResultEvent
	for _, test := range tests {
		if result := m.runTest(ctx, httpClient, test, fp, catchAll); result != nil {
			results = append(results, result)
		}
	}
	return results, nil
}

// probeCatchAll requests a random, definitely-non-existent `*.php` script WITH a
// random PATH_INFO segment. A 200 here means the host returns a generic body for
// any script-shaped path; the captured body is later compared (similarity-
// tolerant) against each candidate to drop catch-all false positives.
func (m *Module) probeCatchAll(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *catchAllProbe {
	randomPath := "/vigolium-pathinfo-catchall-" + utils.RandomString(8) + ".php/" + utils.RandomString(8)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return &catchAllProbe{}
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return &catchAllProbe{}
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return &catchAllProbe{}
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoClustering: true})
	if err != nil {
		return &catchAllProbe{}
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != 200 {
		return &catchAllProbe{}
	}
	return &catchAllProbe{is200: true, body: resp.Body().String()}
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

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

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

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

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
	if catchAll != nil && catchAll.is200 && modkit.BodiesSimilar(catchAll.body, body) {
		return nil
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
