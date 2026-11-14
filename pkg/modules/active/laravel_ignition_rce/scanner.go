package laravel_ignition_rce

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
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// decoyRounds is how many same-directory negative-control probes the catch-all
// disproof issues per candidate. A universal catch-all / echo host that answers
// EVERY path with the same 200 shell (often reflecting the request URI, and —
// under a gzip + bogus Content-Length: 0 transport quirk — captured as only a
// truncated TAIL fragment) trips at least one round and the candidate is dropped.
// Two rounds tolerate a single WAF/CDN flake without over-probing.
const decoyRounds = 2

type probe struct {
	path        string
	method      string
	body        string
	contentType string
	name        string
	markers     []string
	antiMarkers []string
	sev         severity.Severity
	desc        string
	refs        []string
}

// accepts reports whether body satisfies this probe's marker requirement (any
// single case-insensitive marker hit — matching the primary loop's ToLower
// compare). Centralized so the primary match and the catch-all decoy disproof
// apply the EXACT same predicate — the decoy sibling must be judged by the same
// rule the candidate was, so a truncated-tail echo / catch-all server that serves
// the marker for every path is disproved.
func (p probe) accepts(body string) (matched []string, ok bool) {
	lower := strings.ToLower(body)
	for _, marker := range p.markers {
		if strings.Contains(lower, strings.ToLower(marker)) {
			matched = append(matched, marker)
		}
	}
	return matched, len(matched) > 0
}

var probes = []probe{
	{
		path:    "/_ignition/health-check",
		method:  "GET",
		name:    "Ignition Health Check",
		markers: []string{"can_execute_commands"},
		sev:     severity.High,
		desc:    "Laravel Ignition health-check endpoint is publicly accessible, indicating debug tooling is exposed",
		refs:    []string{"https://flareapp.io/docs/ignition-for-laravel/introduction"},
	},
	{
		path:        "/_ignition/execute-solution",
		method:      "POST",
		body:        "{}",
		contentType: "application/json",
		name:        "Ignition Execute Solution",
		markers:     []string{"execute-solution", "spatie/laravel-ignition", "facade/ignition", "ignitionSolution"},
		sev:         severity.Critical,
		desc:        "Laravel Ignition execute-solution endpoint is reachable. This is a CVE-2021-3129 RCE candidate if facade/ignition < 2.5.2",
		refs:        []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-3129", "https://www.ambionics.io/blog/laravel-debug-rce"},
	},
	{
		path:        "/_ignition/scripts/0",
		method:      "GET",
		name:        "Ignition Scripts",
		markers:     []string{"ignition", "Spatie\\", "flareapp.io"},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.Medium,
		desc:        "Laravel Ignition script assets are publicly accessible, confirming debug tooling is enabled in production",
		refs:        []string{"https://flareapp.io/docs/ignition-for-laravel/introduction"},
	},
	{
		path:        "/_ignition/styles/0",
		method:      "GET",
		name:        "Ignition Styles",
		markers:     []string{"ignition", ".ignition-"},
		antiMarkers: []string{"404 Not Found"},
		sev:         severity.Medium,
		desc:        "Laravel Ignition style assets are publicly accessible, confirming debug tooling is enabled in production",
		refs:        []string{"https://flareapp.io/docs/ignition-for-laravel/introduction"},
	},
}

type notFoundFingerprint struct {
	status   int
	bodyHash string
	bodyLen  int
}

// Module implements the Laravel Ignition RCE active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Laravel Ignition RCE module.
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
		ds: dedup.LazyDiskSet("laravel_ignition_rce"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

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

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if !modkit.BeginHostProbe(scanCtx, httpClient, diskSet, host) {
		return nil, nil
	}

	fp := m.fingerprint404(ctx, httpClient)

	var results []*output.ResultEvent
	for _, p := range probes {
		if result := m.probeEndpoint(ctx, httpClient, p, fp); result != nil {
			results = append(results, result)
		}
	}
	return results, nil
}

func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-ignition-404-" + utils.RandomString(8)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}

	// modifiedRaw is internally built (well-formed), so wrap directly instead
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
	if resp.Response() != nil {
		status = resp.Response().StatusCode
	}

	return &notFoundFingerprint{
		status:   status,
		bodyHash: hash,
		bodyLen:  len(body),
	}
}

func (m *Module) probeEndpoint(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	p probe,
	fp *notFoundFingerprint,
) *output.ResultEvent {
	method := p.method
	if method == "" {
		method = "GET"
	}

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), method)
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, p.path)
	if err != nil {
		return nil
	}

	if p.contentType != "" {
		modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "Content-Type", p.contentType)
		if err != nil {
			return nil
		}
	}
	if p.body != "" {
		modifiedRaw, err = httpmsg.SetBody(modifiedRaw, []byte(p.body))
		if err != nil {
			return nil
		}
	}

	// modifiedRaw is internally built (well-formed), so wrap directly instead
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
	if status == 404 || status == 500 || status == 502 || status == 503 {
		return nil
	}

	// Skip redirects to login
	if status == 301 || status == 302 {
		location := resp.Response().Header.Get("Location")
		if strings.Contains(strings.ToLower(location), "login") {
			return nil
		}
	}

	body := resp.Body().String()

	// Check against 404 fingerprint
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

	// Catch-all / SPA shell guard: a themed app that returns the same shell for
	// any path is a false positive even when a weak marker appears in that shell.
	if modkit.ResemblesObservedPage(ctx, body) {
		return nil
	}

	for _, anti := range p.antiMarkers {
		if strings.Contains(body, anti) {
			return nil
		}
	}

	if status != 200 {
		return nil
	}

	// Strip the reflected request path (and any echoed request body) before marker
	// matching: the "ignition" / "execute-solution" markers are segments of the
	// probe path itself (/_ignition/..., /_ignition/execute-solution), so a host
	// that mirrors the requested URI back into its response — the truncated-tail
	// echo server — would otherwise self-satisfy a marker. The original body is
	// kept for anti-markers and stored evidence.
	matchBody := modkit.StripReflectedProbePath(body, p.path)
	if reqBody := ctx.Request().BodyToString(); reqBody != "" {
		matchBody = modkit.StripReflected(matchBody, reqBody)
	}

	matchedMarkers, ok := p.accepts(matchBody)
	if !ok {
		return nil
	}

	// Multi-round catch-all disproof (truncation-proof): the reflected-path strip
	// above kills an echoed-slug marker, but a universal catch-all shell that
	// carries "ignition" as a CONSTANT word for every path (surviving in the
	// truncated tail) slips past it. Probe guaranteed-nonexistent siblings sharing
	// this path's directory: if a random same-shape path returns the same status
	// and ALSO satisfies this probe's predicate, the host serves this content for
	// ANY path — a reflecting/echo server, a SPA fallback, an extension-scoped
	// catch-all — so the match proves nothing. A genuinely exposed Ignition
	// endpoint has no such sibling (the decoy 404s), so this costs no true
	// positives, and it is robust to the body-truncation quirk because the decoy is
	// run through the same predicate rather than a body-similarity compare. The
	// genuine hit here is legitimately an HTML error/stack-trace page, so a
	// content-type=HTML reject would be wrong — the decoy disproof is used instead.
	if modkit.MultiRoundExtDecoyCatchAll(ctx, httpClient, p.path, body, status, decoyRounds, func(b string) bool {
		_, sibOK := p.accepts(b)
		return sibOK
	}) {
		return nil
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + p.path

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("Laravel Ignition RCE: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  ModuleConfidence,
			Tags:        []string{"php", "laravel", "ignition", "rce", "cve-2021-3129"},
			Reference:   p.refs,
		},
	}
}
