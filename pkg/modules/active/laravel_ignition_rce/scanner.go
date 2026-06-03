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

var probes = []probe{
	{
		path:    "/_ignition/health-check",
		method:  "GET",
		name:    "Ignition Health Check",
		markers: []string{"can_execute_commands", "true", "ignition"},
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
		markers:     []string{"execute-solution", "solution", "spatie", "ignition", "class"},
		sev:         severity.Critical,
		desc:        "Laravel Ignition execute-solution endpoint is reachable. This is a CVE-2021-3129 RCE candidate if facade/ignition < 2.5.2",
		refs:        []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-3129", "https://www.ambionics.io/blog/laravel-debug-rce"},
	},
	{
		path:        "/_ignition/scripts/0",
		method:      "GET",
		name:        "Ignition Scripts",
		markers:     []string{"ignition", "Spatie", "script", "function"},
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
	if diskSet != nil && diskSet.IsSeen(host) {
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

	for _, anti := range p.antiMarkers {
		if strings.Contains(body, anti) {
			return nil
		}
	}

	if status != 200 {
		return nil
	}

	matched := false
	var matchedMarkers []string
	for _, marker := range p.markers {
		if strings.Contains(strings.ToLower(body), strings.ToLower(marker)) {
			matched = true
			matchedMarkers = append(matchedMarkers, marker)
		}
	}
	if !matched {
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
