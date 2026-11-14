package aspnet_blazor_exposure

import (
	"crypto/sha256"
	"encoding/json"
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

// decoyRounds is how many same-directory/same-extension negative-control probes
// the catch-all disproof issues per candidate. A host that answers every sibling
// path with the same 200 shell (a reflecting/echo server, an SPA fallback, a
// blanket rewrite) trips at least one round and the candidate is dropped. Two
// rounds tolerate a single WAF/CDN flake without over-probing.
const decoyRounds = 2

type notFoundFingerprint struct {
	bodyHash string
	bodyLen  int
}

// Module implements the Blazor Exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Blazor Exposure module.
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
		ds: dedup.LazyDiskSet("aspnet_blazor_exposure"),
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

// ScanPerRequest probes the host for Blazor-specific exposure.
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

	// If boot manifest was found, try to extract assembly names
	if bootResult := m.probeBootManifest(ctx, httpClient); bootResult != nil {
		results = append(results, bootResult)
	}

	return results, nil
}

func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-blazor-404-" + utils.RandomString(8)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}

	// SetMethod/SetPath produce well-formed raw, so wrap directly instead of
	// re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	body := resp.Body().String()
	return &notFoundFingerprint{
		bodyHash: fmt.Sprintf("%x", sha256.Sum256([]byte(body))),
		bodyLen:  len(body),
	}
}

func (m *Module) probeEndpoint(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	p probe,
	fp *notFoundFingerprint,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, p.path)
	if err != nil {
		return nil
	}

	// SetMethod/SetPath produce well-formed raw, so wrap directly instead of
	// re-parsing on this hot path.
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
	if status == 404 || status == 500 || status == 502 || status == 503 || status == 403 || status == 401 {
		return nil
	}

	if status == 301 || status == 302 {
		location := resp.Response().Header.Get("Location")
		if strings.Contains(strings.ToLower(location), "login") || strings.Contains(strings.ToLower(location), "user") {
			return nil
		}
	}

	body := resp.Body().String()

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

	// Content-type discipline for a structured (non-document) probe. The JSON boot
	// manifest / negotiate response, the JavaScript runtimes, and the .NET WASM
	// binary are never served as an HTML *document*, so a text/html response for
	// them is a catch-all / echo shell — reject it. Truncation-proof: the
	// Content-Type header survives the gzip + bogus Content-Length:0 quirk that
	// captures only a partial body, so this holds even when weak markers ("assembly",
	// "resources", the echoed "_framework"/"blazor" path segment) survive in the
	// truncated tail after the <html> anti-marker in the head is lost. The
	// directory-listing probe serves a genuine HTML document, so it skips this and
	// relies on the decoy catch-all confirmation below.
	if !p.htmlDoc && modkit.ClassifyContentType(resp.Response().Header.Get("Content-Type")) == modkit.ContentClassHTML {
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

	// Strip the reflected request path before marker matching so a marker that is
	// merely a segment of the probe path echoed back ("_framework", "blazor" from
	// /_framework/blazor.webassembly.js) cannot self-match our OWN request. The
	// original body is retained for the stored response evidence.
	matchBody := modkit.StripReflectedProbePath(body, p.path)
	matchedMarkers, matched := p.accepts(matchBody)
	if !matched {
		return nil
	}

	// Multi-round catch-all disproof: probe several guaranteed-nonexistent siblings
	// sharing this probe's directory AND extension. If a random same-shape path
	// returns the same status and also satisfies the marker predicate, the host
	// serves this content for ANY path (a reflecting/echo server, an SPA fallback,
	// an extension-scoped catch-all) and the match proves nothing. A genuinely
	// exposed resource has no such sibling (the decoy 404s), so this costs no true
	// positives, and it survives the body-truncation quirk because the decoy is run
	// through the same marker predicate rather than a body-similarity compare.
	if modkit.MultiRoundExtDecoyCatchAll(ctx, httpClient, p.path, body, status, decoyRounds, p.markerMatch) {
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
			Name:        fmt.Sprintf("Blazor Exposure: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  severity.Firm,
			Tags:        []string{"aspnet", "blazor", "information-disclosure"},
			Reference:   []string{"https://learn.microsoft.com/en-us/aspnet/core/blazor/"},
		},
	}
}

// probeBootManifest fetches the boot manifest and extracts assembly names as
// a separate high-severity finding with detailed assembly enumeration.
func (m *Module) probeBootManifest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, "/_framework/blazor.boot.json")
	if err != nil {
		return nil
	}

	// SetMethod/SetPath produce well-formed raw, so wrap directly instead of
	// re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != 200 {
		return nil
	}

	body := resp.Body().String()

	// Parse the boot manifest to extract assembly names
	var manifest map[string]interface{}
	if err := json.Unmarshal([]byte(body), &manifest); err != nil {
		return nil
	}

	assemblies := extractAssemblyNames(manifest)
	if len(assemblies) == 0 {
		return nil
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + "/_framework/blazor.boot.json"

	extracted := []string{fmt.Sprintf("Total assemblies: %d", len(assemblies))}
	// Include up to 20 assembly names as evidence
	limit := len(assemblies)
	if limit > 20 {
		limit = 20
	}
	for _, name := range assemblies[:limit] {
		extracted = append(extracted, fmt.Sprintf("Assembly: %s", name))
	}
	if len(assemblies) > 20 {
		extracted = append(extracted, fmt.Sprintf("... and %d more", len(assemblies)-20))
	}

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        "Blazor WASM Assembly Enumeration",
			Description: fmt.Sprintf("Blazor WebAssembly boot manifest exposes %d .NET assemblies that can be downloaded and decompiled to recover application source code, secrets, and business logic", len(assemblies)),
			Severity:    severity.High,
			Confidence:  severity.Certain,
			Tags:        []string{"aspnet", "blazor", "source-disclosure", "information-disclosure"},
			Reference:   []string{"https://learn.microsoft.com/en-us/aspnet/core/blazor/host-and-deploy/webassembly"},
		},
	}
}

// extractAssemblyNames parses the Blazor boot manifest JSON to find assembly names.
func extractAssemblyNames(manifest map[string]interface{}) []string {
	var names []string

	// .NET 8+ format: resources.assembly or resources.fingerprinting
	if resources, ok := manifest["resources"].(map[string]interface{}); ok {
		for _, section := range []string{"assembly", "runtime"} {
			if assemblies, ok := resources[section].(map[string]interface{}); ok {
				for name := range assemblies {
					if strings.HasSuffix(name, ".dll") || strings.HasSuffix(name, ".wasm") {
						names = append(names, name)
					}
				}
			}
		}
		// Fingerprinting format (newer .NET)
		if fp, ok := resources["fingerprinting"].(map[string]interface{}); ok {
			for name := range fp {
				if strings.HasSuffix(name, ".dll") || strings.HasSuffix(name, ".wasm") {
					names = append(names, name)
				}
			}
		}
	}

	// Older format: assemblies directly at top level
	if assemblies, ok := manifest["assemblies"].([]interface{}); ok {
		for _, a := range assemblies {
			if name, ok := a.(string); ok {
				names = append(names, name)
			}
		}
	}

	return names
}
