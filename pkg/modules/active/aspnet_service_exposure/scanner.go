package aspnet_service_exposure

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
// disproof issues per candidate. A host that answers every /<dir>/<anything> with
// the same 200 page (a reflecting/echo server, an SPA fallback, a blanket rewrite)
// trips at least one round and the candidate is dropped. Two rounds tolerate a
// single WAF/CDN flake without over-probing.
const decoyRounds = 2

type notFoundFingerprint struct {
	bodyHash string
	bodyLen  int
}

type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

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
		ds: dedup.LazyDiskSet("aspnet_service_exposure"),
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

	// Probe common service paths
	for _, p := range commonProbes {
		if result := m.probeEndpoint(ctx, httpClient, p, fp); result != nil {
			results = append(results, result)
		}
	}

	// Traffic-aware: check if the original request URL is an .asmx or .svc endpoint
	urlx, err := ctx.URL()
	if err != nil {
		return results, nil
	}
	path := urlx.Path

	if strings.HasSuffix(strings.ToLower(path), ".asmx") {
		// Probe WSDL for ASMX
		if result := m.probeServiceDiscovery(ctx, httpClient, path+"?WSDL", "ASMX WSDL", wsdlMarkers, fp); result != nil {
			results = append(results, result)
		}
		// Probe disco for ASMX
		if result := m.probeServiceDiscovery(ctx, httpClient, path+"?disco", "ASMX Discovery", discoMarkers, fp); result != nil {
			results = append(results, result)
		}
	}

	if strings.HasSuffix(strings.ToLower(path), ".svc") {
		// Probe WSDL for WCF
		if result := m.probeServiceDiscovery(ctx, httpClient, path+"?wsdl", "WCF WSDL", wsdlMarkers, fp); result != nil {
			results = append(results, result)
		}
		// Probe WCF detailed faults
		if result := m.probeWCFDetailedFaults(ctx, httpClient, path); result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-svc-404-" + utils.RandomString(8) + ".asmx"

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}

	// SetMethod/SetPath produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
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

	// SetMethod/SetPath produce well-formed raw, so wrap directly instead
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
	if status == 404 || status == 500 || status == 502 || status == 503 || status == 403 || status == 401 {
		return nil
	}

	if status == 301 || status == 302 {
		location := resp.Response().Header.Get("Location")
		if strings.Contains(strings.ToLower(location), "login") || strings.Contains(strings.ToLower(location), "user") {
			return nil
		}
	}

	// Content-type discipline (survives the body-truncation FP — the header is
	// intact when a gzip/Content-Length:0 quirk leaves only a partial body tail): an
	// OData $metadata probe targets an XML document never served as an HTML *page*.
	// A reflecting/catch-all host that answers arbitrary paths with its themed
	// text/html shell would otherwise forge a match on a weak marker ("EntityType")
	// surviving in that tail; rejecting an HTML document for an XML probe costs no
	// true positives.
	if p.structured && modkit.ClassifyContentType(resp.Response().Header.Get("Content-Type")) == modkit.ContentClassHTML {
		return nil
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

	for _, anti := range p.antiMarkers {
		if strings.Contains(body, anti) {
			return nil
		}
	}

	if status != 200 {
		return nil
	}

	// Strip the reflected request path before marker matching: a catch-all/echo host
	// that mirrors the requested path into its response would otherwise let a marker
	// that is itself a path segment satisfy the check. The original body is kept for
	// anti-markers and stored evidence.
	matchBody := modkit.StripReflectedProbePath(body, p.path)

	matchedMarkers, ok := p.accepts(matchBody)
	if !ok {
		return nil
	}

	// Multi-round catch-all disproof: probe several guaranteed-nonexistent siblings
	// under this probe's parent directory. If a random sibling returns the same
	// status and also satisfies the marker predicate, the host serves this content
	// for any path — a reflecting/echo server or a wildcard rewrite — so a weak
	// directory-listing word ("Index of", ".asmx") in the shell proves nothing. A
	// genuinely exposed directory has no such sibling (the decoy 404s), so this
	// costs no true positives, and it is robust to the body-truncation quirk because
	// the decoy is run through the same predicate, not a body-similarity compare.
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
			Name:        fmt.Sprintf("ASP.NET Service Exposed: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  severity.Firm,
			Tags:        []string{"aspnet", "service-exposure", "information-disclosure"},
			Reference:   []string{"https://learn.microsoft.com/en-us/dotnet/framework/wcf/"},
		},
	}
}

func (m *Module) probeServiceDiscovery(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path string,
	name string,
	markers []string,
	fp *notFoundFingerprint,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, path)
	if err != nil {
		return nil
	}

	// SetMethod/SetPath produce well-formed raw, so wrap directly instead
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
	if status != 200 {
		return nil
	}

	// Content-type discipline (survives the body-truncation FP): a WSDL / discovery
	// document is XML, never an HTML *document*. A reflecting/catch-all host that
	// answers arbitrary paths with its themed text/html shell is rejected here even
	// when the shell tail happens to carry a "<definitions" substring; a real WSDL
	// never comes back as text/html.
	if modkit.ClassifyContentType(resp.Response().Header.Get("Content-Type")) == modkit.ContentClassHTML {
		return nil
	}

	body := resp.Body().String()

	if fp != nil {
		bodyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
		if bodyHash == fp.bodyHash {
			return nil
		}
	}

	// Catch-all / SPA shell guard: a themed app that returns the same shell for
	// any path is a false positive even when a weak marker appears in that shell.
	if modkit.ResemblesObservedPage(ctx, body) {
		return nil
	}

	// Strip the reflected request path (the WSDL/disco query is appended to the seed
	// path) before marker matching so a catch-all/echo host that mirrors it back
	// cannot self-satisfy the check.
	matchBody := modkit.StripReflectedProbePath(body, path)

	var matchedMarkers []string
	for _, marker := range markers {
		if strings.Contains(matchBody, marker) {
			matchedMarkers = append(matchedMarkers, marker)
		}
	}
	if len(matchedMarkers) == 0 {
		return nil
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + path

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("ASP.NET %s Disclosed", name),
			Description: fmt.Sprintf("The %s endpoint discloses service definition, revealing available operations, data types, and endpoints.", name),
			Severity:    severity.Medium,
			Confidence:  severity.Firm,
			Tags:        []string{"aspnet", "wsdl", "service-exposure", "information-disclosure"},
			Reference:   []string{"https://learn.microsoft.com/en-us/dotnet/framework/wcf/"},
		},
	}
}

func (m *Module) probeWCFDetailedFaults(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	svcPath string,
) *output.ResultEvent {
	// Send a malformed SOAP request to trigger verbose error
	soapBody := `<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><INVALID/></soap:Body></soap:Envelope>`

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "POST")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, svcPath)
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetBody(modifiedRaw, []byte(soapBody))
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "Content-Type", "text/xml; charset=utf-8")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "SOAPAction", `""`)
	if err != nil {
		return nil
	}

	// SetMethod/SetPath/SetBody produce well-formed raw, so wrap directly
	// instead of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	body := resp.Body().String()

	var matchedMarkers []string
	for _, marker := range wcfFaultMarkers {
		if strings.Contains(body, marker) {
			matchedMarkers = append(matchedMarkers, marker)
		}
	}
	if len(matchedMarkers) == 0 {
		return nil
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + svcPath

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        "WCF Detailed Fault Disclosure",
			Description: "The WCF service returns detailed exception information including stack traces, indicating includeExceptionDetailInFaults is enabled. This reveals internal implementation details.",
			Severity:    severity.Medium,
			Confidence:  severity.Firm,
			Tags:        []string{"aspnet", "wcf", "verbose-error", "information-disclosure"},
			Reference:   []string{"https://learn.microsoft.com/en-us/dotnet/framework/wcf/feature-details/specifying-and-handling-faults-in-contracts-and-services"},
		},
	}
}
