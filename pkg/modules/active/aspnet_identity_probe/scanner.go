package aspnet_identity_probe

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

// Module implements the ASP.NET Identity Probe active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new ASP.NET Identity Probe module.
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
		ds: dedup.LazyDiskSet("aspnet_identity_probe"),
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

// ScanPerRequest probes the host for exposed Identity and OIDC endpoints.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	if !modkit.BeginHostProbeFor(scanCtx, httpClient, &m.ds, ctx) {
		return nil, nil
	}

	fp := m.fingerprint404(ctx, httpClient)

	var results []*output.ResultEvent
	for _, p := range probes {
		if result := m.probeEndpoint(ctx, httpClient, p, fp); result != nil {
			results = append(results, result)
		}
	}

	// Extract detailed OIDC metadata if discovery document found
	if oidcResult := m.probeOIDCDiscovery(ctx, httpClient); oidcResult != nil {
		results = append(results, oidcResult)
	}

	return results, nil
}

func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-identity-404-" + utils.RandomString(8)

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

	// Content-type discipline (survives the body-truncation FP — the header stays
	// intact when a gzip/Content-Length:0 quirk leaves only a partial body tail):
	// the token / JWKS / Identity-API probes target JSON documents that are never
	// served as an HTML *document*. A reflecting or catch-all host that answers an
	// arbitrary path with its themed text/html shell would otherwise forge a match
	// on a weak marker ("email", `"errors":{`) surviving in that tail. Rejecting an
	// HTML document for a JSON probe is decisive and costs no true positives.
	if p.jsonBody && modkit.ClassifyContentType(resp.Response().Header.Get("Content-Type")) == modkit.ContentClassHTML {
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

	// Strip the reflected request from the body before marker matching: a host that
	// echoes the requested path back into its response (the catch-all/echo server)
	// would otherwise let a marker that is itself a path segment satisfy the check
	// ("ForgotPassword" from /Identity/Account/ForgotPassword). The original body is
	// kept for anti-markers and the stored evidence.
	matchBody := modkit.StripReflectedProbePath(body, p.path)
	if reqBody := ctx.Request().BodyToString(); reqBody != "" {
		matchBody = modkit.StripReflected(matchBody, reqBody)
	}

	matchedMarkers, ok := p.accepts(matchBody)
	if !ok {
		return nil
	}

	// Multi-round catch-all disproof: probe several guaranteed-nonexistent siblings
	// under this probe's parent directory. If a random sibling returns the same
	// status and also satisfies the marker predicate, the host serves this content
	// for any path — a reflecting/echo server or a wildcard rewrite — so the match
	// proves nothing (a scaffolded ASP.NET shell carries "__RequestVerificationToken"
	// on every page). A genuinely exposed endpoint has no such sibling (the decoy
	// 404s), so this costs no true positives, and it is robust to the body-truncation
	// quirk because the decoy is run through the same predicate rather than a body-
	// similarity compare.
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
			Name:        fmt.Sprintf("Identity Exposure: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  severity.Firm,
			Tags:        []string{"aspnet", "identity", "authentication", "oidc"},
			Reference:   []string{"https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity"},
		},
	}
}

// probeOIDCDiscovery fetches the OIDC discovery document and extracts metadata
// as a separate finding with detailed endpoint and scope enumeration.
func (m *Module) probeOIDCDiscovery(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, "/.well-known/openid-configuration")
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

	var discovery map[string]interface{}
	if err := json.Unmarshal([]byte(body), &discovery); err != nil {
		return nil
	}

	// Must have issuer to be valid OIDC discovery
	if _, ok := discovery["issuer"]; !ok {
		return nil
	}

	extracted := extractOIDCMetadata(discovery)
	if len(extracted) == 0 {
		return nil
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + "/.well-known/openid-configuration"

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        "OIDC Discovery Metadata Enumeration",
			Description: "OpenID Connect discovery document reveals detailed authentication infrastructure including token endpoints, supported scopes, grant types, and signing algorithms",
			// The discovery document at /.well-known/openid-configuration is public
			// by design (OpenID Connect Discovery 1.0) and not ASP.NET-specific —
			// it is exposed identically by any OIDC provider. It is informational
			// and needs human review, so Low and not tagged "aspnet".
			Severity:   severity.Low,
			Confidence: severity.Certain,
			Tags:       []string{"identity", "oidc", "information-disclosure"},
			Reference:  []string{"https://openid.net/specs/openid-connect-discovery-1_0.html"},
		},
	}
}

// extractOIDCMetadata extracts key fields from the OIDC discovery document.
func extractOIDCMetadata(discovery map[string]interface{}) []string {
	var extracted []string

	if issuer, ok := discovery["issuer"].(string); ok {
		extracted = append(extracted, fmt.Sprintf("Issuer: %s", issuer))
	}

	for _, field := range []string{"token_endpoint", "authorization_endpoint", "userinfo_endpoint", "revocation_endpoint", "introspection_endpoint"} {
		if val, ok := discovery[field].(string); ok {
			extracted = append(extracted, fmt.Sprintf("%s: %s", field, val))
		}
	}

	for _, field := range []string{"scopes_supported", "grant_types_supported", "response_types_supported"} {
		if arr, ok := discovery[field].([]interface{}); ok {
			var items []string
			for _, item := range arr {
				if s, ok := item.(string); ok {
					items = append(items, s)
				}
			}
			if len(items) > 0 {
				extracted = append(extracted, fmt.Sprintf("%s: %s", field, strings.Join(items, ", ")))
			}
		}
	}

	return extracted
}
