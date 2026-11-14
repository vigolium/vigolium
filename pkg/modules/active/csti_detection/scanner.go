package csti_detection

import (
	"fmt"
	"math/rand/v2"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// confirmCount is the number of times a CSTI reflection must be confirmed
// to reduce false positives (each attempt uses fresh random anchors).
const confirmCount = 2

// Module implements the CSTI active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new CSTI Detection module.
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
			modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		rhm: dedup.LazyDefaultRHM("csti_detection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ConfirmsByBodyDifferential opts this module into the executor's body-
// differential safety net: a candidate finding is re-confirmed by replaying the
// probe request and requiring the reflected template expression to reappear as
// stable content absent from the clean baseline. The probe is reflected
// literally, so this guards against non-reproducible reflections (flapping or
// cached pages), not against reflection itself.
func (m *Module) ConfirmsByBodyDifferential() bool { return true }

// VulnClass enables cross-module (param, class) dedup: once any csti module
// reports a parameter, the others in the class skip it.
func (m *Module) VulnClass() string { return modkit.VulnClassCSTI }

// ScanPerInsertionPoint tests a single insertion point for CSTI.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Check deduplication
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Get baseline response body
	var baselineBody string
	if ctx.HasResponse() {
		baselineBody = ctx.Response().BodyToString()
	} else {
		baseResp, _, err := httpClient.Execute(ctx, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			return nil, nil
		}
		baselineBody = baseResp.Body().String()
		baseResp.Close()
	}

	// Check framework fingerprint for this host (cached)
	fw := getFramework(urlx.Host, baselineBody)
	if fw == nil {
		return nil, nil
	}

	// Run confirmation loop
	for attempt := range confirmCount {
		probe, markers := buildCSTIProbe()

		fuzzedRaw := ip.BuildRequest([]byte(probe))
		// BuildRequest produces well-formed raw, so wrap directly instead of
		// re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			return nil, nil
		}

		attackBody := resp.Body().String()
		fullResponse := resp.FullResponseString()
		attackContentType := ""
		if resp.Response() != nil {
			attackContentType = resp.Response().Header.Get("Content-Type")
		}
		resp.Close()

		// CSTI confirmation here is pure LITERAL reflection of the {{...}} probe
		// (not an evaluated product), so it only holds when the response is an HTML
		// rendering context the framework will actually interpret. A non-HTML
		// response (a JSON API echoing the probe in a validation error) reflects the
		// braces as a data value that no template engine renders — and the per-host
		// framework fingerprint is inherited from a sibling HTML page, so without
		// this gate a JSON endpoint on a framework host false-positives.
		if modkit.IsNonHTMLReflectionContext(attackContentType) {
			break
		}

		// Check for literal reflection (not HTML-encoded)
		reflected := false
		for _, marker := range markers {
			if strings.Contains(attackBody, marker) && !strings.Contains(baselineBody, marker) {
				reflected = true
				break
			}
		}

		if !reflected {
			break
		}

		// Check HTML encoding — if encoded, not exploitable
		if isHTMLEncoded(attackBody, markers[0]) {
			break
		}

		// On final confirmation, report finding
		if attempt == confirmCount-1 {
			confidence := severity.Firm
			if isInsideFrameworkScope(attackBody, markers[0]) {
				confidence = severity.Certain
			}

			return []*output.ResultEvent{
				{
					URL:              urlx.String(),
					Request:          string(fuzzedRaw),
					Response:         fullResponse,
					FuzzingParameter: ip.Name(),
					ExtractedResults: []string{probe, fw.Name},
					Info: output.Info{
						Name: "Client-Side Template Injection (CSTI)",
						Description: fmt.Sprintf(
							"The parameter '%s' reflects a template expression {{...}} literally in the HTML response "+
								"within a %s application scope. The %s framework will evaluate this expression in the "+
								"victim's browser, enabling arbitrary JavaScript execution.\n\n"+
								"Proof: injected `%s` — reflected verbatim in response body.",
							ip.Name(), fw.Name, fw.Name, probe,
						),
						Confidence: confidence,
						Reference: []string{
							"https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs",
							"https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection",
						},
					},
				},
			}, nil
		}
	}

	return nil, nil
}

// buildCSTIProbe generates a template expression probe with random anchors.
func buildCSTIProbe() (probe string, markers []string) {
	left := modkit.RandomAlnum(6)
	right := modkit.RandomAlnum(6)
	mathA := 1970 + rand.IntN(100)
	mathB := 2024 + rand.IntN(100)
	expr := fmt.Sprintf("%d*%d", mathA, mathB)

	probe = fmt.Sprintf("%s{{%s}}%s", left, expr, right)
	markers = []string{
		fmt.Sprintf("%s{{%s}}%s", left, expr, right),
		fmt.Sprintf("%s{{ %s }}%s", left, expr, right),
	}
	return probe, markers
}

// isHTMLEncoded checks if the template curlies are HTML-encoded in the response.
func isHTMLEncoded(body, marker string) bool {
	// Extract the left anchor (everything before "{{")
	left, _, ok := strings.Cut(marker, "{{")
	if !ok {
		return false
	}
	encoded := left + "&#123;&#123;"
	altEncoded := left + "&lcub;&lcub;"
	return strings.Contains(body, encoded) || strings.Contains(body, altEncoded)
}

// RequiresReflection opts into the executor's shared reflection probe
// (modkit.ReflectionAware, ECON-2): the oracle reads the payload back, so a
// point whose value does not come back is skipped.
func (m *Module) RequiresReflection() modkit.ReflectionNeed { return modkit.ReflectBody }
