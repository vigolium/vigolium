package command_injection_echo

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Module implements the results-based OS command injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new results-based command injection module.
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
		rhm: dedup.LazyDefaultRHM("command_injection_echo"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests every insertion point for results-based command injection.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return results, nil
	}

	points, err := scanCtx.GetInsertionPoints(ctx.Request().Raw(), ctx.Request().ID(), true)
	if err != nil {
		return results, errors.Wrap(err, "failed to create insertion points")
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		points = rhm.GetNotCheckedInsertionPoints(urlx, ctx.Request(), points)
	}
	if len(points) == 0 {
		return results, nil
	}

	candidates := infra.CmdiEchoCandidates()

ipScan:
	for _, ip := range points {
		baseValue := ip.BaseValue()

		// Fetch the clean, unpayloaded response once per insertion point. Its body
		// is the negative control: the unique needle must NEVER appear here.
		body, raw, full, baselineErr := m.probe(ctx, httpClient, ip, baseValue)
		if errors.Is(baselineErr, hosterrors.ErrUnresponsiveHost) {
			return results, nil
		}
		base := baselineProbe{value: baseValue, body: body, raw: raw, full: full, ok: baselineErr == nil}

		for _, c := range candidates {
			result, err := m.confirmCandidate(ctx, httpClient, ip, c, base)
			if err != nil {
				if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
					return results, nil
				}
				continue
			}
			if result != nil {
				result.URL = urlx.String()
				result.Matched = urlx.String()
				results = append(results, result)
				continue ipScan // one confirmed finding per insertion point
			}
		}
	}

	return results, nil
}

// baselineProbe is the clean, unpayloaded response captured once per insertion
// point. Its body is the negative control: a confirmed needle must be absent
// from it. ok is false when the baseline fetch failed — the absence check is
// then skipped, but the two-round confirmation still applies.
type baselineProbe struct {
	value string
	body  string
	raw   string
	full  string
	ok    bool
}

// confirmCandidate runs the multi-layer confirmation for a single breakout
// context/technique: two independent rounds, each with a fresh unique marker,
// must both echo back the computed needle while it stays absent from the clean
// baseline. Only then is the finding reported (built from round 2, the freshest
// proof). Returns (nil, nil) when the candidate does not confirm.
func (m *Module) confirmCandidate(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	c infra.CmdiCandidate,
	base baselineProbe,
) (*output.ResultEvent, error) {
	_, raw1, _, ok1, err := m.confirmRound(ctx, httpClient, ip, c, base)
	if err != nil {
		return nil, err
	}
	if !ok1 {
		return nil, nil
	}

	marker2, raw2, full2, ok2, err := m.confirmRound(ctx, httpClient, ip, c, base)
	if err != nil {
		return nil, err
	}
	if !ok2 {
		return nil, nil
	}

	// Confirmed. Attach the baseline + round-1 context as supporting evidence.
	ev := modkit.NewEvidenceCollector()
	if base.ok {
		ev.Add("baseline (no payload)", base.raw, base.full)
	}
	ev.Add("round 1 ("+c.Label+")", raw1, "")
	ev.Add("round 2 ("+c.Label+")", raw2, full2)

	desc := fmt.Sprintf(
		"OS command injection confirmed in parameter %q via the %s breakout context. "+
			"The shell evaluated an injected arithmetic expression and returned the unique "+
			"computed value %q (bracketed by per-probe random delimiters) across two "+
			"independent rounds; the value was absent from the unpayloaded baseline. A "+
			"literal reflection of the payload could not produce the computed sum.",
		ip.Name(), c.Label, marker2.Expected)

	return &output.ResultEvent{
		Request:            raw2,
		Response:           full2,
		FuzzingParameter:   ip.Name(),
		ExtractedResults:   []string{marker2.Needle(), base.value + c.Render(marker2)},
		AdditionalEvidence: ev.Entries(),
		MatcherStatus:      true,
		Info: output.Info{
			Name:        ModuleName,
			Description: desc,
			Severity:    severity.Critical,
			Confidence:  severity.Certain,
		},
	}, nil
}

// confirmRound runs one confirmation round: inject the candidate with a fresh
// unique marker and report ok=true only when the computed needle appears in the
// response AND is absent from the clean baseline. It returns the marker and the
// raw/full request-response so the caller can build evidence from the round that
// confirmed.
func (m *Module) confirmRound(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	c infra.CmdiCandidate,
	base baselineProbe,
) (marker infra.CmdiArithMarker, raw, full string, ok bool, err error) {
	marker = infra.NewCmdiArithMarker()
	var body string
	body, raw, full, err = m.probe(ctx, httpClient, ip, base.value+c.Render(marker))
	if err != nil {
		return marker, raw, full, false, err
	}
	if !strings.Contains(body, marker.Needle()) {
		return marker, raw, full, false, nil
	}
	// Baseline comparison: the unique needle must not pre-exist in the clean response.
	if base.ok && strings.Contains(base.body, marker.Needle()) {
		return marker, raw, full, false, nil
	}
	return marker, raw, full, true, nil
}

// probe sends ip set to value and returns the decoded response body, the raw
// request sent, and the full raw response (for evidence). The body is what the
// needle match runs against.
func (m *Module) probe(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	value string,
) (body, rawReq, fullResp string, err error) {
	raw := ip.BuildRequest([]byte(value))
	rawReq = string(raw)

	req, perr := httpmsg.ParseRawRequest(rawReq)
	if perr != nil {
		return "", rawReq, "", perr
	}
	req = req.WithService(ctx.Service())

	// NoRedirects so we inspect the immediate response body where the injected
	// output surfaces, rather than following to an unrelated page.
	resp, _, eerr := httpClient.Execute(req, http.Options{NoRedirects: true})
	if eerr != nil {
		return "", rawReq, "", eerr
	}
	body = resp.Body().String()
	fullResp = resp.FullResponseString()
	resp.Close()
	return body, rawReq, fullResp, nil
}
