package open_redirect_confusion

import (
	"fmt"
	"regexp"

	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/weppos/publicsuffix-go/publicsuffix"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/open_redirect"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// probeEffective is the fixed attacker host used for the cheap first-pass sweep.
// A first-pass hit only nominates a candidate; the finding is not reported until
// the multi-round ConfirmReflection pass re-proves it with fresh random domains,
// so this fixed sentinel cannot itself cause a false positive.
const probeEffective = "redirect-confusion-probe.net"

// confirmRounds is how many fresh-domain rounds must all redirect to their
// round's domain before a finding is reported.
const confirmRounds = 2

// Module implements the open-redirect-via-URL-parser-confusion active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new open-redirect-confusion module.
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
		rhm: dedup.LazyDefaultRHM("open_redirect_confusion"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests redirect-like URL/body parameters with the URL-parser
// authority-confusion ladder.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return nil, nil
	}

	// The decoy is the target's own registrable domain: most same-origin/prefix
	// allowlists trust it, so a decoy@attacker payload models the real bypass.
	// Fall back to the bare hostname (e.g. when the host is an IP).
	decoy, derr := publicsuffix.Domain(urlx.Hostname())
	if derr != nil || decoy == "" {
		decoy = urlx.Hostname()
	}

	points, err := scanCtx.GetInsertionPoints(ctx.Request().Raw(), ctx.Request().ID(), false)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create insertion points")
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())

	var results []*output.ResultEvent
	for _, ip := range points {
		if ip.Type() != httpmsg.INS_PARAM_URL && ip.Type() != httpmsg.INS_PARAM_BODY {
			continue
		}
		if !open_redirect.MatchRedirectParam(ip.Name(), ip.BaseValue()) {
			continue
		}
		if rhm != nil {
			paramType := fmt.Sprintf("%d", ip.Type())
			if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), ip.Name(), ip.BaseValue(), paramType) {
				continue
			}
		}

		res, fatal := m.scanParam(ctx, ip, urlx, decoy, httpClient)
		if fatal {
			return results, nil // host went unresponsive — stop cleanly
		}
		if len(res) > 0 {
			results = append(results, res...)
			return results, nil // one confirmed finding per request is enough
		}
	}
	return results, nil
}

// scanParam runs the cheap first-pass ladder, then re-confirms a candidate across
// multiple fresh-domain rounds. The bool return is true only when the host became
// unresponsive (the caller should stop).
func (m *Module) scanParam(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	urlx *urlutil.URL,
	decoy string,
	httpClient *http.Requester,
) ([]*output.ResultEvent, bool) {
	hit, idx, ok, fatal := m.runLadder(ctx, ip, decoy, probeEffective, httpClient)
	if fatal {
		return nil, true
	}
	if !ok {
		return nil, false
	}

	// Re-confirm: replay ONLY the winning payload with a fresh random attacker
	// domain each round, requiring every round to redirect to that round's domain.
	// A value that genuinely flows to the redirect tracks the changing domain; a
	// coincidental match does not. Replaying just the winner (instead of re-running
	// the whole ladder) confirms the same quirk reproducibly and avoids ~ladder×rounds
	// wasted requests.
	confirmed, cerr := modkit.ConfirmReflection(confirmRounds, func(canary string) (bool, error) {
		matched, fatal := m.replayPayload(ctx, ip, decoy, canary+".com", idx, httpClient)
		if fatal {
			return false, hosterrors.ErrUnresponsiveHost
		}
		return matched, nil
	})
	// Fail open on a transient error (we already had a first-pass hit); fail
	// closed only on a clean "did not re-confirm" verdict.
	if cerr == nil && !confirmed {
		return nil, false
	}

	return []*output.ResultEvent{{
		URL:              urlx.String(),
		Request:          hit.request,
		Response:         hit.responseHeaders,
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{hit.payload, hit.label},
		Info: output.Info{
			Description: fmt.Sprintf(
				"Open redirect via URL-parser authority confusion (%s): a validator that trusts %q is bypassed and the redirect target is attacker-controlled.",
				hit.label, decoy,
			),
			Severity:   severity.High,
			Confidence: severity.Firm,
		},
	}}, false
}

// ladderHit captures the winning payload for finding evidence.
type ladderHit struct {
	payload         string
	label           string
	request         string
	responseHeaders string
}

// runLadder injects each authority-confusion payload (decoy vs effective) and
// returns the first that redirects to the effective host, along with its index in
// the payload ladder (so confirmation can replay just that payload). The fatal
// bool is true when the host became unresponsive mid-sweep.
func (m *Module) runLadder(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	decoy, effective string,
	httpClient *http.Requester,
) (ladderHit, int, bool, bool) {
	re := open_redirect.DomainRedirectRegex(effective)
	for i, p := range infra.AuthorityConfusionPayloads(decoy, effective) {
		matched, raw, headers, fatal := m.sendAndMatch(ctx, ip, p.Value, re, httpClient)
		if fatal {
			return ladderHit{}, 0, false, true
		}
		if matched {
			return ladderHit{payload: p.Value, label: p.Label, request: raw, responseHeaders: headers}, i, true, false
		}
	}
	return ladderHit{}, 0, false, false
}

// replayPayload re-sends only the payload at idx (rebuilt for a fresh effective
// host) and reports whether it redirects to that effective host. Used by the
// confirmation rounds so they replay the winning quirk instead of the whole
// ladder. The fatal bool is true when the host became unresponsive.
func (m *Module) replayPayload(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	decoy, effective string,
	idx int,
	httpClient *http.Requester,
) (matched bool, fatal bool) {
	payloads := infra.AuthorityConfusionPayloads(decoy, effective)
	if idx < 0 || idx >= len(payloads) {
		return false, false
	}
	re := open_redirect.DomainRedirectRegex(effective)
	matched, _, _, fatal = m.sendAndMatch(ctx, ip, payloads[idx].Value, re, httpClient)
	return matched, fatal
}

// sendAndMatch injects payload into the insertion point and reports whether the
// response redirects to a target matching re. On a match it also returns the raw
// request and response headers for finding evidence. The fatal bool is true when
// the host became unresponsive.
func (m *Module) sendAndMatch(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	payload string,
	re *regexp.Regexp,
	httpClient *http.Requester,
) (matched bool, request string, headers string, fatal bool) {
	fuzzedRaw := ip.BuildRequest([]byte(payload))
	req, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return false, "", "", false
	}
	req = req.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true})
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return false, "", "", true
		}
		return false, "", "", false
	}
	defer resp.Close()

	open_redirect.CheckRedirectOutput(resp, func(nextLoc string) bool {
		if re.MatchString(nextLoc) {
			matched = true
			return false
		}
		return true
	})
	if matched {
		return true, string(fuzzedRaw), resp.Headers().String(), false
	}
	return false, "", "", false
}
