package lfi_path_traversal

import (
	"fmt"

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

const minBodyDelta = 50 // minimum body length increase to consider a hit

// Module implements the LFI Path Traversal active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new LFI Path Traversal module.
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
		rhm: dedup.LazyDefaultRHM("lfi_path_traversal"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ConfirmsByBodyDifferential opts this module into the executor's body-
// differential safety net: a candidate finding is re-confirmed by replaying the
// traversal request and requiring the included file content to reappear as
// stable content absent from the clean baseline.
func (m *Module) ConfirmsByBodyDifferential() bool { return true }

// VulnClass enables cross-module (param, class) dedup: once any lfi module
// reports a parameter, the others in the class skip it.
func (m *Module) VulnClass() string { return modkit.VulnClassLFI }

// ScanPerInsertionPoint tests a single insertion point for advanced LFI path traversal.
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

	// Dedup check
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Pre-filter: only test file-like parameters
	if !matchFileParams(ip.Name()) && !looksLikeFilePath(ip.BaseValue()) {
		return nil, nil
	}

	// Get baseline body for false-positive suppression
	var baselineBody string
	var baselineLen int
	var baselineStatus int
	if ctx.Response() != nil {
		baselineBody = ctx.Response().BodyToString()
		baselineLen = len(baselineBody)
		baselineStatus = ctx.Response().StatusCode()
	}

	statusChanged := false

	// Tier 1: core traversal payloads
	for _, p := range tier1Payloads {
		result, sc, err := m.testPayload(ctx, ip, httpClient, p, baselineBody, baselineLen, baselineStatus)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			continue
		}
		if sc {
			statusChanged = true
		}
		if result != nil {
			return []*output.ResultEvent{result}, nil
		}
	}

	// Tier 2: only if tier 1 caused a *served* (non-blocked, <400) status change,
	// which hints traversal alters handling so a different file may be reachable.
	// A WAF block does not set statusChanged, so we never escalate against an edge
	// that is already blocking the payloads.
	if statusChanged {
		for _, p := range tier2CanaryFiles {
			result, _, err := m.testPayload(ctx, ip, httpClient, p, baselineBody, baselineLen, baselineStatus)
			if err != nil {
				if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
					return nil, nil
				}
				continue
			}
			if result != nil {
				return []*output.ResultEvent{result}, nil
			}
		}
	}

	return nil, nil
}

// testPayload sends a single LFI payload and checks for marker matches.
// Returns (result, statusChanged, error).
func (m *Module) testPayload(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	p lfiPayload,
	baselineBody string,
	baselineLen int,
	baselineStatus int,
) (*output.ResultEvent, bool, error) {
	fuzzedRaw := httpmsg.BuildPayload(ip, []byte(p.payload), p.preEncoded)

	// BuildRequest produces well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil, false, err
	}
	defer resp.Close()

	respStatus := 0
	if resp.Response() != nil {
		respStatus = resp.Response().StatusCode
	}

	// Reject the response before mining it for file content when it is a WAF/CDN
	// block, an interstitial challenge, an auth gate, a rate limit, or any
	// 4xx/5xx. A successful file include returns the file body with a 2xx/3xx
	// status; a rejected payload's body — a Cloudflare "Blocked Content" page, a
	// 404 shell, a stack trace — is the server (or its edge) talking, not leaked
	// file content, even when it happens to carry file-shaped tokens. This kills
	// the motivating false positive: a 403 Cloudflare block page whose cf-beacon
	// JSON ("server_timing"/"location_startswith") satisfied the old bare
	// "server"/"location" nginx.conf markers.
	//
	// A block also does not count as a "status change" for tier-2 escalation —
	// the WAF catching the payload is not evidence traversal works — so we return
	// statusChanged=false and avoid hammering an edge that is already blocking.
	if infra.IsBlockedResponse(resp) || respStatus >= 400 {
		return nil, false, nil
	}

	body := resp.Body().String()
	statusChanged := respStatus != baselineStatus && baselineStatus != 0

	// Body length delta check
	if len(body)-baselineLen < minBodyDelta {
		return nil, statusChanged, nil
	}

	// Structural confirmation with baseline subtraction: the targeted file's real
	// content shape must appear and must be absent from the baseline.
	ok, score := p.confirm(body, baselineBody)
	if !ok {
		return nil, statusChanged, nil
	}

	urlx, _ := ctx.URL()
	target, info := urlx.String(), lfiInfo(ip.Name(), p.payload, score)

	// A published file reached through a URL path segment was fetched at its own
	// URL, not included: the traversal prefix normalizes away and the request is
	// an ordinary GET. Report the exposure informationally — nothing here shows
	// the application reading a caller-controlled path — and anchor it at the
	// file's URL since that is the thing to act on.
	if modkit.DocrootFetchNotInclusion(ip.Type(), p.payload) {
		info = modkit.DocrootFetchInfo(p.payload)
		if fileURL := httpmsg.GetURLFromRequest(urlx.Scheme, fuzzedRaw); fileURL != "" {
			target = fileURL
		}
	}

	return &output.ResultEvent{
		URL:              target,
		Matched:          target,
		Request:          string(fuzzedRaw),
		Response:         resp.FullResponseString(),
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{p.payload},
		Info:             info,
	}, statusChanged, nil
}

// lfiInfo describes a confirmed inclusion. Confidence rises to Certain once the
// response carries three or more distinct markers of the targeted file.
func lfiInfo(paramName, payload string, score int) output.Info {
	conf := severity.Firm
	if score >= 3 {
		conf = severity.Certain
	}
	return output.Info{
		Name:        "LFI Path Traversal",
		Description: fmt.Sprintf("Local file inclusion detected via parameter %q with payload: %s (%d distinct file-content markers confirmed)", paramName, payload, score),
		Severity:    severity.High,
		Confidence:  conf,
		Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion"},
	}
}
