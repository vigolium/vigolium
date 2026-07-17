package input_behavior_probe

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// fuzzPayload contains special characters to trigger various parser behaviors.
const fuzzPayload = `a'a\'b"c>?>%}}%%>c<[[?${{%}}cake\`

type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
	ds  dedup.Lazy[dedup.DiskSet]
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
			modkit.ScanScopeRequest|modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		rhm: dedup.LazyDefaultRHM("input_behavior_probe"),
		ds:  dedup.LazyDiskSet("input_behavior_probe"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest probes headers, path manipulations, and debug params once per
// unique host+path combination.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	// Dedup by host+path to avoid repeated probing for the same endpoint
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	// Get baseline response (cached across modules)
	entry, err := scanCtx.GetOrFetchBaseline(ctx, httpClient)
	if err != nil {
		return nil, nil
	}
	baseline := newDetectionBaseline(entry)
	// A baseline that is itself a WAF/CDN edge block (a CloudFront "Request blocked"
	// 403, a Cloudflare challenge served at 200 or 403, a 429) is not the
	// application's response. A probe that rewrites the offending path segment dodges
	// the edge rule and returns the real 200 page — which the 403→200 status leg
	// misreads as an access-control flip and the tag-diff leg misreads as an
	// input-driven structural change. Neither leg has a usable reference, so drop the
	// endpoint. IsEdgeBlockedResponse flags only vendor blocks, so a genuine app 403
	// baseline (the real access-control-flip signal) is preserved.
	if baseline.edgeBlocked {
		return nil, nil
	}
	calibrateTagJitter(ctx, httpClient, baseline)

	var results []*output.ResultEvent
	results = append(results, probeHeaders(ctx, httpClient, baseline)...)
	results = append(results, probePaths(ctx, httpClient, baseline)...)
	results = append(results, probeDebugParams(ctx, httpClient, baseline)...)

	// Collapse every probe that diverged for this endpoint into ONE finding so the
	// run writes a single http_record instead of one per probe (the rest ride along
	// as inline AdditionalEvidence) — keeps probe traffic from flooding the table.
	return collapseProbeFindings(results), nil
}

// ScanPerInsertionPoint tests a single insertion point for HTML structure
// changes using a polyglot fuzz payload and per-char param fuzzing.
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

	// Check if we should scan this insertion point
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Get baseline response (cached across modules)
	entry, err := scanCtx.GetOrFetchBaseline(ctx, httpClient)
	if err != nil {
		return nil, nil
	}
	baseline := newDetectionBaseline(entry)
	// Drop an edge-blocked baseline (see ScanPerRequest): a WAF/CDN block page is not
	// a usable reference for the status or tag-structure differential.
	if baseline.edgeBlocked {
		return nil, nil
	}
	calibrateTagJitter(ctx, httpClient, baseline)

	var results []*output.ResultEvent

	// Polyglot fuzz probe (existing logic)
	results = append(results, m.probePolyglot(ctx, ip, httpClient, baseline)...)

	// Per-char param fuzzing
	results = append(results, probeParamFuzz(ctx, ip, httpClient, baseline)...)

	// Collapse to a single finding (one http_record) per insertion point; the other
	// diverging char/polyglot probes become inline AdditionalEvidence.
	return collapseProbeFindings(results), nil
}

// probePolyglot sends a polyglot payload to detect HTML tag structure changes.
func (m *Module) probePolyglot(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	baseline *detectionBaseline,
) []*output.ResultEvent {
	fuzzedRaw := ip.BuildRequest([]byte(fuzzPayload))

	// fuzzedRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())

	fuzzedResp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil
		}
		return nil
	}
	defer fuzzedResp.Close()

	change := detectChange(baseline, fuzzedResp.Body().String(), fuzzedResp.Response().StatusCode)
	if confirmChange(ctx, httpClient, baseline, fuzzedRaw, change) {
		urlx, _ := ctx.URL()
		urlStr := ""
		if urlx != nil {
			urlStr = urlx.String()
		}
		return []*output.ResultEvent{
			buildProbeResult(
				urlStr, fuzzedRaw, fuzzedResp.FullResponseString(),
				ip.Name(), "polyglot_fuzz", fuzzPayload, change,
			),
		}
	}

	return nil
}
