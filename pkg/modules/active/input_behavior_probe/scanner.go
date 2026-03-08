package input_behavior_probe

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
)

// fuzzPayload contains special characters to trigger various parser behaviors.
// From ActiveScan++ SimpleFuzz.java
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

	var results []*output.ResultEvent
	results = append(results, probeHeaders(ctx, httpClient, baseline)...)
	results = append(results, probePaths(ctx, httpClient, baseline)...)
	results = append(results, probeDebugParams(ctx, httpClient, baseline)...)

	return results, nil
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

	var results []*output.ResultEvent

	// Polyglot fuzz probe (existing logic)
	results = append(results, m.probePolyglot(ctx, ip, httpClient, baseline)...)

	// Per-char param fuzzing
	results = append(results, probeParamFuzz(ctx, ip, httpClient, baseline)...)

	return results, nil
}

// probePolyglot sends a polyglot payload to detect HTML tag structure changes.
func (m *Module) probePolyglot(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	baseline *detectionBaseline,
) []*output.ResultEvent {
	fuzzedRaw := ip.BuildRequest([]byte(fuzzPayload))

	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	fuzzedResp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil
		}
		return nil
	}
	defer fuzzedResp.Close()

	change := detectChange(baseline, fuzzedResp.Body().String(), fuzzedResp.Response().StatusCode)
	if change.IsInteresting {
		urlx, _ := ctx.URL()
		urlStr := ""
		if urlx != nil {
			urlStr = urlx.String()
		}
		return []*output.ResultEvent{
			buildProbeResult(
				urlStr, fuzzedRaw, fuzzedResp.FullResponse().String(),
				ip.Name(), "polyglot_fuzz", fuzzPayload, change,
			),
		}
	}

	return nil
}
