package backslash_transformation

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/zap"
)

// Module detects server-side handling of backslash-escaped characters.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new BackslashTransformation module.
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
		rhm: dedup.LazyDefaultRHM("backslash_transformation"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests a single insertion point for backslash transformations.
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

	// Deduplication check
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Phase 1: Initial reflection check
	reflects, err := m.checkReflection(ctx, ip, httpClient)
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil, nil
		}
		zap.L().Debug("reflection check failed", zap.Error(err))
		return nil, nil
	}
	if !reflects {
		zap.L().Debug("parameter does not reflect, skipping",
			zap.String("param", ip.Name()),
			zap.String("url", urlx.String()))
		return nil, nil
	}

	// Phase 2: Backslash consumption check
	backslashConsumed, err := m.checkBackslashConsumption(ctx, ip, httpClient)
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil, nil
		}
		zap.L().Debug("backslash consumption check failed", zap.Error(err))
		return nil, nil
	}

	zap.L().Debug("backslash consumption status",
		zap.Bool("consumed", backslashConsumed),
		zap.String("param", ip.Name()))

	var interesting []*TransformResult
	var boring []*TransformResult

	// Phase 3: Escape sequence probes
	for _, payload := range DecodeBasedPayloads {
		results, reqRaw, respFull, err := m.recordAndClassify(ctx, ip, httpClient, payload, backslashConsumed)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			continue
		}

		for _, r := range results {
			if r.Classification == ClassificationInteresting ||
				r.Classification == ClassificationBackslashConsumed {
				interesting = append(interesting, r)
				// Store request/response for reporting
				r.Pretty = fmt.Sprintf("%s [req: %d bytes]", r.Pretty, len(reqRaw))
				_ = respFull // Available for detailed reporting if needed
			} else {
				boring = append(boring, r)
			}
		}
	}

	// Phase 4: Character probes
	for _, charPayload := range CharacterPayloads {
		escapedPayload := "\\" + charPayload

		var chosenPayload, followUpPayload string
		if backslashConsumed {
			chosenPayload = charPayload
			followUpPayload = escapedPayload
		} else {
			chosenPayload = escapedPayload
			followUpPayload = charPayload
		}

		results, _, _, err := m.recordAndClassify(ctx, ip, httpClient, chosenPayload, backslashConsumed)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			continue
		}

		hasInteresting := false
		for _, r := range results {
			if r.Classification == ClassificationInteresting ||
				r.Classification == ClassificationBackslashConsumed {
				interesting = append(interesting, r)
				hasInteresting = true
			} else {
				boring = append(boring, r)
			}
		}

		// If interesting, also record the follow-up payload
		if hasInteresting {
			followUpTransforms, err := m.recordTransformations(ctx, ip, httpClient, followUpPayload)
			if err == nil {
				for _, t := range followUpTransforms {
					interesting = append(interesting, &TransformResult{
						Probe:          followUpPayload,
						Received:       t,
						Classification: ClassificationInteresting,
						Pretty:         followUpPayload + " => " + t,
					})
				}
			}
		}
	}

	// Report findings
	if len(interesting) == 0 {
		return nil, nil
	}

	return m.buildResults(ctx, ip, httpClient, interesting, boring, backslashConsumed)
}

// checkReflection verifies that the parameter value reflects in the response.
// If existing response and base value are available, checks there first to save requests.
func (m *Module) checkReflection(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
) (bool, error) {
	// Fast path: check if base value reflects in existing response
	if ctx.HasResponse() && ip.BaseValue() != "" {
		body := ctx.Response().Body()
		if !httpmsg.ContainsBytes(body, []byte(ip.BaseValue())) {
			// Base value doesn't reflect, no need to send probe
			return false, nil
		}
	}

	// Send anchored probe to confirm reflection with our canary
	payload, searchAnchor := NewBasicReflectionPayload()

	fuzzedRaw := ip.BuildRequest([]byte(payload))
	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return false, errors.Wrap(err, "failed to parse fuzzed request")
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return false, err
	}
	defer resp.Close()

	body := resp.Body().Bytes()
	matches := httpmsg.GetMatches(body, []byte(searchAnchor), 1)

	return len(matches) > 0, nil
}

// checkBackslashConsumption determines if the server strips backslashes.
func (m *Module) checkBackslashConsumption(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
) (bool, error) {
	transformations, err := m.recordTransformations(ctx, ip, httpClient, "\\zz")
	if err != nil {
		return false, err
	}

	return IsBackslashConsumed(transformations), nil
}

// recordTransformations sends a probe and extracts transformation results.
func (m *Module) recordTransformations(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	probe string,
) ([]string, error) {
	ap := NewAnchoredPayload(probe)

	fuzzedRaw := ip.BuildRequest([]byte(ap.FullPayload))
	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse fuzzed request")
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	body := resp.Body().Bytes()
	return ExtractBetweenAnchors(body, ap.SearchAnchor(), ap.RightAnchor), nil
}

// recordAndClassify sends a probe and classifies the transformations.
func (m *Module) recordAndClassify(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	probe string,
	expectBackslashConsumption bool,
) ([]*TransformResult, []byte, string, error) {
	ap := NewAnchoredPayload(probe)

	fuzzedRaw := ip.BuildRequest([]byte(ap.FullPayload))
	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return nil, nil, "", errors.Wrap(err, "failed to parse fuzzed request")
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil, nil, "", err
	}
	defer resp.Close()

	body := resp.Body().Bytes()
	fullResp := resp.FullResponseString()

	transformations := ExtractBetweenAnchors(body, ap.SearchAnchor(), ap.RightAnchor)

	var results []*TransformResult
	for _, t := range transformations {
		result := ClassifyTransformation(probe, t, expectBackslashConsumption)
		results = append(results, result)
	}

	return results, fuzzedRaw, fullResp, nil
}

// buildResults constructs the output result events.
func (m *Module) buildResults(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	interesting []*TransformResult,
	_ []*TransformResult, // boring results not included in output
	backslashConsumed bool,
) ([]*output.ResultEvent, error) {
	urlx, _ := ctx.URL()

	// Build extracted results list
	var extracted []string
	extracted = append(extracted, fmt.Sprintf("backslashConsumed: %v", backslashConsumed))

	for _, r := range interesting {
		extracted = append(extracted, r.Pretty)
	}

	// Determine severity based on findings
	sev := severity.Medium
	description := "Input transformation detected"

	// Check for high-severity findings (escape sequence interpretation)
	for _, r := range interesting {
		if strings.HasPrefix(r.Probe, "\\") && r.Classification == ClassificationInteresting {
			// Escape sequence was decoded - potential injection
			sev = severity.High
			description = "Escape sequence interpretation detected - potential injection vector"
			break
		}
	}

	// If only backslash consumption, lower severity
	hasOnlyBackslashConsumption := true
	for _, r := range interesting {
		if r.Classification != ClassificationBackslashConsumed {
			hasOnlyBackslashConsumption = false
			break
		}
	}
	if hasOnlyBackslashConsumption && len(interesting) > 0 {
		sev = severity.Low
		description = "Backslash consumption detected - escape bypass possible"
	}

	// Get a sample request/response for the report
	var reqRaw []byte
	var respFull string
	if len(interesting) > 0 {
		// Re-send first interesting probe for the report
		ap := NewAnchoredPayload(interesting[0].Probe)
		fuzzedRaw := ip.BuildRequest([]byte(ap.FullPayload))
		fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
		if err == nil {
			fuzzedReq = fuzzedReq.WithService(ctx.Service())
			resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
			if err == nil {
				reqRaw = fuzzedRaw
				respFull = resp.FullResponseString()
				resp.Close()
			}
		}
	}

	result := &output.ResultEvent{
		URL:              urlx.String(),
		Request:          string(reqRaw),
		Response:         respFull,
		FuzzingParameter: ip.Name(),
		ExtractedResults: extracted,
		Matched:          urlx.String(),
		Info: output.Info{
			Name:        m.Name(),
			Severity:    sev,
			Description: description,
			Reference: []string{
				"https://portswigger.net/research/backslash-powered-scanning",
			},
		},
	}

	return []*output.ResultEvent{result}, nil
}
