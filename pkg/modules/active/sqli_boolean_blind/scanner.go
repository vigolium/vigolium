package sqli_boolean_blind

import (
	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
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
		rhm: dedup.LazyDefaultRHM("sqli_boolean_blind"),
	}
	m.ModuleTags = ModuleTags
	return m
}

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

	// Create all insertion points (uses cached provider when available)
	points, err := scanCtx.GetInsertionPoints(ctx.Request().Raw(), ctx.Request().ID(), true)
	if err != nil {
		return results, errors.Wrap(err, "failed to create insertion points")
	}

	// Filter out already checked insertion points
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		points = rhm.GetNotCheckedInsertionPoints(urlx, ctx.Request(), points)
	}
	if len(points) == 0 {
		return results, nil
	}

ipScan:
	for _, ip := range points {
		baseValue := ip.BaseValue()

		// Get baseline signature by sending the original unmodified value.
		// This lets us detect cases where both TRUE and FALSE payloads differ
		// from baseline in the same way (e.g., mangled header values causing
		// different responses due to syntax breakage, not SQL logic).
		_, baselineSig, err := m.sendPayload(ctx, httpClient, ip, baseValue)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		payloads := getPayloadsForValue(baseValue)

		for _, pair := range payloads {
			truePayload := baseValue + pair.trueVal
			falsePayload := baseValue + pair.falseVal

			result, err := m.testPayloadPair(ctx, httpClient, ip, truePayload, falsePayload, baselineSig)
			if err != nil {
				if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
					return results, nil
				}
				continue
			}

			if result != nil {
				result.URL = urlx.String()
				results = append(results, result)
				continue ipScan
			}
		}
	}

	return results, nil
}

// testPayloadPair implements the verification algorithm with baseline comparison.
func (m *Module) testPayloadPair(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	truePayload, falsePayload string,
	baselineSig responseSignature,
) (*output.ResultEvent, error) {
	// Step 1: Send TRUE payload
	_, trueSig1, err := m.sendPayload(ctx, httpClient, ip, truePayload)
	if err != nil {
		return nil, err
	}

	// Step 2: Send FALSE payload
	_, falseSig1, err := m.sendPayload(ctx, httpClient, ip, falsePayload)
	if err != nil {
		return nil, err
	}

	// Step 3: Check if TRUE and FALSE produce different responses
	if !isDifferent(trueSig1, falseSig1) {
		return nil, nil
	}

	// Step 4: Verify the differential is driven by SQL logic, not just syntax breakage.
	// If both TRUE and FALSE differ from the baseline in the same direction (both differ
	// from baseline), but neither matches the baseline, the injection likely just broke
	// the value (e.g., mangled ETag/header causing different error pages with dynamic content).
	// At least one of TRUE/FALSE must match the baseline to confirm SQL-driven behavior.
	trueSimilarToBaseline := isSimilar(trueSig1, baselineSig)
	falseSimilarToBaseline := isSimilar(falseSig1, baselineSig)
	if !trueSimilarToBaseline && !falseSimilarToBaseline {
		return nil, nil // Both differ from baseline — likely syntax breakage, not SQLi
	}

	// Step 5: Confirm TRUE is consistent
	_, trueSig2, err := m.sendPayload(ctx, httpClient, ip, truePayload)
	if err != nil {
		return nil, err
	}
	if !isSimilar(trueSig1, trueSig2) {
		return nil, nil // Unstable TRUE response
	}

	// Step 6: Confirm FALSE is consistent
	_, falseSig2, err := m.sendPayload(ctx, httpClient, ip, falsePayload)
	if err != nil {
		return nil, err
	}
	if !isSimilar(falseSig1, falseSig2) {
		return nil, nil // Unstable FALSE response
	}

	// Step 7: Re-verify baseline hasn't drifted (catches dynamic content noise).
	_, baselineSig2, err := m.sendPayload(ctx, httpClient, ip, ip.BaseValue())
	if err != nil {
		return nil, err
	}
	if !isSimilar(baselineSig, baselineSig2) {
		return nil, nil // Baseline is unstable — responses are too dynamic to trust
	}

	// Step 8: Final guardrail — both TRUE and FALSE must share baseline's status
	// code (typically 200) AND show a substantial body-length differential.
	// Filters out false positives where the only differential is a status flip
	// (e.g., baseline 200 → FALSE 302 redirect) without real SQL-driven content
	// change. Real boolean-based SQLi manifests as content differences within the
	// same successful response status.
	if trueSig1.statusCode != baselineSig.statusCode || falseSig1.statusCode != baselineSig.statusCode {
		return nil, nil
	}
	if !hasSubstantialBodyDifference(trueSig1, falseSig1) {
		return nil, nil
	}

	// All checks passed — confirmed blind SQLi
	fuzzedRaw := ip.BuildRequest([]byte(truePayload))
	return &output.ResultEvent{
		Request:          string(fuzzedRaw),
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{truePayload, falsePayload},
		Info: output.Info{
			Description: "Boolean-based blind SQL injection confirmed via TRUE/FALSE response differential with baseline verification",
		},
	}, nil
}

// sendPayload sends a payload through an insertion point and returns the response signature.
func (m *Module) sendPayload(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	payload string,
) (string, responseSignature, error) {
	fuzzedRaw := ip.BuildRequest([]byte(payload))

	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return "", responseSignature{}, err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	if err != nil {
		return "", responseSignature{}, err
	}
	defer resp.Close()

	if resp.Response() == nil {
		return "", responseSignature{}, nil
	}

	body := resp.FullResponse().String()
	sig := newResponseSignature(resp.Response().StatusCode, body)
	return body, sig, nil
}
