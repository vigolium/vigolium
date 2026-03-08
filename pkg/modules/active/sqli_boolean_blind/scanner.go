package sqli_boolean_blind

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/pkg/errors"
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

	// Create all insertion points
	points, err := httpmsg.CreateAllInsertionPoints(ctx.Request().Raw(), true)
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

		// Handle email-style values: inject before the @ portion
		emailPrefix := ""
		if strings.Contains(baseValue, "@") {
			parts := strings.SplitN(baseValue, "@", 2)
			emailPrefix = parts[0]
			baseValue = emailPrefix
		}

		payloads := getPayloadsForValue(baseValue)

		for _, pair := range payloads {
			truePayload := baseValue + pair.trueVal
			falsePayload := baseValue + pair.falseVal

			// If email, append the @domain back
			if emailPrefix != "" {
				atPart := "@" + strings.SplitN(ip.BaseValue(), "@", 2)[1]
				truePayload += atPart
				falsePayload += atPart
			}

			result, err := m.testPayloadPair(ctx, httpClient, ip, truePayload, falsePayload)
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

// testPayloadPair implements the triple-verification algorithm.
func (m *Module) testPayloadPair(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	truePayload, falsePayload string,
) (*output.ResultEvent, error) {
	// Step 1: Send TRUE payload
	trueResp1, trueSig1, err := m.sendPayload(ctx, httpClient, ip, truePayload)
	if err != nil {
		return nil, err
	}
	_ = trueResp1

	// Step 2: Send FALSE payload
	falseResp1, falseSig1, err := m.sendPayload(ctx, httpClient, ip, falsePayload)
	if err != nil {
		return nil, err
	}
	_ = falseResp1

	// Step 3: Check if TRUE and FALSE produce different responses
	if !isDifferent(trueSig1, falseSig1) {
		return nil, nil
	}

	// Step 4: Confirm TRUE is consistent
	_, trueSig2, err := m.sendPayload(ctx, httpClient, ip, truePayload)
	if err != nil {
		return nil, err
	}
	if !isSimilar(trueSig1, trueSig2) {
		return nil, nil // Unstable TRUE response
	}

	// Step 5: Confirm FALSE is consistent
	_, falseSig2, err := m.sendPayload(ctx, httpClient, ip, falsePayload)
	if err != nil {
		return nil, err
	}
	if !isSimilar(falseSig1, falseSig2) {
		return nil, nil // Unstable FALSE response
	}

	// Step 6: Send original value and verify it matches TRUE
	origValue := ip.BaseValue()
	_, origSig, err := m.sendPayload(ctx, httpClient, ip, origValue)
	if err != nil {
		return nil, err
	}
	if !isSimilar(trueSig1, origSig) {
		return nil, nil // Original doesn't match TRUE behavior
	}

	// All checks passed — confirmed blind SQLi
	fuzzedRaw := ip.BuildRequest([]byte(truePayload))
	return &output.ResultEvent{
		Request:          string(fuzzedRaw),
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{truePayload, falsePayload},
		Info: output.Info{
			Description: "Boolean-based blind SQL injection confirmed via TRUE/FALSE response differential",
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
