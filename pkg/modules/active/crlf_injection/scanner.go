package crlf_injection

import (
	"fmt"
	"regexp"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
)

type Module struct {
	modkit.BaseActiveModule
	randomStr           string
	payloads            []string
	patternCookieTamper *regexp.Regexp
	rhm                 dedup.Lazy[dedup.RequestHashManager]
}

func New() *Module {
	randomStr := "Tamper=" + utils.RandomString(12)
	payloads := []string{
		"Set-cookie: " + randomStr,
		"any\r\nSet-cookie: " + randomStr,
		"any?\r\nSet-cookie: " + randomStr,
		"any\nSet-cookie: " + randomStr,
		"any?\nSet-cookie: " + randomStr,
		"any\r\nSet-cookie: " + randomStr + "\r\n",
		"any?\r\nSet-cookie: " + randomStr + "\r\n",
		"%0d%0aSet-cookie: " + randomStr,
		"%0D%0ASet-cookie: " + randomStr,
		"%250d%250aSet-cookie: " + randomStr,
	}

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
			modkit.URLParamTypes, // CRLF typically targets URL params
		),
		randomStr:           randomStr,
		payloads:            payloads,
		patternCookieTamper: regexp.MustCompile("(?mi)\\nSet-cookie: " + randomStr),
		rhm:                 dedup.LazyDefaultRHM("crlf_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests a single insertion point for CRLF injection.
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

	var results []*output.ResultEvent

	for _, payload := range m.payloads {
		// Append payload to original value
		fullPayload := ip.BaseValue() + payload

		// Build fuzzed request with payload
		fuzzedRaw := ip.BuildRequest([]byte(fullPayload))

		// Parse the fuzzed raw request to HttpRequestResponse
		fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
		if err != nil {
			continue
		}

		// Copy HttpService from original request
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		matches := m.patternCookieTamper.FindStringSubmatch(resp.Headers().String())
		if matches != nil {
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(fuzzedRaw),
				Response:         resp.Headers().String(),
				FuzzingParameter: ip.Name(),
				ExtractedResults: []string{payload},
				Info: output.Info{
					Description: fmt.Sprintf("String reflected in %q", matches),
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}
