package reflected_ssti

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/pkg/errors"
)

type Module struct {
	modkit.BaseActiveModule
	result   string
	payloads []string
	rhm      dedup.Lazy[dedup.RequestHashManager]
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
			modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		result:   "3987280",
		payloads: buildPayloads(1970, 2024),
		rhm:      dedup.LazyDefaultRHM("reflected_ssti"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests a single insertion point for SSTI.
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
		// Build fuzzed request with payload
		fuzzedRaw := ip.BuildRequest([]byte(payload))

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

		if strings.Contains(resp.Body().String(), m.result) {
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(fuzzedRaw),
				Response:         resp.FullResponse().String(),
				FuzzingParameter: ip.Name(),
				ExtractedResults: []string{ip.BaseValue()},
			})
		}
		resp.Close()
	}

	return results, nil
}

func buildPayloads(firstNum, lastNum int) []string {
	return []string{
		fmt.Sprintf("${{%d*%d}}", firstNum, lastNum),
		fmt.Sprintf("{{%d*%d}}", firstNum, lastNum),
		fmt.Sprintf("<%%=%d*%d%%>", firstNum, lastNum),
		fmt.Sprintf("{%d*%d}", firstNum, lastNum),
		fmt.Sprintf("{{{%d*%d}}}", firstNum, lastNum),
		fmt.Sprintf("${{%d*%d}}", firstNum, lastNum),
		fmt.Sprintf("#{%d*%d}", firstNum, lastNum),
		fmt.Sprintf("[[%d*%d]]", firstNum, lastNum),
		fmt.Sprintf("{{=%d*%d}}", firstNum, lastNum),
		fmt.Sprintf("[[${%d*%d}]]", firstNum, lastNum),
		fmt.Sprintf("${xyz|%d*%d}", firstNum, lastNum),
		fmt.Sprintf("#set($x=%d*%d)${x}", firstNum, lastNum),
		fmt.Sprintf("@(%d*%d)", firstNum, lastNum),
		fmt.Sprintf("{@%d*%d}", firstNum, lastNum),
		fmt.Sprintf("${%d*%d}", firstNum, lastNum),
	}
}
