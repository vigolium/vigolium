package sqli_error_based

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
	"github.com/vigolium/vigolium/pkg/utils"
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
			modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		rhm: dedup.LazyDefaultRHM("sqli_error_based"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests a single insertion point for SQL injection.
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

	fuzzingChars := []string{`b'b"b\`, `b)b\`}
	var results []*output.ResultEvent

	for _, char := range fuzzingChars {
		var payload string
		paramValue := ip.BaseValue()
		if strings.Contains(paramValue, "@") || strings.Contains(paramValue, "%40") {
			payload = fmt.Sprintf(`%s%s@gmail.com`, utils.RandomString(10), char)
		} else {
			payload = fmt.Sprintf(`%s%s`, paramValue, char)
		}

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

		if dbms, regExp, success := checkBodyContainsErrorMsg(resp.Body().String()); success {
			// Some case the original response match some keywords
			// In this case we need to check if the response contains the error message
			var originalResponseBody string
			if ctx.Response() == nil {
				originalResponseBody = getResponseBodyIfNotResponsive(ctx, httpClient)
			} else {
				originalResponseBody = ctx.Response().BodyToString()
			}
			if regExp != nil && originalResponseBody != "" && regExp.MatchString(originalResponseBody) {
				resp.Close()
				continue
			}

			// Record the identified backend for this host so the blind SQLi
			// modules can prioritize matching payloads (DBMS narrowing).
			if dbType := infra.NormalizeDBMS(dbms); dbType != "" {
				scanCtx.MarkTech(urlx.Host, infra.DBMSTechTag(dbType))
			}

			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(fuzzedRaw),
				Response:         resp.FullResponseString(),
				FuzzingParameter: ip.Name(),
				Info: output.Info{
					Description: fmt.Sprintf("DBMS: %s", dbms),
				},
			})
		}
		resp.Close()
	}

	return results, nil
}

func getResponseBodyIfNotResponsive(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) string {
	if ctx.Response() != nil {
		return ctx.Response().BodyToString()
	}
	resp, _, err := httpClient.Execute(ctx, http.Options{})
	if err != nil {
		return ""
	}
	defer resp.Close()
	return resp.Body().String()
}
