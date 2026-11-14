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
			// Parameter names reach dynamic column/ORDER BY clauses (opt-in, MISS-15).
			modkit.AllParamTypes|modkit.ParamNameTypes,
		),
		rhm: dedup.LazyDefaultRHM("sqli_error_based"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// VulnClass enables cross-module (param, class) dedup: once any sqli module
// reports a parameter, the others in the class skip it.
func (m *Module) VulnClass() string { return modkit.VulnClassSQLi }

// ClassPriority orders this module within its vuln class (lower runs first).
func (m *Module) ClassPriority() int { return modkit.ClassCostInBand }

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

		// BuildRequest produces well-formed raw, so wrap directly instead
		// of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		// A WAF/CDN challenge, auth gate, rate limiter, or maintenance page is not
		// the application surfacing a database error — yet its body can carry a
		// token that trips a DBMS error pattern. The motivating false positive: a
		// Cloudflare 429 "challenge" page (Cf-Mitigated: challenge) matched the TiDB
		// signature and was reported as Critical/Certain SQLi. Never read a blocked
		// response as a SQL error.
		if infra.IsBlockedResponse(resp) {
			resp.Close()
			continue
		}

		// A 404/redirect means the route never resolved, so no SQL query ran: a
		// DBMS-name or error substring in such a body is page noise, not an
		// injection leak. The motivating false positive: a Salesforce community
		// 404 SPA shell whose inline feature-flag list carries literal DB connector
		// names ("...userHasCockroachDBEnabled...") matched the CockroachDB
		// signature and was reported as Critical/Certain SQLi. Only an application
		// error surface (5xx, or a 2xx/4xx the app returns with the driver message
		// echoed) can carry a genuine error-based leak.
		if !infra.IsErrorSurfaceStatus(resp) {
			resp.Close()
			continue
		}

		dbms, regExp, success := checkBodyContainsErrorMsg(resp.Body().String())
		if !success {
			resp.Close()
			continue
		}

		// A DBMS error already present in the unfuzzed baseline is static page
		// content, not injection: suppress it.
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

		fullResp := resp.FullResponseString()
		resp.Close()

		// Confirm the error is genuinely introduced by the broken-syntax payload:
		// it must reproduce when the payload is re-sent (not a one-off upstream
		// blip) AND be absent from a fresh control fetch of the original value (so a
		// page that returns the pattern for ANY input — a static error string, or
		// one a stale baseline missed — is rejected). Fails open on a transport
		// error so a transient failure never suppresses a true positive.
		if !modkit.ConfirmMatchReproduces(ctx, ip, httpClient, fuzzedRaw, regExp) {
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
			Response:         fullResp,
			FuzzingParameter: ip.Name(),
			Info: output.Info{
				Description: fmt.Sprintf("DBMS: %s", dbms),
			},
		})
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
