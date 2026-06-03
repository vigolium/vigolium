package sqli_error_based

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	httputil "github.com/projectdiscovery/utils/http"
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

		// A WAF/CDN challenge, auth gate, rate limiter, or maintenance page is not
		// the application surfacing a database error — yet its body can carry a
		// token that trips a DBMS error pattern. The motivating false positive: a
		// Cloudflare 429 "challenge" page (Cf-Mitigated: challenge) matched the TiDB
		// signature and was reported as Critical/Certain SQLi. Never read a blocked
		// response as a SQL error.
		if isBlockedResponse(resp) {
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
		if regExp != nil && !m.confirmSQLError(ctx, ip, httpClient, fuzzedRaw, regExp) {
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

// confirmSQLError verifies a matched DBMS error is genuinely introduced by the
// broken-syntax payload rather than ambient. It requires the error to (1)
// reproduce when the payload request is re-sent (not a one-off upstream error)
// and (2) be ABSENT from a fresh fetch of the ORIGINAL value (the control — so an
// error the endpoint returns for any input is rejected even when the captured
// baseline happened to miss it). Fails open on a transport error so a transient
// failure never suppresses a true positive, and drops the finding when either
// re-fetch returns a WAF/rate-limit page: such a page is noise, not a reproduced
// SQL error, and cannot serve as a clean control.
func (m *Module) confirmSQLError(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	payloadRaw []byte,
	regExp *regexp.Regexp,
) bool {
	// (1) Reproducible under the payload, on a genuine (non-blocked) response.
	body, blocked, ok := fetchBody(ctx, httpClient, payloadRaw)
	if !ok {
		return true
	}
	if blocked {
		return false
	}
	if !regExp.MatchString(body) {
		return false
	}

	// (2) Absent from a fresh, non-blocked control fetch of the original value.
	controlRaw := ip.BuildRequest([]byte(ip.BaseValue()))
	controlBody, controlBlocked, ok := fetchBody(ctx, httpClient, controlRaw)
	if !ok {
		return true
	}
	if controlBlocked {
		return false
	}
	return !regExp.MatchString(controlBody)
}

// fetchBody re-issues a raw request and returns its response body and whether the
// response was a WAF/CDN/rate-limit page. ok is false on any parse/HTTP error.
func fetchBody(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, raw []byte) (body string, blocked, ok bool) {
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return "", false, false
	}
	req = req.WithService(ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return "", false, false
	}
	defer resp.Close()
	return resp.Body().String(), isBlockedResponse(resp), true
}

// isBlockedResponse reports whether resp came from a WAF/CDN challenge, auth gate,
// rate limiter, or maintenance page rather than the application. A genuine
// error-based SQLi leak is emitted by the app stack, so a denied or challenged
// response can only yield false matches. It combines the vendor-aware block
// detector (Cloudflare, Akamai, Incapsula, …) with a plain status gate that also
// catches generic WAFs the detector does not recognize.
func isBlockedResponse(resp *httputil.ResponseChain) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}
	if infra.GetBlockDetectionValidator().Validate(resp) != nil {
		return true
	}
	switch resp.Response().StatusCode {
	case 401, 403, 429, 503:
		return true
	}
	return false
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
