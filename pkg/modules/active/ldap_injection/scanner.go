package ldap_injection

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// Boolean-based differential thresholds. A wildcard response is only flagged
// when it diverges from the comparison signature by BOTH an absolute and a
// relative margin — status-only flips and small content drift don't count.
const (
	booleanMinAbsoluteDelta = 100
	booleanMinRelativeDelta = 0.30
)

// controlPayload is the "no-match" probe paired with the wildcard. It looks
// like ordinary parameter data (no LDAP metacharacters, no WAF triggers) and
// is overwhelmingly unlikely to match any real LDAP attribute, giving a stable
// reference for what the endpoint returns when the value just doesn't match.
const controlPayload = "vigolium_ldap_nomatch_zZ9qX7cB"

// ldapErrorPatterns are strings that indicate LDAP-related errors in responses.
var ldapErrorPatterns = []string{
	"ldap",
	"javax.naming",
	"invalid dn",
	"bad search filter",
	"unrecognized search filter",
	"invalid attribute",
	"malformed filter",
	"filter error",
	"search filter",
	"ldap_search",
	"ldap_bind",
	"ldap_connect",
	"error in filter",
	"expected filter",
}

// ldapParamNames are parameter name substrings that suggest LDAP involvement.
var ldapParamNames = []string{
	"username", "user", "login", "uid", "cn", "dn", "filter",
	"search", "query", "name", "email", "mail", "sn", "givenname",
	"ou", "group", "member", "objectclass", "base", "scope", "ldap",
	"password", "pass", "pwd",
}

// ldapPayloads are LDAP filter injection strings for error-based detection.
var ldapPayloads = []string{
	")(objectClass=*",
	"*)(uid=*))(|(uid=*",
	"*)(|(objectClass=*",
	"*)(objectClass=*))(&(objectClass=",
	"\\00",
	")(cn=*",
}

// Module implements the LDAP injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new LDAP Injection module.
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
		rhm: dedup.LazyDefaultRHM("ldap_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests LDAP injection in parameters with LDAP-related names.
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

	// Only test parameters whose name suggests LDAP usage
	if !isLDAPRelatedParam(ip.Name()) {
		return nil, nil
	}

	// Dedup by request hash + param via RHM
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Get baseline response body
	var baselineBody string
	var baselineStatus int
	if ctx.Response() != nil {
		baselineBody = ctx.Response().BodyToString()
		baselineStatus = ctx.Response().StatusCode()
	}

	// Skip if baseline already contains LDAP error strings
	if containsLDAPError(baselineBody) {
		return nil, nil
	}

	var results []*output.ResultEvent

	// Error-based detection: inject malformed LDAP filter syntax
	for _, payload := range ldapPayloads {
		fuzzedRaw := ip.BuildRequest([]byte(payload))

		fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		body := resp.Body().String()
		if containsLDAPError(body) {
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Matched:          urlx.String(),
				Request:          string(fuzzedRaw),
				Response:         resp.FullResponseString(),
				FuzzingParameter: ip.Name(),
				ExtractedResults: []string{findLDAPError(body)},
				Info: output.Info{
					Name:        "LDAP Injection: error-based",
					Description: fmt.Sprintf("LDAP error triggered by injecting %q into parameter %q", payload, ip.Name()),
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	// Boolean-based detection: send a TRUE-like wildcard probe and a
	// "no-match" control probe alongside the baseline. The wildcard is only
	// flagged if its response is *uniquely* different — substantially diverging
	// from BOTH the baseline AND the control. Comparing against a control
	// filters out endpoints that simply reflect any user input (search forms
	// echoing the query, dynamic listings, etc.), where wildcard and control
	// would both differ from baseline by similar amounts but look like each
	// other. Genuine LDAP filter expansion produces a wildcard response that
	// no normal value (control) can reproduce.
	baselineSig := newResponseSignature(baselineStatus, baselineBody)

	wildcardRaw := ip.BuildRequest([]byte("*"))
	wildcardSig, wildcardFull, ok := m.probeSignature(ctx, httpClient, wildcardRaw)
	if !ok {
		return results, nil
	}

	controlRaw := ip.BuildRequest([]byte(controlPayload))
	controlSig, _, ok := m.probeSignature(ctx, httpClient, controlRaw)
	if !ok {
		return results, nil
	}

	// Suppress when either probe is blocked by a WAF/auth/rate-limit layer but
	// the baseline wasn't — the gateway is reacting to the probe value, not the
	// app interpreting it as an LDAP filter. The block page also explains any
	// body-length delta.
	if !isAccessDenied(baselineStatus) {
		if isAccessDenied(wildcardSig.statusCode) || isAccessDenied(controlSig.statusCode) {
			return results, nil
		}
	}

	// Require the wildcard response to diverge substantially from BOTH the
	// baseline AND the control. Both deltas must clear the absolute+relative
	// gate, so a single anomalous probe (e.g., transient 5xx) can't carry the
	// finding on its own.
	if !hasSubstantialBodyDifference(wildcardSig, baselineSig) {
		return results, nil
	}
	if !hasSubstantialBodyDifference(wildcardSig, controlSig) {
		return results, nil
	}

	results = append(results, &output.ResultEvent{
		URL:              urlx.String(),
		Matched:          urlx.String(),
		Request:          string(wildcardRaw),
		Response:         wildcardFull,
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{fmt.Sprintf(
			"baseline_status=%d baseline_len=%d wildcard_status=%d wildcard_len=%d control_status=%d control_len=%d",
			baselineSig.statusCode, baselineSig.bodyLength,
			wildcardSig.statusCode, wildcardSig.bodyLength,
			controlSig.statusCode, controlSig.bodyLength,
		)},
		Info: output.Info{
			Name:        "LDAP Injection: boolean-based",
			Description: fmt.Sprintf("Wildcard injection in parameter %q produced a response that differs substantially from both the baseline and a no-match control, suggesting LDAP filter manipulation", ip.Name()),
		},
	})

	return results, nil
}

// responseSignature captures key response attributes for differential comparison.
type responseSignature struct {
	statusCode int
	bodyLength int
	bodyHash   [32]byte
}

func newResponseSignature(statusCode int, body string) responseSignature {
	return responseSignature{
		statusCode: statusCode,
		bodyLength: len(body),
		bodyHash:   sha256.Sum256([]byte(body)),
	}
}

// hasSubstantialBodyDifference reports whether two responses diverge by both an
// absolute (>booleanMinAbsoluteDelta bytes) and a relative
// (>=booleanMinRelativeDelta) margin. Status-code flips alone are not enough —
// the body content has to actually change in a meaningful way, which is what
// LDAP filter manipulation produces (filter expanded → more matched records →
// larger or structurally different page).
func hasSubstantialBodyDifference(a, b responseSignature) bool {
	if a.bodyHash == b.bodyHash {
		return false
	}
	diff := a.bodyLength - b.bodyLength
	if diff < 0 {
		diff = -diff
	}
	if diff <= booleanMinAbsoluteDelta {
		return false
	}
	maxLen := a.bodyLength
	if b.bodyLength > maxLen {
		maxLen = b.bodyLength
	}
	if maxLen == 0 {
		return false
	}
	return float64(diff)/float64(maxLen) >= booleanMinRelativeDelta
}

// probeSignature sends a single fuzzed request and returns its response
// signature along with the full response string. The boolean ok is false when
// the request couldn't be sent or the host became unresponsive — callers
// should abort the boolean-based pass in that case rather than treat the
// missing probe as evidence.
func (m *Module) probeSignature(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	rawReq []byte,
) (responseSignature, string, bool) {
	req, err := httpmsg.ParseRawRequest(string(rawReq))
	if err != nil {
		return responseSignature{}, "", false
	}
	req = req.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return responseSignature{}, "", false
		}
		return responseSignature{}, "", false
	}
	defer resp.Close()

	body := resp.Body().String()
	sig := newResponseSignature(resp.Response().StatusCode, body)
	full := resp.FullResponseString()
	return sig, full, true
}

// isAccessDenied returns true for status codes that indicate the request was
// rejected by an auth/WAF/rate-limit layer rather than served by the app.
func isAccessDenied(status int) bool {
	return status == 401 || status == 403 || status == 429 || status == 503
}

// isLDAPRelatedParam checks if a parameter name suggests LDAP involvement.
func isLDAPRelatedParam(name string) bool {
	nameLower := strings.ToLower(name)
	for _, p := range ldapParamNames {
		if strings.Contains(nameLower, p) {
			return true
		}
	}
	return false
}

// containsLDAPError checks if the response body contains LDAP error indicators.
func containsLDAPError(body string) bool {
	bodyLower := strings.ToLower(body)
	for _, p := range ldapErrorPatterns {
		if strings.Contains(bodyLower, p) {
			return true
		}
	}
	return false
}

// findLDAPError returns the first matching LDAP error pattern found in the body.
func findLDAPError(body string) string {
	bodyLower := strings.ToLower(body)
	for _, p := range ldapErrorPatterns {
		if strings.Contains(bodyLower, p) {
			return p
		}
	}
	return ""
}
