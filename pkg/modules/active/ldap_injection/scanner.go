package ldap_injection

import (
	"fmt"
	"math"
	"strings"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/pkg/errors"
)

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
	var baselineLen int
	if ctx.Response() != nil {
		baselineBody = ctx.Response().BodyToString()
		baselineStatus = ctx.Response().StatusCode()
		baselineLen = len(baselineBody)
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
				Response:         resp.FullResponse().String(),
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

	// Boolean-based detection: inject wildcard and compare response
	wildcardRaw := ip.BuildRequest([]byte("*"))
	wildcardReq, err := httpmsg.ParseRawRequest(string(wildcardRaw))
	if err != nil {
		return results, nil
	}
	wildcardReq = wildcardReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(wildcardReq, http.Options{})
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return results, nil
		}
		return results, nil
	}

	wildcardBody := resp.Body().String()
	wildcardStatus := resp.Response().StatusCode
	wildcardLen := len(wildcardBody)

	// Check for significant differences suggesting LDAP filter manipulation
	statusDiff := wildcardStatus != baselineStatus
	lenDiff := baselineLen > 0 && math.Abs(float64(wildcardLen-baselineLen))/float64(baselineLen) > 0.3

	if statusDiff || lenDiff {
		results = append(results, &output.ResultEvent{
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(wildcardRaw),
			Response:         resp.FullResponse().String(),
			FuzzingParameter: ip.Name(),
			ExtractedResults: []string{fmt.Sprintf("baseline_status=%d wildcard_status=%d baseline_len=%d wildcard_len=%d", baselineStatus, wildcardStatus, baselineLen, wildcardLen)},
			Info: output.Info{
				Name:        "LDAP Injection: boolean-based",
				Description: fmt.Sprintf("Wildcard injection in parameter %q produced a significantly different response, suggesting LDAP filter manipulation", ip.Name()),
			},
		})
	}
	resp.Close()

	return results, nil
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
