package authz_compare

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/authzutil"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
)

// maxProbesPerHost limits the number of cross-session probes per host.
const maxProbesPerHost = 100

// maxBodySize is the upper body size limit (500KB) for response comparison.
const maxBodySize = 500 * 1024

// minBodySize is the minimum body size (50 bytes) for meaningful comparison.
const minBodySize = 50

// Module implements the cross-session authorization comparison scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm              dedup.Lazy[dedup.RequestHashManager]
	ds               dedup.Lazy[dedup.DiskSet]
	compareClients   []*http.Requester
	compareNames     []string
}

// New creates a new cross-session authorization compare module.
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
		rhm: dedup.LazyDefaultRHM("authz_compare"),
		ds:  dedup.LazyDiskSet("authz_compare"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// SetCompareClients configures the HTTP requesters for compare sessions.
// Each requester has its own cookie jar and custom headers matching a session.
func (m *Module) SetCompareClients(clients []*http.Requester, names []string) {
	m.compareClients = clients
	m.compareNames = names
}

// HasCompareClients returns true if compare sessions are configured.
func (m *Module) HasCompareClients() bool {
	return len(m.compareClients) > 0
}

// CanProcess skips this module if no compare sessions are configured.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if !m.HasCompareClients() {
		return false
	}
	return m.BaseActiveModule.CanProcess(ctx)
}

// ScanPerRequest replays the request with each compare session and compares responses.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	// Dedup by request hash (URL + method)
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		if !rhm.ShouldCheck(urlx, ctx.Request(), nil) {
			return nil, nil
		}
	}

	// Per-host rate limit
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil {
		hostKey := utils.Sha1(urlx.Host)
		if _, ok := diskSet.IncrementAndCheck(hostKey, maxProbesPerHost); !ok {
			return nil, nil
		}
	}

	// Get primary session's response (baseline)
	primary, err := m.getPrimaryResponse(ctx, httpClient, scanCtx)
	if err != nil || primary == nil {
		return nil, nil
	}

	// Only compare successful responses
	if primary.StatusCode < 200 || primary.StatusCode >= 300 {
		return nil, nil
	}
	if primary.BodyLength < minBodySize || primary.BodyLength > maxBodySize {
		return nil, nil
	}

	host := urlx.Host
	urlStr := urlx.String()
	compareOpts := authzutil.DefaultCompareOptions()

	var results []*output.ResultEvent
	for i, compareClient := range m.compareClients {
		compareName := "compare"
		if i < len(m.compareNames) {
			compareName = m.compareNames[i]
		}

		result, err := m.probeWithSession(ctx, compareClient, primary, compareOpts, host, urlStr, compareName)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}
		if result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

// responseSummary holds response data for comparison.
type responseSummary struct {
	StatusCode int
	BodyLength int
	Summary    *authzutil.ResponseSummary
}

// getPrimaryResponse obtains the primary session's response.
func (m *Module) getPrimaryResponse(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) (*responseSummary, error) {
	// Prefer existing response
	if ctx.HasResponse() {
		resp := ctx.Response()
		body := resp.Body()
		summary := authzutil.SummarizeResponse(
			resp.StatusCode(),
			resp.Header("Content-Type"),
			body,
		)
		return &responseSummary{
			StatusCode: resp.StatusCode(),
			BodyLength: len(body),
			Summary:    summary,
		}, nil
	}

	// Replay with primary client
	entry, err := scanCtx.GetOrFetchBaseline(ctx, httpClient)
	if err != nil {
		return nil, err
	}
	if entry == nil || entry.Response == nil {
		return nil, nil
	}

	body := entry.Response.Body()
	summary := authzutil.SummarizeResponse(
		entry.StatusCode,
		entry.Response.Header("Content-Type"),
		body,
	)
	return &responseSummary{
		StatusCode: entry.StatusCode,
		BodyLength: entry.BodyLen,
		Summary:    summary,
	}, nil
}

// probeWithSession replays the request with a compare session and evaluates the result.
func (m *Module) probeWithSession(
	ctx *httpmsg.HttpRequestResponse,
	compareClient *http.Requester,
	primary *responseSummary,
	compareOpts authzutil.CompareOptions,
	host, urlStr, sessionName string,
) (*output.ResultEvent, error) {
	// Replay exact same request with compare session's requester
	resp, _, err := compareClient.Execute(ctx, http.Options{})
	if err != nil {
		return nil, err
	}

	// Extract response data before closing
	compareStatus := 0
	var compareContentType string
	var location string
	if resp.Response() != nil {
		compareStatus = resp.Response().StatusCode
		compareContentType = resp.Response().Header.Get("Content-Type")
		location = resp.Response().Header.Get("Location")
	}
	compareBody := resp.Body().Bytes()
	// Defer full response serialization until we know a finding will be emitted
	fullResp := resp.FullResponse()
	resp.Close()

	// Authorization enforced: 401, 403
	if compareStatus == 401 || compareStatus == 403 {
		return nil, nil // properly enforced
	}

	// Not found: 404
	if compareStatus == 404 {
		return nil, nil
	}

	// Login redirect
	if authzutil.IsLoginRedirect(compareStatus, location) {
		return nil, nil // properly enforced
	}

	// Non-2xx → not accessible by compare session
	if compareStatus < 200 || compareStatus >= 300 {
		return nil, nil
	}

	// Soft-denial in body
	if authzutil.ContainsEnforcementString(string(compareBody)) {
		return nil, nil
	}

	// Both 200 — compare content
	compareSummary := authzutil.SummarizeResponse(compareStatus, compareContentType, compareBody)
	comparison := authzutil.CompareResponses(primary.Summary, compareSummary, compareOpts)

	// Identical content → public endpoint, no IDOR
	if comparison.ContentIdentical {
		return nil, nil
	}

	// Not structurally similar → different error page or resource type
	if !comparison.StructurallyIdentical {
		return nil, nil
	}

	// Structurally similar + different content → IDOR/BOLA
	confidence := severity.Firm
	if comparison.UserFieldsDiffer {
		confidence = severity.Certain
	}

	desc := fmt.Sprintf(
		"Request to %s returned structurally similar 200 responses for two different "+
			"authenticated sessions (primary vs %s) with different content "+
			"(body ratio=%.2f), suggesting missing authorization enforcement.",
		urlStr, sessionName, comparison.BodyLengthRatio,
	)
	if len(comparison.DifferingFields) > 0 {
		desc += fmt.Sprintf(" User-specific fields differ: %s.", strings.Join(comparison.DifferingFields, ", "))
	}

	return &output.ResultEvent{
		ModuleID: ModuleID,
		Host:     host,
		URL:      urlStr,
		Matched:  urlStr,
		Request:  string(ctx.Request().Raw()),
		Response: fullResp.String(),
		Info: output.Info{
			Name:        "Cross-Session IDOR / Broken Object Level Authorization",
			Description: desc,
			Severity:    severity.High,
			Confidence:  confidence,
			Tags:        []string{"idor", "bola", "access-control", "api-security", "cross-session"},
			Reference: []string{
				"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
				"https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
				"https://cwe.mitre.org/data/definitions/639.html",
			},
		},
		Metadata: map[string]any{
			"primary_status":       primary.StatusCode,
			"compare_status":       compareStatus,
			"compare_session":      sessionName,
			"body_length_ratio":    comparison.BodyLengthRatio,
			"content_identical":    comparison.ContentIdentical,
			"structural_identical": comparison.StructurallyIdentical,
			"user_fields_differ":   comparison.UserFieldsDiffer,
			"differing_fields":     comparison.DifferingFields,
		},
	}, nil
}
