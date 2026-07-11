package authz_compare

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/authzutil"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
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
	compareHostnames []string // per-client hostname filter (empty = all hosts)
}

// authorizationTarget records why a request is suitable for a cross-session
// authorization comparison. Replaying every successful endpoint is not useful:
// two sessions are expected to receive different content from personalized
// endpoints and identical content from public endpoints. We therefore limit the
// oracle to self-scoped routes or requests carrying a recognizable object
// reference, then require the response comparison to prove that principal
// identity values were shared across sessions.
type authorizationTarget struct {
	kind       string
	references []string
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
// The optional hostnames slice enables per-hostname filtering: clients with a
// non-empty hostname are only used for requests matching that hostname.
func (m *Module) SetCompareClients(clients []*http.Requester, names []string, hostnames ...[]string) {
	m.compareClients = clients
	m.compareNames = names
	if len(hostnames) > 0 {
		m.compareHostnames = hostnames[0]
	} else {
		m.compareHostnames = make([]string, len(clients))
	}
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
	target, ok := classifyAuthorizationTarget(ctx, scanCtx, urlx.Path)
	if !ok {
		return nil, nil
	}

	// Strip port from host for hostname matching (e.g. "example.com:8080" → "example.com").
	// Uses net.SplitHostPort to correctly handle IPv6 addresses like [::1]:8080.
	hostOnly := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostOnly = h
	}

	var results []*output.ResultEvent
	for i, compareClient := range m.compareClients {
		// Skip compare sessions bound to a different hostname
		if i < len(m.compareHostnames) && m.compareHostnames[i] != "" && m.compareHostnames[i] != hostOnly {
			continue
		}

		compareName := "compare"
		if i < len(m.compareNames) {
			compareName = m.compareNames[i]
		}

		result, err := m.probeWithSession(ctx, compareClient, primary, compareOpts, host, urlStr, compareName, target)
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
	// FullResponse is the primary (authenticated) session's full raw response,
	// retained so a finding can carry the baseline side of the cross-session
	// differential as evidence (the compare-session response is the attack pair).
	FullResponse string
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
			StatusCode:   resp.StatusCode(),
			BodyLength:   len(body),
			Summary:      summary,
			FullResponse: string(resp.Raw()),
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
		StatusCode:   entry.StatusCode,
		BodyLength:   entry.BodyLen,
		Summary:      summary,
		FullResponse: string(entry.Response.Raw()),
	}, nil
}

// probeWithSession replays the request with a compare session and evaluates the result.
func (m *Module) probeWithSession(
	ctx *httpmsg.HttpRequestResponse,
	compareClient *http.Requester,
	primary *responseSummary,
	compareOpts authzutil.CompareOptions,
	host, urlStr, sessionName string,
	target authorizationTarget,
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
	// Copy body + full response before Close: resp.Body()/FullResponse() alias a
	// buffer that Close() returns to a process-global pool, so reading them
	// afterwards is a use-after-free that races with concurrent module execution.
	compareBody := append([]byte(nil), resp.Body().Bytes()...)
	fullResp := resp.FullResponseString()
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

	// Not structurally similar → different error page or resource type
	if !comparison.StructurallyIdentical {
		return nil, nil
	}

	// The security signal is shared principal identity, not merely response shape.
	// Alice receiving Alice's profile while Bob receives Bob's profile is correct
	// isolation even though the two JSON documents are structurally similar. A
	// bypass requires Bob's replay to retain Alice's identity-bearing values.
	sharedIdentity, differingIdentity := compareIdentityFields(primary.Summary.Body, compareBody)
	if len(sharedIdentity) == 0 || len(differingIdentity) > 0 {
		return nil, nil
	}

	ev := modkit.NewEvidenceCollector()
	ev.Add("baseline (primary session)", string(ctx.Request().Raw()), primary.FullResponse)

	desc := fmt.Sprintf(
		"A request targeting %s at %s returned a successful, structurally similar response "+
			"to compare session %s while retaining the primary principal's identity field(s): %s. "+
			"This indicates that the same principal-scoped object was exposed across sessions "+
			"rather than each session receiving its own personalized object.",
		target.kind, urlStr, sessionName, strings.Join(sharedIdentity, ", "),
	)

	return &output.ResultEvent{
		ModuleID:           ModuleID,
		Host:               host,
		URL:                urlStr,
		Matched:            urlStr,
		Request:            string(ctx.Request().Raw()),
		Response:           fullResp,
		AdditionalEvidence: ev.Entries(),
		Info: output.Info{
			Name:        "Cross-Session Object Access / Broken Object Level Authorization",
			Description: desc,
			Severity:    severity.High,
			Confidence:  severity.Firm,
			Tags:        []string{"idor", "bola", "access-control", "api-security", "cross-session"},
			Reference: []string{
				"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
				"https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
				"https://cwe.mitre.org/data/definitions/639.html",
			},
		},
		Metadata: map[string]any{
			"primary_status":         primary.StatusCode,
			"compare_status":         compareStatus,
			"compare_session":        sessionName,
			"body_length_ratio":      comparison.BodyLengthRatio,
			"content_identical":      comparison.ContentIdentical,
			"structural_identical":   comparison.StructurallyIdentical,
			"user_fields_differ":     comparison.UserFieldsDiffer,
			"differing_fields":       comparison.DifferingFields,
			"shared_identity_fields": sharedIdentity,
			"authorization_target":   target.kind,
			"object_references":      target.references,
		},
	}, nil
}

// classifyAuthorizationTarget rejects generic endpoints before cross-session
// replay. A request qualifies when it targets a conventional self-service route
// (/me, /account, /profile, …) or carries a parameter/path value that the shared
// authorization classifier recognizes as an object identifier.
func classifyAuthorizationTarget(
	ctx *httpmsg.HttpRequestResponse,
	scanCtx *modkit.ScanContext,
	path string,
) (authorizationTarget, bool) {
	for _, segment := range strings.Split(strings.ToLower(path), "/") {
		switch segment {
		case "me", "my", "myself", "account", "profile", "settings", "dashboard", "wallet":
			return authorizationTarget{kind: "self-scoped route"}, true
		}
	}

	if scanCtx == nil {
		scanCtx = &modkit.ScanContext{}
	}
	points, err := scanCtx.GetInsertionPoints(ctx.Request().Raw(), ctx.Request().ID(), true)
	if err != nil {
		return authorizationTarget{}, false
	}
	pathSegments := strings.Split(path, "/")
	seen := make(map[string]struct{})
	var references []string
	for _, ip := range points {
		isPath := ip.Type() == httpmsg.INS_URL_PATH_FOLDER || ip.Type() == httpmsg.INS_URL_PATH_FILENAME
		switch ip.Type() {
		case httpmsg.INS_PARAM_URL, httpmsg.INS_PARAM_BODY, httpmsg.INS_PARAM_JSON,
			httpmsg.INS_PARAM_XML, httpmsg.INS_PARAM_XML_ATTR,
			httpmsg.INS_PARAM_MULTIPART_ATTR, httpmsg.INS_URL_PATH_FOLDER,
			httpmsg.INS_URL_PATH_FILENAME:
		default:
			continue
		}
		classification := authzutil.ClassifyParam(ip.Name(), ip.BaseValue(), isPath, pathSegments)
		if !classification.IsObjectID {
			continue
		}
		ref := ip.Name() + "=" + ip.BaseValue()
		if _, exists := seen[ref]; exists {
			continue
		}
		seen[ref] = struct{}{}
		references = append(references, ref)
	}
	if len(references) == 0 {
		return authorizationTarget{}, false
	}
	sort.Strings(references)
	return authorizationTarget{kind: "object-referenced route", references: references}, true
}

var identityFieldNames = map[string]string{
	"owner":          "owner",
	"ownerid":        "owner_id",
	"userid":         "user_id",
	"useruuid":       "user_uuid",
	"accountid":      "account_id",
	"customerid":     "customer_id",
	"memberid":       "member_id",
	"tenantid":       "tenant_id",
	"organizationid": "organization_id",
	"orgid":          "org_id",
	"principalid":    "principal_id",
	"subject":        "subject",
	"sub":            "sub",
	"email":          "email",
	"username":       "username",
}

// compareIdentityFields parses both responses as JSON and compares only
// identity-bearing values. Generic text similarity cannot establish ownership;
// retaining the same owner/account/email value across two authenticated sessions
// can. Any differing identity value is treated as evidence of correct per-session
// personalization and suppresses the finding.
func compareIdentityFields(primaryBody, compareBody []byte) (shared, different []string) {
	primary := extractIdentityFields(primaryBody)
	compare := extractIdentityFields(compareBody)
	if len(primary) == 0 || len(compare) == 0 {
		return nil, nil
	}

	keys := make(map[string]struct{}, len(primary)+len(compare))
	for key := range primary {
		keys[key] = struct{}{}
	}
	for key := range compare {
		keys[key] = struct{}{}
	}
	for key := range keys {
		left, leftOK := primary[key]
		right, rightOK := compare[key]
		if !leftOK || !rightOK || strings.Join(left, "\x00") != strings.Join(right, "\x00") {
			different = append(different, key)
			continue
		}
		shared = append(shared, key)
	}
	sort.Strings(shared)
	sort.Strings(different)
	return shared, different
}

func extractIdentityFields(body []byte) map[string][]string {
	var document any
	if err := json.Unmarshal(body, &document); err != nil {
		return nil
	}
	fields := make(map[string][]string)
	collectIdentityFields(document, fields)
	for key := range fields {
		sort.Strings(fields[key])
	}
	return fields
}

func collectIdentityFields(value any, fields map[string][]string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(strings.ToLower(key))
			if canonical, ok := identityFieldNames[normalized]; ok {
				encoded, err := json.Marshal(child)
				if err == nil && identityValueIsSubstantive(string(encoded)) {
					fields[canonical] = append(fields[canonical], string(encoded))
				}
			}
			collectIdentityFields(child, fields)
		}
	case []any:
		for _, child := range typed {
			collectIdentityFields(child, fields)
		}
	}
}

func identityValueIsSubstantive(value string) bool {
	switch strings.TrimSpace(value) {
	case "", `""`, "null", "false", "0", "[]", "{}":
		return false
	default:
		return true
	}
}
