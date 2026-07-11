package fastapi_auth_inconsistency

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/authzutil"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

type openAPISpec struct {
	Paths    map[string]map[string]operation `json:"paths"`
	Security []map[string][]string           `json:"security"`
}

type operation struct {
	Security    *[]map[string][]string `json:"security"`
	Summary     string                 `json:"summary"`
	Description string                 `json:"description"`
	OperationID string                 `json:"operationId"`
	Tags        []string               `json:"tags"`
}

type apiOperation struct {
	path        string
	method      string
	operationID string
	summary     string
	reason      string
}

type runtimeBypass struct {
	detail   string
	evidence []string
}

// Module implements the FastAPI Auth Inconsistency active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new FastAPI Auth Inconsistency module.
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
		ds: dedup.LazyDiskSet("fastapi_auth_inconsistency"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil && ctx.Response() != nil
}

// ScanPerRequest separates documentation observations from behavioral auth
// bypasses. Missing OpenAPI security metadata does not prove a route lacks
// middleware or in-function authorization, and a 422 only proves validation ran.
// A finding is emitted only when an operation declared protected returns stable,
// substantive data to a requester with a fresh cookie jar and no credentials.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}
	host := service.Host()
	if diskSet := m.ds.Get(scanCtx.DedupMgr()); diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil, nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, "/openapi.json")
	if err != nil {
		return nil, nil
	}
	modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "Accept", "application/json")
	if err != nil {
		return nil, nil
	}
	schemaReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())
	resp, _, err := httpClient.Execute(schemaReq, http.Options{NoClustering: true})
	if err != nil {
		return nil, nil
	}
	defer resp.Close()
	if resp.Response() == nil || resp.Response().StatusCode != 200 {
		return nil, nil
	}

	var spec openAPISpec
	if err := json.Unmarshal(resp.Body().Bytes(), &spec); err != nil || len(spec.Paths) == 0 {
		return nil, nil
	}
	unprotected, protected := classifyOperations(spec)

	var bypasses []runtimeBypass
	if len(protected) > 0 {
		anonymousClient, cloneErr := httpClient.CloneWithoutCredentials()
		if cloneErr == nil {
			const maxRuntimeChecks = 8
			attempts := 0
			for _, op := range protected {
				if len(bypasses) >= 3 || attempts >= maxRuntimeChecks {
					break
				}
				attempts++
				if bypass := verifyDeclaredProtection(ctx, anonymousClient, op); bypass != nil {
					bypasses = append(bypasses, *bypass)
				}
			}
		}
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + "/openapi.json"
	if len(bypasses) > 0 {
		var extracted, evidence []string
		for _, bypass := range bypasses {
			extracted = append(extracted, bypass.detail)
			evidence = append(evidence, bypass.evidence...)
		}
		return []*output.ResultEvent{{
			ModuleID:           ModuleID,
			URL:                targetURL,
			Matched:            targetURL,
			Request:            string(modifiedRaw),
			Response:           resp.FullResponseString(),
			AdditionalEvidence: evidence,
			ExtractedResults:   extracted,
			RecordKind:         output.RecordKindFinding,
			EvidenceGrade:      output.EvidenceGradeBypass,
			Info: output.Info{
				Name:        fmt.Sprintf("FastAPI Runtime Auth Inconsistency: %d protected operation(s)", len(bypasses)),
				Description: "OpenAPI declares these operations protected, but repeated requests from an isolated credential-free client returned stable, substantive application data. This is a behavioral mismatch with the documented security requirement.",
				Severity:    ModuleSeverity,
				Confidence:  ModuleConfidence,
				Tags:        []string{"python", "fastapi", "openapi", "auth", "misconfiguration"},
				Reference:   []string{"https://fastapi.tiangolo.com/tutorial/security/"},
			},
		}}, nil
	}

	if len(unprotected) == 0 {
		return nil, nil
	}
	extracted := make([]string, 0, len(unprotected))
	for _, op := range unprotected {
		detail := fmt.Sprintf("%s %s", op.method, op.path)
		if op.operationID != "" {
			detail += fmt.Sprintf(" (operationId: %s)", op.operationID)
		}
		extracted = append(extracted, detail+" - "+op.reason)
	}
	return []*output.ResultEvent{{
		ModuleID:         ModuleID,
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: extracted,
		RecordKind:       output.RecordKindObservation,
		EvidenceGrade:    output.EvidenceGradeObservation,
		Info: output.Info{
			Name:        fmt.Sprintf("FastAPI Security-Metadata Observation: %d sensitive operation(s)", len(unprotected)),
			Description: "The OpenAPI document does not declare security for these potentially sensitive operations. This is documentation/configuration evidence only: global middleware, dependencies, or in-function checks may still enforce authorization, and public operations may be intentional.",
			Severity:    severity.Info,
			Confidence:  severity.Tentative,
			Tags:        []string{"python", "fastapi", "openapi", "auth", "observation"},
			Reference:   []string{"https://fastapi.tiangolo.com/tutorial/security/"},
		},
	}}, nil
}

func classifyOperations(spec openAPISpec) (unprotected, protected []apiOperation) {
	hasGlobalSecurity := len(spec.Security) > 0
	for path, methods := range spec.Paths {
		if !strings.HasPrefix(strings.ToLower(path), "/api") {
			continue
		}
		for method, op := range methods {
			method = strings.ToUpper(method)
			if !isHTTPMethod(method) || !operationLooksSensitive(path, method, op) {
				continue
			}
			candidate := apiOperation{path: path, method: method, operationID: op.OperationID, summary: op.Summary}
			switch {
			case op.Security != nil && len(*op.Security) == 0:
				candidate.reason = "explicitly declares public access (security: [])"
				unprotected = append(unprotected, candidate)
			case op.Security != nil && len(*op.Security) > 0:
				candidate.reason = "operation declares a security requirement"
				protected = append(protected, candidate)
			case hasGlobalSecurity:
				candidate.reason = "inherits the global security requirement"
				protected = append(protected, candidate)
			default:
				candidate.reason = "no operation-level or global security metadata"
				unprotected = append(unprotected, candidate)
			}
		}
	}
	return unprotected, protected
}

func isHTTPMethod(method string) bool {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE":
		return true
	default:
		return false
	}
}

func operationLooksSensitive(path, method string, op operation) bool {
	if method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE" {
		return true
	}
	haystack := strings.ToLower(strings.Join(append([]string{path, op.OperationID, op.Summary, op.Description}, op.Tags...), " "))
	for _, safe := range []string{"/health", "/status", "/ping", "/version", "/metrics"} {
		if strings.Contains(strings.ToLower(path), safe) {
			return false
		}
	}
	for _, marker := range []string{
		"admin", "user", "account", "profile", "customer", "tenant", "member",
		"token", "secret", "password", "credential", "session", "permission", "role",
		"payment", "billing", "invoice", "order", "internal", "private", "audit",
	} {
		if strings.Contains(haystack, marker) {
			return true
		}
	}
	return false
}

func verifyDeclaredProtection(ctx *httpmsg.HttpRequestResponse, client *http.Requester, op apiOperation) *runtimeBypass {
	if op.method != "GET" && op.method != "HEAD" {
		return nil // never replay state-changing operations for confirmation
	}
	if strings.ContainsAny(op.path, "{}") {
		return nil
	}
	raw, ok := anonymousOperationRequest(ctx, op)
	if !ok {
		return nil
	}
	first := fetchRuntimeProbe(ctx, client, raw)
	second := fetchRuntimeProbe(ctx, client, raw)
	if first == nil || second == nil || !first.substantive || !second.substantive {
		return nil
	}
	if first.status != second.status || !modkit.BodiesSimilar(first.body, second.body) {
		return nil
	}
	return &runtimeBypass{
		detail:   fmt.Sprintf("Confirmed anonymous data response: %s %s returned stable %d JSON despite %s", op.method, op.path, first.status, op.reason),
		evidence: []string{first.request, first.response, second.request, second.response},
	}
}

func anonymousOperationRequest(ctx *httpmsg.HttpRequestResponse, op apiOperation) ([]byte, bool) {
	raw, err := httpmsg.SetMethod(ctx.Request().Raw(), op.method)
	if err != nil {
		return nil, false
	}
	raw, err = httpmsg.SetPath(raw, op.path)
	if err != nil {
		return nil, false
	}
	for _, header := range []string{
		"Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key", "Api-Key",
		"X-Api-Token", "X-Auth-Token", "X-Access-Token", "X-Session-Token",
	} {
		raw, err = httpmsg.RemoveHeader(raw, header)
		if err != nil {
			return nil, false
		}
	}
	if op.method == "GET" || op.method == "HEAD" {
		raw, err = httpmsg.SetBody(raw, nil)
		if err != nil {
			return nil, false
		}
	}
	return raw, true
}

type runtimeProbe struct {
	status      int
	body        string
	request     string
	response    string
	substantive bool
}

func fetchRuntimeProbe(ctx *httpmsg.HttpRequestResponse, client *http.Requester, raw []byte) *runtimeProbe {
	request := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := client.Execute(request, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil
	}
	defer resp.Close()
	if resp.Response() == nil {
		return nil
	}
	status := resp.Response().StatusCode
	body := resp.Body().String()
	contentType := resp.Response().Header.Get("Content-Type")
	return &runtimeProbe{
		status:      status,
		body:        body,
		request:     string(raw),
		response:    resp.FullResponseString(),
		substantive: status >= 200 && status < 300 && substantiveJSONResponse(contentType, body),
	}
}

func substantiveJSONResponse(contentType, body string) bool {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" || authzutil.ContainsEnforcementString(trimmed) {
		return false
	}
	if !strings.Contains(strings.ToLower(contentType), "json") && !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return false
	}
	var value any
	if err := json.Unmarshal([]byte(trimmed), &value); err != nil {
		return false
	}
	return jsonValueContainsApplicationData(value)
}

func jsonValueContainsApplicationData(value any) bool {
	switch typed := value.(type) {
	case []any:
		return len(typed) > 0
	case map[string]any:
		for key, child := range typed {
			switch strings.ToLower(key) {
			case "detail", "error", "errors", "message", "status", "code":
				continue
			}
			if jsonValueSubstantive(child) {
				return true
			}
		}
	}
	return false
}

func jsonValueSubstantive(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(typed) != ""
	case bool:
		return typed
	case float64:
		return true
	case []any:
		return len(typed) > 0
	case map[string]any:
		return len(typed) > 0
	default:
		return false
	}
}
