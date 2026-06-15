package fastapi_auth_inconsistency

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
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
	OperationID string                 `json:"operationId"`
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
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

// ScanPerRequest fetches the OpenAPI schema and identifies unprotected operations.
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

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	// Fetch /openapi.json.
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

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil, nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil, nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil, nil
	}

	if resp.Response().StatusCode != 200 {
		return nil, nil
	}

	body := resp.Body().String()

	var spec openAPISpec
	if err := json.Unmarshal([]byte(body), &spec); err != nil {
		return nil, nil
	}

	if len(spec.Paths) == 0 {
		return nil, nil
	}

	hasGlobalSecurity := len(spec.Security) > 0

	type unprotectedOp struct {
		path        string
		method      string
		operationID string
		summary     string
		reason      string
	}

	var unprotected []unprotectedOp

	for path, methods := range spec.Paths {
		for method, op := range methods {
			if !strings.HasPrefix(path, "/api") {
				continue
			}

			if op.Security != nil {
				// Operation explicitly defines security.
				if len(*op.Security) == 0 {
					// security: [] explicitly opts out of global security.
					unprotected = append(unprotected, unprotectedOp{
						path:        path,
						method:      strings.ToUpper(method),
						operationID: op.OperationID,
						summary:     op.Summary,
						reason:      "explicitly opts out of security (security: [])",
					})
				}
				// If security is non-empty, the operation is protected.
				continue
			}

			// Operation has no security field.
			if !hasGlobalSecurity {
				unprotected = append(unprotected, unprotectedOp{
					path:        path,
					method:      strings.ToUpper(method),
					operationID: op.OperationID,
					summary:     op.Summary,
					reason:      "no security defined at operation or global level",
				})
			}
		}
	}

	if len(unprotected) == 0 {
		return nil, nil
	}

	// Verify the unprotected operations by calling them without auth. Only a 2xx or
	// a FastAPI 422 validation error proves the endpoint is actually REACHED
	// unauthenticated (see verifyUnprotected); templated paths (/api/x/{id}) can't be
	// called literally, so they are skipped. Attempts are bounded so a large spec
	// can't fan out into a request flood.
	const (
		maxVerifyAttempts = 8
		maxVerified       = 3
	)
	var verified []string
	attempts := 0
	for _, op := range unprotected {
		if len(verified) >= maxVerified || attempts >= maxVerifyAttempts {
			break
		}
		if strings.ContainsAny(op.path, "{}") {
			continue // templated path — a literal call says nothing about auth
		}
		attempts++
		if r := m.verifyUnprotected(ctx, httpClient, op.path, op.method); r != "" {
			verified = append(verified, r)
		}
	}

	var extracted []string
	for _, op := range unprotected {
		detail := fmt.Sprintf("%s %s", op.method, op.path)
		if op.operationID != "" {
			detail += fmt.Sprintf(" (operationId: %s)", op.operationID)
		}
		detail += fmt.Sprintf(" - %s", op.reason)
		extracted = append(extracted, detail)
	}
	extracted = append(extracted, verified...)

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + "/openapi.json"

	// Confidence tracks runtime evidence: Firm only when at least one operation was
	// confirmed reachable without auth; otherwise the schema is the sole signal (the
	// runtime may still enforce auth via an undeclared global dependency/middleware),
	// so the finding is Tentative — a schema/middleware inconsistency, not a proven
	// bypass.
	confidence := severity.Tentative
	description := "FastAPI OpenAPI schema declares API operations without security requirements; runtime enforcement was not confirmed, so this may be a schema/middleware inconsistency rather than an exploitable bypass"
	if len(verified) > 0 {
		confidence = ModuleConfidence
		description = "FastAPI OpenAPI schema reveals API operations without security requirements, and at least one was confirmed reachable without authentication"
	}

	return []*output.ResultEvent{
		{
			URL:              targetURL,
			Matched:          targetURL,
			Request:          string(modifiedRaw),
			Response:         resp.FullResponseString(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        fmt.Sprintf("FastAPI Auth Inconsistency: %d unprotected operations", len(unprotected)),
				Description: description,
				Severity:    ModuleSeverity,
				Confidence:  confidence,
				Tags:        []string{"python", "fastapi", "openapi", "auth", "misconfiguration"},
				Reference:   []string{"https://fastapi.tiangolo.com/tutorial/security/"},
			},
		},
	}, nil
}

// verifyUnprotected calls an operation without auth and returns a human-readable
// confirmation ONLY when the response proves the endpoint was actually reached
// unauthenticated — a 2xx, or a FastAPI 422 (which is emitted only after auth has
// been cleared and request-body validation runs). A 401/403 (protected) or a
// 404/405/3xx/5xx (the endpoint was not reached as intended — often because the
// path is templated or needs a body) returns "" and is not treated as evidence.
func (m *Module) verifyUnprotected(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path string,
	method string,
) string {
	// A templated path (e.g. /api/users/{user_id}) cannot be verified by calling it
	// literally — the placeholder yields a 404/422 that says nothing about auth.
	if strings.ContainsAny(path, "{}") {
		return ""
	}

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), method)
	if err != nil {
		return ""
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, path)
	if err != nil {
		return ""
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return ""
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return ""
	}
	defer resp.Close()

	if resp.Response() == nil {
		return ""
	}

	status := resp.Response().StatusCode
	switch {
	case status >= 200 && status < 300:
		return fmt.Sprintf("Verified: %s %s returned %d without authentication", method, path, status)
	case status == 422:
		// 422 is FastAPI's request-validation error, emitted only AFTER the request
		// clears any auth dependency — so it proves the endpoint is reachable
		// unauthenticated even though our empty probe failed validation.
		return fmt.Sprintf("Verified: %s %s reached request validation (422) without authentication", method, path)
	default:
		return ""
	}
}
