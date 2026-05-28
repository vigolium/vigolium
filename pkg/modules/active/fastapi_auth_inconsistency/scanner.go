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

	// Optionally verify by calling the first unprotected endpoint without auth.
	var verified []string
	for _, op := range unprotected {
		if len(verified) >= 3 {
			break
		}

		verifyResult := m.verifyUnprotected(ctx, httpClient, op.path, op.method)
		if verifyResult != "" {
			verified = append(verified, verifyResult)
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

	return []*output.ResultEvent{
		{
			URL:              targetURL,
			Matched:          targetURL,
			Request:          string(modifiedRaw),
			Response:         resp.FullResponseString(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        fmt.Sprintf("FastAPI Auth Inconsistency: %d unprotected operations", len(unprotected)),
				Description: "FastAPI OpenAPI schema reveals API operations without security requirements, potentially allowing unauthenticated access to sensitive endpoints",
				Severity:    ModuleSeverity,
				Confidence:  ModuleConfidence,
				Tags:        []string{"python", "fastapi", "openapi", "auth", "misconfiguration"},
				Reference:   []string{"https://fastapi.tiangolo.com/tutorial/security/"},
			},
		},
	}, nil
}

// verifyUnprotected attempts to call an unprotected endpoint without auth
// and checks if it returns a non-401/403 response.
func (m *Module) verifyUnprotected(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path string,
	method string,
) string {
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
	if status != 401 && status != 403 {
		return fmt.Sprintf("Verified: %s %s returned status %d without authentication", method, path, status)
	}

	return ""
}
