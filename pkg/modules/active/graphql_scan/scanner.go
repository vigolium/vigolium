package graphql_scan

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
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
		ds: dedup.LazyDiskSet("graphql_scan"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses custom CanProcess.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess returns true if the request has a response (host is reachable).
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

// ScanPerRequest discovers and tests GraphQL endpoints on the target.
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

	// Dedup by host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	var results []*output.ResultEvent

	// Phase 1: Discover GraphQL endpoint
	endpointPath, err := m.discoverEndpoint(ctx, httpClient)
	if err != nil || endpointPath == "" {
		return results, nil
	}

	target := ctx.Target()

	// Phase 2: Test introspection
	introBody, err := m.sendGraphQLQuery(ctx, httpClient, endpointPath, introspectionQuery)
	if err == nil && hasIntrospection(introBody) {
		results = append(results, &output.ResultEvent{
			URL:     target,
			Matched: target + endpointPath,
			ExtractedResults: []string{
				fmt.Sprintf("GraphQL endpoint: %s", endpointPath),
				"Introspection enabled",
			},
			Info: output.Info{
				Name:        "GraphQL Introspection Enabled",
				Description: "GraphQL introspection is enabled, exposing the complete API schema including types, fields, and arguments. This information aids attackers in crafting targeted queries.",
				Severity:    severity.Medium,
				Confidence:  severity.Certain,
			},
		})
	}

	// Phase 3: Test SQL injection through GraphQL arguments
	sqliResults := m.testInjection(ctx, httpClient, endpointPath, introBody, target)
	results = append(results, sqliResults...)

	// Phase 4: Test batching (array-based)
	batchBody, err := m.sendGraphQLQuery(ctx, httpClient, endpointPath, batchQuery)
	if err == nil && isBatchResponse(batchBody) {
		results = append(results, &output.ResultEvent{
			URL:     target,
			Matched: target + endpointPath,
			ExtractedResults: []string{
				fmt.Sprintf("GraphQL endpoint: %s", endpointPath),
				"Query batching supported",
			},
			Info: output.Info{
				Name:        "GraphQL Query Batching",
				Description: "GraphQL endpoint supports query batching, which can be abused to bypass rate limiting or perform denial of service attacks.",
				Severity:    severity.Low,
				Confidence:  severity.Certain,
			},
		})
	}

	// Phase 5: Test alias-based batching
	aliasBody, err := m.sendGraphQLQuery(ctx, httpClient, endpointPath, aliasBatchQuery)
	if err == nil && isAliasBatchResponse(aliasBody) {
		results = append(results, &output.ResultEvent{
			URL:     target,
			Matched: target + endpointPath,
			ExtractedResults: []string{
				fmt.Sprintf("GraphQL endpoint: %s", endpointPath),
				"Alias-based query batching supported",
			},
			Info: output.Info{
				Name:        "GraphQL Alias-Based Query Batching",
				Description: "GraphQL endpoint supports alias-based query batching, which can be abused to bypass rate limiting even when array batching is disabled.",
				Severity:    severity.Low,
				Confidence:  severity.Certain,
			},
		})
	}

	return results, nil
}

// discoverEndpoint probes common GraphQL paths and returns the first working endpoint.
func (m *Module) discoverEndpoint(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) (string, error) {
	for _, path := range graphqlPaths {
		body, err := m.sendGraphQLQuery(ctx, httpClient, path, typenameQuery)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return "", err
			}
			continue
		}
		if isGraphQLEndpoint(body) {
			return path, nil
		}
	}

	// Fallback: try GET method with query parameter
	for _, path := range graphqlPaths {
		body, err := m.sendGraphQLGET(ctx, httpClient, path, "{ __typename }")
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return "", err
			}
			continue
		}
		if isGraphQLEndpoint(body) {
			return path, nil
		}
	}
	return "", nil
}

// testInjection tests SQL injection through GraphQL field arguments.
func (m *Module) testInjection(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	endpointPath, introBody, target string,
) []*output.ResultEvent {
	var results []*output.ResultEvent
	var fieldsToTest []introspectionField

	// If introspection worked, use discovered fields
	if introBody != "" {
		fieldsToTest = parseIntrospectionResponse(introBody)
	}

	// If no fields from introspection, try generic field names
	if len(fieldsToTest) == 0 {
		for _, name := range genericFieldNames {
			fieldsToTest = append(fieldsToTest, introspectionField{
				fieldName: name,
				argName:   "id",
			})
		}
	}

	// Limit to 10 fields to avoid excessive requests
	if len(fieldsToTest) > 10 {
		fieldsToTest = fieldsToTest[:10]
	}

	sqliPayload := `' OR '1'='1`
	for _, field := range fieldsToTest {
		query := fmt.Sprintf(`{"query":"{ %s(%s: \"%s\") { __typename } }"}`,
			field.fieldName, field.argName, escapeJSON(sqliPayload))

		body, err := m.sendGraphQLQuery(ctx, httpClient, endpointPath, query)
		if err != nil {
			continue
		}

		if containsSQLError(body) {
			results = append(results, &output.ResultEvent{
				URL:     target,
				Matched: target + endpointPath,
				ExtractedResults: []string{
					fmt.Sprintf("GraphQL endpoint: %s", endpointPath),
					fmt.Sprintf("Vulnerable field: %s(%s:)", field.fieldName, field.argName),
					fmt.Sprintf("Payload: %s", sqliPayload),
				},
				Info: output.Info{
					Name:        "SQL Injection via GraphQL",
					Description: fmt.Sprintf("SQL injection detected in GraphQL field '%s' argument '%s'. The server returned database error messages when injecting SQL syntax.", field.fieldName, field.argName),
					Severity:    severity.High,
					Confidence:  severity.Certain,
				},
			})
			return results // One finding is enough
		}
	}

	return results
}

// sendGraphQLQuery sends a GraphQL query to the specified path.
func (m *Module) sendGraphQLQuery(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path, queryBody string,
) (string, error) {
	raw := ctx.Request().Raw()

	// Build POST request to GraphQL endpoint
	modified, err := httpmsg.SetPath(raw, path)
	if err != nil {
		return "", err
	}
	modified, err = httpmsg.SetMethod(modified, "POST")
	if err != nil {
		return "", err
	}
	modified, err = httpmsg.AddOrReplaceHeader(modified, "Content-Type", "application/json")
	if err != nil {
		return "", err
	}
	modified, err = httpmsg.SetBodyString(modified, queryBody)
	if err != nil {
		return "", err
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modified))
	if err != nil {
		return "", err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return "", err
	}
	defer resp.Close()

	return resp.FullResponseString(), nil
}

// sendGraphQLGET sends a GraphQL query via GET with a query parameter.
func (m *Module) sendGraphQLGET(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path, query string,
) (string, error) {
	raw := ctx.Request().Raw()

	fullPath := path + "?query=" + strings.ReplaceAll(strings.ReplaceAll(query, " ", "+"), "{", "%7B")
	fullPath = strings.ReplaceAll(fullPath, "}", "%7D")

	modified, err := httpmsg.SetPath(raw, fullPath)
	if err != nil {
		return "", err
	}
	modified, err = httpmsg.SetMethod(modified, "GET")
	if err != nil {
		return "", err
	}
	modified, err = httpmsg.ClearBody(modified)
	if err != nil {
		return "", err
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modified))
	if err != nil {
		return "", err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return "", err
	}
	defer resp.Close()

	return resp.FullResponseString(), nil
}

// escapeJSON escapes a string for use inside a JSON string value.
func escapeJSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return strings.ReplaceAll(s, `"`, `\"`)
	}
	// json.Marshal wraps in quotes, remove them
	return string(b[1 : len(b)-1])
}
