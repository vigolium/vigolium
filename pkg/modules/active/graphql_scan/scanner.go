package graphql_scan

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	httputil "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/graphqlx"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
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
	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
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
			ModuleID:      ModuleID,
			RecordKind:    output.RecordKindObservation,
			EvidenceGrade: output.EvidenceGradeObservation,
			DedupKey:      fmt.Sprintf("graphql-introspection|%s|%s", host, endpointPath),
			URL:           target,
			Matched:       target + endpointPath,
			ExtractedResults: []string{
				fmt.Sprintf("GraphQL endpoint: %s", endpointPath),
				"Introspection enabled",
			},
			Info: output.Info{
				Name:        "GraphQL Schema Introspection Observed",
				Description: "The endpoint returned a complete, parseable GraphQL schema. Introspection is useful reconnaissance, but public and developer-facing APIs may intentionally expose it; this observation is not an authorization bypass or sensitive-data finding.",
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        ModuleTags,
			},
			Metadata: map[string]any{
				"security_primitive": "schema-introspection",
				"impact_proven":      false,
			},
		})
	}

	// Phase 3: Test error-based SQL injection through GraphQL arguments
	sqliResults := m.testInjection(ctx, httpClient, endpointPath, introBody, target)
	results = append(results, sqliResults...)

	// The remaining phases each perform their own multi-round confirmation and
	// only fire on a confirmed live GraphQL endpoint (reached only after
	// discoverEndpoint succeeded above), so a non-GraphQL host never triggers them.
	// The introspection schema is parsed once here and shared; a nil schema
	// (introspection disabled or unparseable) skips the schema-driven phases.
	schema, _ := graphqlx.ParseSchema([]byte(introBody))

	// Phase 4: Expand the introspection schema into concrete operations and feed
	// them into the pipeline so every detector evaluates real GraphQL responses.
	if scanCtx != nil {
		if op := m.phaseOperations(ctx, scanCtx, endpointPath, schema, target); op != nil {
			results = append(results, op)
		}
	}

	// Phase 5: Exposed in-browser GraphQL IDE (GraphiQL/Playground/Altair/…).
	results = append(results, m.phaseConsole(ctx, httpClient, endpointPath, target)...)

	// Phase 6: Weaponized (uncapped) query batching — rate-limit/brute-force bypass.
	if b := m.phaseBatching(ctx, httpClient, endpointPath, target); b != nil {
		results = append(results, b)
	}

	// Phase 7: Broken object-level authorization (IDOR/BOLA) on predictable ids.
	results = append(results, m.phaseAuthz(ctx, httpClient, endpointPath, schema, target)...)

	// Phase 8: Reflected XSS in error messages.
	if x := m.phaseXSSError(ctx, httpClient, endpointPath, schema, target); x != nil {
		results = append(results, x)
	}

	// Phase 9: Boolean-based SQL injection (corroborates the error-based path).
	if s := m.phaseBooleanSQLi(ctx, httpClient, endpointPath, schema, target); s != nil {
		results = append(results, s)
	}

	// Phase 10: Missing query-depth/complexity limit — deep scans only (heavier
	// than the default surface, though the probe itself is bounded).
	if scanCtx != nil && scanCtx.DeepScan {
		if d := m.phaseDoS(ctx, httpClient, endpointPath, schema, target); d != nil {
			results = append(results, d)
		}
	}

	return results, nil
}

// discoverEndpoint probes common GraphQL paths and returns the first working
// endpoint. Each known path is tried under the web root and under every
// context-path prefix of the observed URL (e.g. /orders/graphql when the spider
// hit /orders/items), so a GraphQL endpoint mounted behind a service/gateway
// prefix is discovered, not only one at the web root.
func (m *Module) discoverEndpoint(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) (string, error) {
	candidates := m.candidatePaths(ctx)

	for _, path := range candidates {
		var terminalErr error
		confirmed := confirmRounds(defaultConfirmRounds, func() (bool, error) {
			r, err := m.send(ctx, httpClient, "POST", path, "application/json", typenameQuery)
			if err != nil {
				if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
					terminalErr = err
				}
				return false, err
			}
			return !r.blocked && r.status >= 200 && r.status < 300 && isGraphQLEndpoint(r.body), nil
		})
		if terminalErr != nil {
			return "", terminalErr
		}
		if confirmed {
			return path, nil
		}
	}

	// Fallback: try GET method with query parameter
	for _, path := range candidates {
		fullPath := graphQLGETPath(path, "{ __typename }")
		var terminalErr error
		confirmed := confirmRounds(defaultConfirmRounds, func() (bool, error) {
			r, err := m.send(ctx, httpClient, "GET", fullPath, "", "")
			if err != nil {
				if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
					terminalErr = err
				}
				return false, err
			}
			return !r.blocked && r.status >= 200 && r.status < 300 && isGraphQLEndpoint(r.body), nil
		})
		if terminalErr != nil {
			return "", terminalErr
		}
		if confirmed {
			return path, nil
		}
	}
	return "", nil
}

// candidatePaths expands the known GraphQL paths across the web root plus every
// context-path prefix of the observed URL, de-duplicated and order-stable (root
// paths first). A failure to read the URL degrades gracefully to the root paths.
func (m *Module) candidatePaths(ctx *httpmsg.HttpRequestResponse) []string {
	bases := []string{""}
	if urlx, err := ctx.URL(); err == nil {
		bases = modkit.CandidateBasePaths(urlx.Path)
	}
	seen := make(map[string]bool, len(bases)*len(graphqlPaths))
	candidates := make([]string, 0, len(bases)*len(graphqlPaths))
	for _, base := range bases {
		for _, p := range graphqlPaths {
			cp := base + p
			if seen[cp] {
				continue
			}
			seen[cp] = true
			candidates = append(candidates, cp)
		}
	}
	return candidates
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
		confirmed := confirmRounds(defaultConfirmRounds, func() (bool, error) {
			benignQuery := fmt.Sprintf(`{"query":"{ %s(%s: \"%s\") { __typename } }"}`,
				field.fieldName, field.argName, escapeJSON("vigolium"))
			controlBody, controlBlocked, cerr := m.sendGraphQLQueryEx(ctx, httpClient, endpointPath, benignQuery)
			if cerr != nil || controlBlocked || containsSQLError(controlBody) {
				return false, cerr
			}

			attackQuery := fmt.Sprintf(`{"query":"{ %s(%s: \"%s\") { __typename } }"}`,
				field.fieldName, field.argName, escapeJSON(sqliPayload))
			attackBody, attackBlocked, attackErr := m.sendGraphQLQueryEx(ctx, httpClient, endpointPath, attackQuery)
			if attackErr != nil || attackBlocked {
				return false, attackErr
			}
			return containsSQLError(attackBody), nil
		})
		if confirmed {

			results = append(results, &output.ResultEvent{
				ModuleID:      ModuleID,
				RecordKind:    output.RecordKindCandidate,
				EvidenceGrade: output.EvidenceGradeDifferential,
				URL:           target,
				Matched:       target + endpointPath,
				ExtractedResults: []string{
					fmt.Sprintf("GraphQL endpoint: %s", endpointPath),
					fmt.Sprintf("Vulnerable field: %s(%s:)", field.fieldName, field.argName),
					fmt.Sprintf("Payload: %s", sqliPayload),
				},
				Info: output.Info{
					Name:        "GraphQL SQL Injection Candidate",
					Description: fmt.Sprintf("GraphQL field '%s' argument '%s' reproducibly returned a structured GraphQL database error for SQL syntax while the benign control stayed clean. This is strong injection evidence, but query alteration or data access was not demonstrated.", field.fieldName, field.argName),
					Severity:    severity.High,
					Confidence:  severity.Certain,
					Tags:        ModuleTags,
				},
				Metadata: map[string]any{
					"control_clean":       true,
					"confirmation_rounds": defaultConfirmRounds,
					"impact_proven":       false,
				},
			})
			return results // One finding is enough
		}
	}

	return results
}

// sendGraphQLQuery sends a GraphQL query to the specified path and returns the
// full response. The blocked status is discarded for callers that do not need it.
func (m *Module) sendGraphQLQuery(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path, queryBody string,
) (string, error) {
	body, _, err := m.sendGraphQLQueryEx(ctx, httpClient, path, queryBody)
	return body, err
}

// sendGraphQLQueryEx sends a GraphQL query and additionally reports whether the
// response was a WAF/CDN/rate-limit page, so SQL-error detection can skip pages
// that are not the GraphQL backend (a Cloudflare 429 challenge can carry tokens
// that trip the SQL-error patterns).
func (m *Module) sendGraphQLQueryEx(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path, queryBody string,
) (string, bool, error) {
	r, err := m.send(ctx, httpClient, "POST", path, "application/json", queryBody)
	if err != nil {
		return "", false, err
	}
	return r.body, r.blocked, nil
}

// isBlockedResponse reports whether resp came from a WAF/CDN challenge, auth gate,
// rate limiter, or maintenance page rather than the GraphQL backend. Genuine
// error-based SQLi leaks are emitted by the app stack, so a denied or challenged
// response can only yield false matches. It combines the vendor-aware block
// detector (Cloudflare, Akamai, Incapsula, …) with a plain status gate that also
// catches generic WAFs the detector does not recognize.
func isBlockedResponse(resp *httputil.ResponseChain) bool {
	return infra.IsBlockedResponse(resp)
}

// sendGraphQLGET sends a GraphQL query via GET with a query parameter.
func (m *Module) sendGraphQLGET(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path, query string,
) (string, error) {
	r, err := m.send(ctx, httpClient, "GET", graphQLGETPath(path, query), "", "")
	if err != nil {
		return "", err
	}
	return r.body, nil
}

func graphQLGETPath(path, query string) string {
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return path + separator + "query=" + url.QueryEscape(query)
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
