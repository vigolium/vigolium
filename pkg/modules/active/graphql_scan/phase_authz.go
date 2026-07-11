package graphql_scan

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/graphqlx"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// maxIDORFields caps how many id-lookup fields are probed per host.
const maxIDORFields = 5

// idLiteral formats a value as a GraphQL literal for the given scalar type:
// numeric types are bare, everything else (ID, String, custom) is quoted.
func idLiteral(typeName, val string) string {
	switch typeName {
	case "Int", "Float":
		return val
	default:
		return graphqlx.QuoteString(val)
	}
}

// controlValue returns a type-valid identifier that is very unlikely to exist,
// used to prove the field is a real id lookup (absent id → no object).
func controlValue(typeName string) string {
	switch typeName {
	case "Int", "Float":
		return "999999999"
	case "String":
		return "vigolium-nonexistent-id"
	default: // ID
		return "999999999"
	}
}

// fieldObject reports whether data.<field> resolved to a non-null value and, if
// so, a normalized digest of that value for distinctness comparison.
func fieldObject(body, field string) (present bool, norm string) {
	var resp struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &resp); err != nil {
		return false, ""
	}
	raw, ok := resp.Data[field]
	if !ok {
		return false, ""
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return false, ""
	}
	// Require an object shape (a selected record), not a bare scalar echo.
	if !strings.HasPrefix(trimmed, "{") {
		return false, ""
	}
	return true, trimmed
}

// probeIDOR runs one full observation of the predictable-ID pattern for a field:
// id=1 and id=2 must each return a distinct object, and a non-existent control
// id must return no object. All three requests are fresh, so a cache or flaky
// response breaks the pattern.
func (m *Module) probeIDOR(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	schema *graphqlx.Schema,
	lookup graphqlx.IDLookupField,
	endpointPath string,
) bool {
	argType := lookup.IDArgType()
	field := lookup.Field.Name

	fetch := func(val string) (*gqlResp, bool) {
		q, ok := schema.RenderProbe(lookup.Field, lookup.IDArg, idLiteral(argType, val), 0)
		if !ok {
			return nil, false
		}
		r, err := m.send(ctx, httpClient, "POST", endpointPath, "application/json", graphqlx.QueryBody(q))
		if err != nil || r.blocked {
			return nil, false
		}
		return r, true
	}

	r1, ok := fetch("1")
	if !ok {
		return false
	}
	present1, norm1 := fieldObject(r1.body, field)
	if !present1 {
		return false
	}

	r2, ok := fetch("2")
	if !ok {
		return false
	}
	present2, norm2 := fieldObject(r2.body, field)
	// Compare normalized objects so per-request dynamic tokens (ids, timestamps,
	// nonces) don't make an otherwise-identical record look distinct.
	if !present2 || modkit.NormalizeForRatio(norm1, "") == modkit.NormalizeForRatio(norm2, "") {
		return false // second id absent, or same object for every id (not per-record)
	}

	rc, ok := fetch(controlValue(argType))
	if !ok {
		return false
	}
	presentC, _ := fieldObject(rc.body, field)
	return !presentC // control id must NOT resolve to an object
}

// phaseAuthz probes root fields that fetch an object by a predictable "id"
// argument for broken object-level authorization (IDOR/BOLA). It confirms — over
// multiple independent rounds — that sequential ids return distinct records
// while a non-existent id returns nothing, i.e. arbitrary objects are reachable
// by walking ids. It is reported as Tentative because confirming a true
// authorization *bypass* requires an access baseline the scanner may not have;
// the finding flags the surface for verification.
func (m *Module) phaseAuthz(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	endpointPath string,
	schema *graphqlx.Schema,
	target string,
) []*output.ResultEvent {
	if schema == nil {
		return nil
	}
	lookups := schema.IDLookupFields()
	if len(lookups) == 0 {
		return nil
	}
	if len(lookups) > maxIDORFields {
		lookups = lookups[:maxIDORFields]
	}

	var results []*output.ResultEvent
	for _, lookup := range lookups {
		field := lookup.Field.Name
		// The predictable-ID pattern must reproduce across independent rounds.
		if !confirmRounds(defaultConfirmRounds, func() (bool, error) {
			return m.probeIDOR(ctx, httpClient, schema, lookup, endpointPath), nil
		}) {
			continue
		}

		results = append(results, &output.ResultEvent{
			ModuleID:      ModuleID,
			RecordKind:    output.RecordKindCandidate,
			EvidenceGrade: output.EvidenceGradeDifferential,
			URL:           target,
			Matched:       target + endpointPath,
			ExtractedResults: []string{
				fmt.Sprintf("GraphQL endpoint: %s", endpointPath),
				fmt.Sprintf("Field: %s(%s:)", field, lookup.IDArg),
				"Sequential ids return distinct objects; absent id returns none",
			},
			Info: output.Info{
				Name: "GraphQL Predictable Object Access Candidate",
				Description: fmt.Sprintf(
					"The GraphQL field '%s' returns distinct objects for sequential '%s' values while a "+
						"non-existent id returns nothing. This confirms predictable object lookup in the "+
						"current principal's session, not cross-user access: the objects may be public or "+
						"authorized to that principal. Verify '%s' with an identifier owned by another user "+
						"before classifying it as IDOR/BOLA.",
					field, lookup.IDArg, field),
				Severity:   severity.Medium,
				Confidence: severity.Tentative,
				Tags:       ModuleTags,
			},
			Metadata: map[string]any{
				"same_principal_only": true,
				"cross_user_proven":   false,
				"negative_id_control": true,
				"confirmation_rounds": defaultConfirmRounds,
			},
		})
		// One representative finding per host is enough to flag the surface.
		break
	}
	return results
}
