package graphql_scan

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/graphqlx"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// xssMarkers are two distinct HTML-metachar markers. Requiring BOTH to reflect
// verbatim (raw <, >) confirms the endpoint echoes attacker input into error
// messages without HTML-encoding, and rules out a one-off coincidence.
var xssMarkers = []string{"<vgx7hs2z>", "<vgx4mk9w>"}

// maxXSSCandidates caps how many (field, arg) pairs are probed per host.
const maxXSSCandidates = 6

// xssCandidate is a (field, arg) injection point. Non-string scalar args are
// preferred: passing a string marker to an Int/enum/ID arg forces a type
// coercion error that echoes the value verbatim.
type xssCandidate struct {
	field *graphqlx.Field
	arg   string
}

// collectXSSCandidates gathers scalar-arg injection points from the schema,
// non-string types first (they reliably trigger an echoing coercion error).
func collectXSSCandidates(schema *graphqlx.Schema) []xssCandidate {
	var preferred, strings_ []xssCandidate
	for _, f := range schema.QueryFields() {
		for _, a := range f.Args {
			if a == nil {
				continue
			}
			switch a.Type.Named() {
			case "Int", "Float", "Boolean", "ID":
				preferred = append(preferred, xssCandidate{field: f, arg: a.Name})
			case "String":
				strings_ = append(strings_, xssCandidate{field: f, arg: a.Name})
			}
		}
	}
	out := append(preferred, strings_...)
	if len(out) > maxXSSCandidates {
		out = out[:maxXSSCandidates]
	}
	return out
}

// reflectsMarker sends the marker into the candidate's argument and reports
// whether the marker is reflected verbatim (raw angle brackets) in the response,
// plus whether that response was served as HTML.
func (m *Module) reflectsMarker(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	schema *graphqlx.Schema,
	c xssCandidate,
	endpointPath, marker string,
) (reflected, htmlCtx bool) {
	q, ok := schema.RenderProbe(c.field, c.arg, graphqlx.QuoteString(marker), 0)
	if !ok {
		return false, false
	}
	r, err := m.send(ctx, httpClient, "POST", endpointPath, "application/json", graphqlx.QueryBody(q))
	if err != nil || r.blocked {
		return false, false
	}
	// Verbatim containment: the marker keeps its raw <,> only if the server did
	// not HTML-encode it (an encoded reflection would read <vgx…> or
	// &lt;vgx…&gt; and fail this check).
	if !strings.Contains(r.body, marker) {
		return false, false
	}
	return true, r.isHTML()
}

// phaseXSSError injects HTML-metachar markers into scalar arguments and reports
// when the endpoint reflects them unescaped in error messages. Two distinct
// markers must both reflect verbatim before it is reported. Severity is raised
// when the reflecting response is served as HTML (directly browser-executable);
// a JSON reflection is reported Low as it only becomes XSS when a client renders
// the message.
func (m *Module) phaseXSSError(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	endpointPath string,
	schema *graphqlx.Schema,
	target string,
) *output.ResultEvent {
	if schema == nil {
		return nil
	}
	candidates := collectXSSCandidates(schema)
	if len(candidates) == 0 {
		return nil
	}

	for _, c := range candidates {
		anyHTML := false
		allReflected := true
		for _, marker := range xssMarkers {
			reflected, htmlCtx := m.reflectsMarker(ctx, httpClient, schema, c, endpointPath, marker)
			if !reflected {
				allReflected = false
				break
			}
			anyHTML = anyHTML || htmlCtx
		}
		if !allReflected {
			continue
		}

		sev := severity.Low
		conf := severity.Tentative
		context := "JSON error message (exploitable only if a client renders it as HTML)"
		if anyHTML {
			sev = severity.Medium
			conf = severity.Firm
			context = "HTML response (directly browser-executable)"
		}

		kind := output.RecordKindObservation
		grade := output.EvidenceGradeObservation
		if anyHTML {
			kind = output.RecordKindCandidate
			grade = output.EvidenceGradeDifferential
		}

		return &output.ResultEvent{
			ModuleID:      ModuleID,
			RecordKind:    kind,
			EvidenceGrade: grade,
			URL:           target,
			Matched:       target + endpointPath,
			ExtractedResults: []string{
				fmt.Sprintf("GraphQL endpoint: %s", endpointPath),
				fmt.Sprintf("Reflected field/arg: %s(%s:)", c.field.Name, c.arg),
				fmt.Sprintf("Markers reflected unescaped: %s", strings.Join(xssMarkers, ", ")),
				fmt.Sprintf("Context: %s", context),
			},
			Info: output.Info{
				Name: "GraphQL Error Reflection" + map[bool]string{true: " XSS Candidate", false: " Observation"}[anyHTML],
				Description: fmt.Sprintf(
					"The GraphQL endpoint reflected injected HTML markers verbatim (raw angle brackets) "+
						"in the error message for field '%s' argument '%s', served as a %s. This proves "+
						"reflection, not JavaScript execution; JSON requires a separate unsafe renderer, and "+
						"the HTML probe used a non-executable marker. Confirm execution in a browser before "+
						"classifying it as XSS.",
					c.field.Name, c.arg, context),
				Severity:   sev,
				Confidence: conf,
				Tags:       ModuleTags,
			},
			Metadata: map[string]any{
				"html_context":     anyHTML,
				"execution_proven": false,
				"markers":          append([]string(nil), xssMarkers...),
			},
		}
	}
	return nil
}
