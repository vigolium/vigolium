package graphql_scan

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// consoleSig identifies an in-browser GraphQL IDE by strong HTML/asset markers.
// A single strong marker is enough — these tokens do not appear on ordinary
// pages, so requiring one keeps false positives near zero.
type consoleSig struct {
	name    string
	markers []string
}

var consoleSigs = []consoleSig{
	{"GraphiQL", []string{
		"<title>GraphiQL", "id=\"graphiql\"", "graphiql.min.js", "graphiql.min.css",
		">GraphiQL<", "renderGraphiQL", "GraphiQL - ",
	}},
	{"GraphQL Playground", []string{
		"GraphQL Playground", "graphql-playground", "GraphQLPlayground.init", "playground.min.js",
	}},
	{"Altair GraphQL", []string{
		"AltairGraphQL", "altair.js", "<app-altair", "altair_static", "Altair GraphQL Client",
	}},
	{"GraphQL Voyager", []string{
		"GraphQL Voyager", "voyager.worker", "renderVoyager", "graphql-voyager",
	}},
	{"Apollo Sandbox", []string{
		"embeddable-sandbox", "ApolloServerPluginLandingPage", "apollographql.com/embeddable-sandbox",
	}},
}

// consolePaths are well-known IDE mount points, probed relative to the web root
// in addition to the discovered endpoint path itself (GraphiQL is frequently
// served from the endpoint on a GET).
var consolePaths = []string{
	"/graphiql",
	"/graphql/console",
	"/console",
	"/playground",
	"/graphql-playground",
	"/graphql/playground",
	"/altair",
	"/graphql/altair",
	"/voyager",
	"/graphql/voyager",
}

// matchConsole returns the console name if the response is a live, HTML IDE page.
// Requires a 200, an HTML-ish body, and a strong signature marker.
func matchConsole(r *gqlResp) string {
	if r == nil || r.status != 200 {
		return ""
	}
	body := r.body
	// Require HTML: either an HTML content-type, or a body with an HTML document
	// signature. Guards against JSON errors that mention an IDE by name.
	if !r.isHTML() && !infra.BodyLooksLikeHTMLPage(body) {
		return ""
	}
	for _, sig := range consoleSigs {
		for _, marker := range sig.markers {
			if strings.Contains(body, marker) {
				return sig.name
			}
		}
	}
	return ""
}

// phaseConsole probes for an exposed in-browser GraphQL IDE (GraphiQL,
// Playground, Altair, Voyager, Apollo Sandbox) reachable in production. Each hit
// is confirmed across multiple independent fetches, and the exact console
// signature must reproduce every round, so a transient/error page cannot trip it.
func (m *Module) phaseConsole(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	endpointPath, target string,
) []*output.ResultEvent {
	// Probe the endpoint itself (GET) first, then the well-known IDE paths, deduped.
	paths := make([]string, 0, len(consolePaths)+1)
	seen := map[string]bool{}
	for _, p := range append([]string{endpointPath}, consolePaths...) {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		paths = append(paths, p)
	}

	var results []*output.ResultEvent
	reportedType := map[string]bool{}

	for _, path := range paths {
		// First observation: cheap single GET to see if it looks like a console.
		first, err := m.send(ctx, httpClient, "GET", path, "", "")
		if err != nil {
			continue
		}
		name := matchConsole(first)
		if name == "" || reportedType[name] {
			continue
		}

		// Confirm: the same console signature must reproduce on further rounds.
		confirmed := confirmRounds(defaultConfirmRounds-1, func() (bool, error) {
			r, err := m.send(ctx, httpClient, "GET", path, "", "")
			if err != nil {
				return false, err
			}
			return matchConsole(r) == name, nil
		})
		if !confirmed {
			continue
		}

		reportedType[name] = true
		consoleURL := target + path
		results = append(results, &output.ResultEvent{
			ModuleID:      ModuleID,
			RecordKind:    output.RecordKindObservation,
			EvidenceGrade: output.EvidenceGradeObservation,
			URL:           target,
			Matched:       consoleURL,
			ExtractedResults: []string{
				fmt.Sprintf("Exposed GraphQL IDE: %s", name),
				fmt.Sprintf("Location: %s", path),
			},
			Info: output.Info{
				Name: "GraphQL Development Console Observed",
				Description: fmt.Sprintf(
					"An interactive %s GraphQL IDE is reachable at %s. This is useful attack-surface "+
						"information, but the scanner cannot infer that the target is production or that "+
						"the IDE grants access beyond the underlying API's authorization policy.",
					name, path),
				Severity:   severity.Info,
				Confidence: severity.Certain,
				Tags:       ModuleTags,
			},
			Metadata: map[string]any{
				"console":       name,
				"impact_proven": false,
			},
		})
	}
	return results
}
