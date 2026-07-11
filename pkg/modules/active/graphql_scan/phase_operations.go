package graphql_scan

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/graphqlx"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// phaseOperations expands a successful introspection schema into concrete
// GraphQL operations — one per root query field (and mutations only under a deep
// scan) — and feeds them into the scanning pipeline, exactly the way an OpenAPI
// spec is expanded into requests. This lets every passive/active detector
// (secrets, IDOR, error leaks, injection, PII) analyze real GraphQL responses
// instead of never seeing GraphQL traffic.
//
// A parsed schema is itself proof of a live GraphQL endpoint — the server just
// answered the introspection query with a schema — so no extra liveness probe is
// needed before feeding.
func (m *Module) phaseOperations(
	ctx *httpmsg.HttpRequestResponse,
	scanCtx *modkit.ScanContext,
	endpointPath string,
	schema *graphqlx.Schema,
	target string,
) *output.ResultEvent {
	if scanCtx == nil {
		return nil
	}
	feeder := scanCtx.Feeder()
	if feeder == nil || schema == nil {
		return nil // nothing to feed into, or introspection unavailable
	}

	// Mutations change state, so only exercise them under an explicit deep scan.
	ops := graphqlx.BuildOperations(schema, graphqlx.BuildOptions{
		IncludeMutations: scanCtx.DeepScan,
	})
	if len(ops) == 0 {
		return nil
	}

	var fed, queries, mutations int
	for _, op := range ops {
		raw, err := buildRaw(ctx, "POST", endpointPath, "application/json", op.Body)
		if err != nil {
			continue
		}
		rr := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
		if feeder.Feed(rr) {
			fed++
			if op.Kind == graphqlx.KindMutation {
				mutations++
			} else {
				queries++
			}
		}
	}
	if fed == 0 {
		return nil
	}

	endpointURL := target + endpointPath
	terminal.Notice("graphql", fmt.Sprintf(
		"Expanded GraphQL schema at %s — auto-exercising %d operation(s) (%d queries, %d mutations); "+
			"extra traffic queued so all detectors see real GraphQL responses",
		endpointURL, fed, queries, mutations))

	extracted := []string{
		fmt.Sprintf("GraphQL endpoint: %s", endpointPath),
		fmt.Sprintf("Operations exercised: %d (%d queries, %d mutations)", fed, queries, mutations),
	}
	return &output.ResultEvent{
		ModuleID:         ModuleID,
		RecordKind:       output.RecordKindObservation,
		EvidenceGrade:    output.EvidenceGradeObservation,
		URL:              target,
		Matched:          endpointURL,
		ExtractedResults: extracted,
		Info: output.Info{
			Name: "GraphQL Schema Auto-Exercised",
			Description: fmt.Sprintf(
				"Introspection at %s exposed a queryable schema; %d operations were synthesized "+
					"from the schema and fed into the scanner so downstream detectors evaluate real "+
					"GraphQL responses. Review the queued GraphQL traffic for data exposure.",
				endpointPath, fed),
			Severity:   severity.Info,
			Confidence: severity.Certain,
			Tags:       ModuleTags,
		},
		Metadata: map[string]any{
			"operations_queued": fed,
			"queries_queued":    queries,
			"mutations_queued":  mutations,
			"impact_proven":     false,
		},
	}
}
