package graphql_scan

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// batchProbeSize is the batch width used to prove an endpoint executes many
// operations per request without a cap. Kept moderate so it demonstrates the
// primitive (no per-request limit) without being an actual DoS.
const batchProbeSize = 12

// buildArrayBatch builds an array-batched request of n identical __typename
// queries.
func buildArrayBatch(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = `{"query":"{ __typename }"}`
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// buildAliasBatch builds a single query aliasing __typename n times (a0..a{n-1}).
func buildAliasBatch(n int) string {
	var sb strings.Builder
	sb.WriteString(`{"query":"{ `)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "a%d: __typename ", i)
	}
	sb.WriteString(`}"}`)
	return sb.String()
}

// countArrayResults counts how many entries of an array-batched response actually
// executed (carry a data.__typename). Returns 0 for a non-array / malformed body.
func countArrayResults(body string) int {
	var arr []struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &arr); err != nil {
		return 0
	}
	n := 0
	for _, e := range arr {
		if _, ok := e.Data["__typename"]; ok {
			n++
		}
	}
	return n
}

// countAliasResults counts how many of the a0..a{n-1} aliases resolved in a
// single response's data object.
func countAliasResults(body string, n int) int {
	var resp struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &resp); err != nil {
		return 0
	}
	c := 0
	for i := 0; i < n; i++ {
		if _, ok := resp.Data[fmt.Sprintf("a%d", i)]; ok {
			c++
		}
	}
	return c
}

// phaseBatching confirms whether the endpoint executes an uncapped batch of
// operations in a single HTTP request — the primitive behind rate-limit bypass,
// ID/credential brute-forcing, and MFA/OTP bypass. Both array batching and
// alias batching are tested, and a positive result must reproduce across
// independent rounds (every operation in the batch executing each time) before
// it is reported, so a partial/flaky response cannot trip it.
func (m *Module) phaseBatching(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	endpointPath, target string,
) *output.ResultEvent {
	arrayConfirmed := confirmRounds(defaultConfirmRounds, func() (bool, error) {
		r, err := m.send(ctx, httpClient, "POST", endpointPath, "application/json", buildArrayBatch(batchProbeSize))
		if err != nil {
			return false, err
		}
		if r.blocked {
			return false, nil
		}
		return countArrayResults(r.body) == batchProbeSize, nil
	})

	aliasConfirmed := confirmRounds(defaultConfirmRounds, func() (bool, error) {
		r, err := m.send(ctx, httpClient, "POST", endpointPath, "application/json", buildAliasBatch(batchProbeSize))
		if err != nil {
			return false, err
		}
		if r.blocked {
			return false, nil
		}
		return countAliasResults(r.body, batchProbeSize) == batchProbeSize, nil
	})

	if !arrayConfirmed && !aliasConfirmed {
		return nil
	}

	var forms []string
	if arrayConfirmed {
		forms = append(forms, "array batching")
	}
	if aliasConfirmed {
		forms = append(forms, "alias batching")
	}
	formsStr := strings.Join(forms, " and ")

	return &output.ResultEvent{
		ModuleID:      ModuleID,
		RecordKind:    output.RecordKindCandidate,
		EvidenceGrade: output.EvidenceGradeCandidate,
		URL:           target,
		Matched:       target + endpointPath,
		ExtractedResults: []string{
			fmt.Sprintf("GraphQL endpoint: %s", endpointPath),
			fmt.Sprintf("Uncapped batching: %s", formsStr),
			fmt.Sprintf("%d operations executed in one request", batchProbeSize),
		},
		Info: output.Info{
			Name: "GraphQL Batch Execution Capability Observed",
			Description: fmt.Sprintf(
				"The GraphQL endpoint reproducibly executed %d harmless __typename operations in one "+
					"request via %s. This establishes batching capacity, but it does not prove that a "+
					"sensitive operation exists or that batching bypasses its rate limit. Verify with a "+
					"non-destructive rate-limited operation before treating this as a bypass.",
				batchProbeSize, formsStr),
			Severity:   severity.Medium,
			Confidence: severity.Certain,
			Tags:       ModuleTags,
		},
		Metadata: map[string]any{
			"batch_size":          batchProbeSize,
			"rate_limit_bypassed": false,
			"sensitive_operation": false,
			"confirmation_rounds": defaultConfirmRounds,
		},
	}
}
