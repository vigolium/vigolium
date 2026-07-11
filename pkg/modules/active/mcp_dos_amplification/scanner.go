package mcp_dos_amplification

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	mcpinfra "github.com/vigolium/vigolium/pkg/modules/infra/mcp"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// oversizedBatchSize is the number of harmless ping requests bundled into the
// oversized probe batch. A server with no batch-size cap or rate limit answers
// essentially all of them; a hardened one caps, rate-limits, or rejects it.
const oversizedBatchSize = 200

// amplificationRatio is the fraction of the oversized batch that must be fully
// processed before we flag amplification. A capping/rate-limiting server
// answers far fewer than this.
const amplificationRatio = 0.9

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
			modkit.ScanScopeHost,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("mcp_dos_amplification"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil || ctx.Response() == nil {
		return false
	}
	return mcpinfra.Detect(ctx).Strong()
}

func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	if ctx.Service() == nil {
		return nil, nil
	}
	host := ctx.Service().Host()
	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	if ds := diskSet; ds != nil && ds.IsSeen(host) {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, err
	}

	client := mcpinfra.NewClient(ctx, httpClient, urlx.Path)

	// 1. Capability control: does the server support JSON-RPC batching at all?
	//    Send a *small* batch of two harmless pings (distinct ids). If the server
	//    does not answer with a 2-element array (it rejects batching, e.g. a
	//    single -32600 object, or collapses the array), there is nothing to
	//    amplify — a server that never honours a batch cannot be flooded by one.
	baseline := []json.RawMessage{
		mcpinfra.MarshalRequest(1, "ping", nil),
		mcpinfra.MarshalRequest(2, "ping", nil),
	}
	baselineBody, err := json.Marshal(baseline)
	if err != nil {
		return nil, err
	}
	baseResp, _, err := client.PostRaw(baselineBody)
	if err != nil || baseResp == "" {
		return nil, nil
	}
	var baseArr []mcpinfra.JSONRPCResponse
	if uerr := json.Unmarshal([]byte(mcpinfra.ExtractJSONFromSSE(baseResp)), &baseArr); uerr != nil {
		// Not an array response => the server does not process batches.
		return nil, nil
	}
	if len(baseArr) != len(baseline) {
		// The server did not process both entries of even a 2-element batch, so
		// it does not honour batching the way an amplifiable server would.
		return nil, nil
	}

	// 2. Oversized probe: a single array of oversizedBatchSize harmless pings
	//    (distinct ids). ping is a no-op — never a state-changing method.
	oversized := make([]json.RawMessage, 0, oversizedBatchSize)
	for i := 0; i < oversizedBatchSize; i++ {
		oversized = append(oversized, mcpinfra.MarshalRequest(1000+i, "ping", nil))
	}
	oversizedBody, err := json.Marshal(oversized)
	if err != nil {
		return nil, err
	}
	oversizedResp, _, err := client.PostRaw(oversizedBody)
	if err != nil || oversizedResp == "" {
		return nil, nil
	}

	var results []mcpinfra.JSONRPCResponse
	if uerr := json.Unmarshal([]byte(mcpinfra.ExtractJSONFromSSE(oversizedResp)), &results); uerr != nil {
		// The server rejected the oversized batch (e.g. a single error object)
		// rather than processing it — that is the safe behaviour.
		return nil, nil
	}

	// 3. Confirm amplification ONLY when the server fully processed the oversized
	//    batch: nearly every element answered AND no element is a batch-size /
	//    rate-limit / invalid-request error. A server that caps, rate-limits, or
	//    rejects the array must NOT be flagged.
	processed := len(results)
	for i := range results {
		if isBatchLimitError(results[i].Error) {
			return nil, nil
		}
	}
	threshold := int(float64(oversizedBatchSize) * amplificationRatio)
	if processed < threshold {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			ModuleID:      ModuleID,
			RecordKind:    output.RecordKindCandidate,
			EvidenceGrade: output.EvidenceGradeDifferential,
			URL:           urlx.String(),
			Matched:       urlx.String(),
			Request:       string(ctx.Request().Raw()),
			MatcherStatus: true,
			ExtractedResults: []string{
				fmt.Sprintf("oversized batch sent: %d ping requests", oversizedBatchSize),
				fmt.Sprintf("batch responses processed: %d", processed),
			},
			Info: output.Info{
				Name:        "MCP Large JSON-RPC Batch Processing Candidate",
				Description: "The server processed nearly every element of a 200-ping JSON-RPC batch after a two-element control. This shows a high batch limit at the tested size; it does not prove an unbounded limit, missing long-window rate controls, resource exhaustion, or service degradation.",
				Severity:    severity.Medium,
				Confidence:  severity.Firm,
				Tags:        []string{"mcp", "dos", "rate-limit"},
				Reference:   []string{"https://www.jsonrpc.org/specification"},
			},
			Metadata: map[string]any{"batch_size": oversizedBatchSize, "processed": processed, "service_degradation_observed": false, "resource_exhaustion_measured": false, "rate_limit_window_tested": false},
		},
	}, nil
}

// isBatchLimitError reports whether a JSON-RPC error indicates the server
// capped, rate-limited, or rejected the oversized batch rather than processing
// it. Such an error is a *safe* signal — the server bounded the work — so its
// presence must suppress a finding.
func isBatchLimitError(e *mcpinfra.JSONRPCError) bool {
	if e == nil {
		return false
	}
	if e.Code == -32600 { // Invalid Request — the batch was rejected.
		return true
	}
	msg := strings.ToLower(e.Message)
	for _, kw := range batchLimitKeywords {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	return false
}

// batchLimitKeywords are error-message substrings that indicate the server
// bounded/rejected the oversized batch rather than processing it.
var batchLimitKeywords = []string{"rate", "limit", "too many", "too large", "429", "batch size", "exceed"}
