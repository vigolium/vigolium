package mcp_method_enum

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	mcpinfra "github.com/vigolium/vigolium/pkg/modules/infra/mcp"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// methodWordlist is intentionally short - we keep the false-positive risk
// low and the request count manageable. Add to it deliberately.
var methodWordlist = []string{
	"debug/info",
	"debug/dump",
	"debug/state",
	"debug/eval",
	"admin/users",
	"admin/sessions",
	"admin/reload",
	"admin/shutdown",
	"_internal/diagnostics",
	"_internal/echo",
	"system/info",
	"system/exec",
	"logging/getLevel",
	"experimental/echo",
	"experimental/run",
	"server/restart",
}

// JSON-RPC standard "method not found" error code.
const errMethodNotFound = -32601

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
		ds: dedup.LazyDiskSet("mcp_method_enum"),
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
	if _, err := client.Initialize(); err != nil {
		return nil, nil
	}
	_ = client.SendInitializedNotification()

	// Negative control: probe a guaranteed-nonexistent method first to learn how
	// this server answers unknown methods. Without it, a server that returns a
	// result for *any* method (a catch-all) — or that uses a non-standard error
	// code like -32603/-32600 for unknowns — would trip a finding on every single
	// wordlist entry. `unknownCode` is the error code this server uses for methods
	// it doesn't implement; matching it means "not found", same as -32601.
	unknownCode := errMethodNotFound
	{
		controlMethod := "vig-nonexistent-" + utils.RandomString(12)
		body, _, err := client.PostRaw(mcpinfra.MarshalRequest(4999, controlMethod, map[string]any{}))
		if err != nil || body == "" {
			return nil, nil
		}
		resp, perr := mcpinfra.ParseResponse(body)
		if perr != nil || resp == nil {
			return nil, nil
		}
		if resp.Error == nil && len(resp.Result) > 0 {
			// Catch-all: unknown methods return a result. Every wordlist
			// probe would look "exposed" — bail rather than emit noise.
			return nil, nil
		}
		if resp.Error == nil {
			return nil, nil
		}
		unknownCode = resp.Error.Code
	}

	var findings []*output.ResultEvent
	for i, method := range methodWordlist {
		body, _, err := client.PostRaw(mcpinfra.MarshalRequest(5000+i, method, map[string]any{}))
		if err != nil || body == "" {
			continue
		}
		resp, err := mcpinfra.ParseResponse(body)
		if err != nil || resp == nil {
			continue
		}
		isError := resp.Error != nil
		if isError && (resp.Error.Code == errMethodNotFound || resp.Error.Code == unknownCode) {
			continue
		}
		if !isError && len(resp.Result) == 0 {
			continue
		}

		evidence := "JSON-RPC result returned"
		sev := severity.Low
		kind := output.RecordKindCandidate
		grade := output.EvidenceGradeCandidate
		if !isError && len(resp.Result) > 0 {
			evidence = "JSON-RPC result returned (method implemented)"
		} else if isError {
			evidence = fmt.Sprintf("JSON-RPC error code %d (method recognised but rejected)", resp.Error.Code)
			sev = severity.Info
			kind = output.RecordKindObservation
			grade = output.EvidenceGradeObservation
		}

		findings = append(findings, &output.ResultEvent{
			ModuleID:         ModuleID,
			RecordKind:       kind,
			EvidenceGrade:    grade,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(ctx.Request().Raw()),
			ExtractedResults: []string{method, evidence, truncate(body, 200)},
			Info: output.Info{
				Name:        fmt.Sprintf("MCP Non-Standard Method Observed: %s", method),
				Description: fmt.Sprintf("MCP server at %s distinguishes non-standard JSON-RPC method %q from a randomized unknown-method control. This inventories implementation behavior; sensitive data access or privileged side effects were not demonstrated.", urlx.Host, method),
				Severity:    sev,
				Confidence:  severity.Firm,
				Tags:        []string{"mcp", "enumeration", "info-disclosure"},
				Reference:   []string{"https://modelcontextprotocol.io/specification/2025-11-25"},
			},
			Metadata: map[string]any{"method": method, "negative_control_code": unknownCode, "method_invoked": !isError, "impact_confirmed": false},
		})
	}
	return findings, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
