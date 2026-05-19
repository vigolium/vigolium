package mcp_batch_abuse

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
		ds: dedup.LazyDiskSet("mcp_batch_abuse"),
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
	if ds := m.ds.Get(scanCtx.DedupMgr()); ds != nil && ds.IsSeen(host) {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, err
	}

	// Build a batch with initialize + tools/list, NO session header.
	batch := []json.RawMessage{
		mcpinfra.BuildInitializeRequest(),
		mcpinfra.BuildToolsListRequest(),
	}
	body, err := json.Marshal(batch)
	if err != nil {
		return nil, err
	}

	client := mcpinfra.NewClient(ctx, httpClient, urlx.Path)
	respBody, _, err := client.PostRaw(body)
	if err != nil || respBody == "" {
		return nil, nil
	}

	respBody = mcpinfra.ExtractJSONFromSSE(respBody)

	// Some servers reject batches with -32600 (invalid request) - that's the
	// safe behaviour. We're looking for the case where they happily process it.
	var multiple []mcpinfra.JSONRPCResponse
	if err := json.Unmarshal([]byte(respBody), &multiple); err != nil {
		return nil, nil
	}

	var smuggledOK bool
	var smuggledMethod string
	for _, r := range multiple {
		if r.Error != nil {
			continue
		}
		if len(r.Result) == 0 {
			continue
		}
		// initialize result has serverInfo / protocolVersion; tools result has tools array
		s := string(r.Result)
		if strings.Contains(s, `"tools"`) || strings.Contains(s, `"resources"`) {
			smuggledOK = true
			smuggledMethod = "tools/list (batched)"
			break
		}
	}
	if !smuggledOK {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: []string{smuggledMethod, fmt.Sprintf("batch responses: %d", len(multiple))},
			Info: output.Info{
				Name:        "MCP JSON-RPC Batch Auth Bypass",
				Description: "Server processed a batched JSON-RPC array containing initialize + tools/list without enforcing the per-request session gate. The smuggled tools/list returned a result, indicating batched per-method auth checks are weaker than the singleton path.",
				Severity:    severity.High,
				Confidence:  severity.Firm,
				Tags:        []string{"mcp", "auth-bypass", "json-rpc"},
				Reference:   []string{"https://www.jsonrpc.org/specification"},
			},
		},
	}, nil
}
