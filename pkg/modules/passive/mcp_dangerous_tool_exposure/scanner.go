// Package mcp_dangerous_tool_exposure passively inventories the tools advertised
// by an MCP server and flags those whose names indicate high-impact, side-
// effecting capabilities (code execution, file write/delete, outbound fetch,
// raw SQL, secret access). It maps to the OWASP MCP "over-scoped permissions"
// risk: exposing such tools widens the blast radius of any prompt-injection,
// missing-auth, or argument-injection flaw. It sends no new traffic.
package mcp_dangerous_tool_exposure

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	mcpinfra "github.com/vigolium/vigolium/pkg/modules/infra/mcp"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("passive_mcp_dangerous_tool_exposure"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// Capability classification works on whole tokens of the tool name (split on
// separators and camelCase), NOT raw substrings — so "retrieval" is not read as
// "eval" and "search_query" is not read as SQL. Descriptions are left to the
// description-injection detector.
var (
	codeExecTokens    = setOf("exec", "eval", "shell", "spawn", "subprocess", "cmd", "command", "bash", "powershell")
	destructiveTokens = setOf("delete", "remove", "unlink", "rmdir", "rm", "truncate", "overwrite", "drop", "write")
	fetchTokens       = setOf("fetch", "download", "curl", "wget", "proxy", "webhook", "browse", "http")
	secretTokens      = setOf("secret", "secrets", "credential", "credentials", "password", "passwd", "apikey", "privatekey")
	// sqlQualifiers gate the broad "query" token: only "execute_query" /
	// "run_query" / "raw_query" style names count as raw-SQL, not "search_query".
	sqlQualifiers = setOf("execute", "run", "raw", "db", "database", "exec")
)

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if ctx == nil || ctx.Response() == nil {
		return nil, nil
	}
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	// Only look at MCP-shaped responses that carry a tools list.
	flags := mcpinfra.Detect(ctx)
	if !flags.HasJSONRPC {
		return nil, nil
	}
	body := mcpinfra.ExtractJSONFromSSE(ctx.Response().BodyToString())
	if !strings.Contains(body, `"tools"`) {
		return nil, nil
	}
	tools, err := mcpinfra.ParseToolsListResponse(body)
	if err != nil || tools == nil || len(tools.Tools) == 0 {
		return nil, nil
	}

	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	dedupKey := urlx.Host + urlx.Path
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	// Group matched tools by capability label (stable order for reproducibility).
	grouped := map[string][]string{}
	for _, t := range tools.Tools {
		if label := classify(t.Name); label != "" {
			grouped[label] = append(grouped[label], t.Name)
		}
	}
	if len(grouped) == 0 {
		return nil, nil
	}

	labels := make([]string, 0, len(grouped))
	for label := range grouped {
		labels = append(labels, label)
	}
	sort.Strings(labels)

	var evidence []string
	total := 0
	for _, label := range labels {
		names := grouped[label]
		sort.Strings(names)
		total += len(names)
		evidence = append(evidence, fmt.Sprintf("%s: %s", label, strings.Join(names, ", ")))
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			RecordKind:       output.RecordKindObservation,
			EvidenceGrade:    output.EvidenceGradeObservation,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(ctx.Request().Raw()),
			Response:         string(ctx.Response().Raw()),
			MatcherStatus:    true,
			ExtractedResults: evidence,
			Info: output.Info{
				Name:        "MCP Dangerous Tool Exposure",
				Description: fmt.Sprintf("MCP server at %s advertises %d tool name(s) associated with high-impact capabilities. This is capability inventory only; authorization, arguments, human approval, and invocation success were not tested.", urlx.Host, total),
				Severity:    severity.Low,
				Confidence:  severity.Firm,
				Tags:        []string{"mcp", "excessive-permissions", "api-security"},
				Reference:   []string{"https://modelcontextprotocol.io/specification/2025-11-25/server/tools"},
			},
			Metadata: map[string]any{"tool_count": total, "authorization_tested": false, "tools_invoked": false, "impact_confirmed": false},
		},
	}, nil
}

// classify returns the high-impact capability label a tool name matches, or ""
// if the name looks benign. SQL is checked first so "execute_query" is labelled
// database access rather than generic code execution.
func classify(name string) string {
	toks := tokenize(name)
	set := map[string]bool{}
	for _, t := range toks {
		set[t] = true
	}
	switch {
	case set["sql"] || (set["query"] && anyIn(toks, sqlQualifiers)):
		return "raw database/SQL"
	case anyIn(toks, codeExecTokens):
		return "code execution"
	case anyIn(toks, destructiveTokens):
		return "destructive write/delete"
	case anyIn(toks, fetchTokens):
		return "outbound fetch (SSRF surface)"
	case anyIn(toks, secretTokens) || (set["key"] && (set["api"] || set["private"] || set["access"] || set["secret"])):
		return "secret/credential access"
	}
	return ""
}

// tokenize splits a tool name into lowercased tokens on separators and camelCase
// boundaries: "deleteAccount" -> [delete account], "get_api_key" -> [get api key].
func tokenize(name string) []string {
	var toks []string
	var cur []rune
	runes := []rune(name)
	flush := func() {
		if len(cur) > 0 {
			toks = append(toks, strings.ToLower(string(cur)))
			cur = nil
		}
	}
	for i, r := range runes {
		switch {
		case r == '_' || r == '-' || r == '/' || r == '.' || r == ' ' || r == ':':
			flush()
		case unicode.IsUpper(r) && i > 0 && (unicode.IsLower(runes[i-1]) || unicode.IsDigit(runes[i-1])):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return toks
}

func setOf(vals ...string) map[string]bool {
	m := make(map[string]bool, len(vals))
	for _, v := range vals {
		m[v] = true
	}
	return m
}

func anyIn(toks []string, set map[string]bool) bool {
	for _, t := range toks {
		if set[t] {
			return true
		}
	}
	return false
}
