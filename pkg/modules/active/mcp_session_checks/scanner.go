package mcp_session_checks

import (
	"fmt"
	"math"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	mcpinfra "github.com/vigolium/vigolium/pkg/modules/infra/mcp"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	sessionSamples       = 4
	minAcceptableLength  = 16
	minAcceptableEntropy = 3.0 // bits per character
	fixationCandidate    = "vigolium-fixation-test-0001"
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
		ds: dedup.LazyDiskSet("mcp_session_checks"),
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

	var findings []*output.ResultEvent
	var samples []string

	// 1. Sample N session IDs by initializing repeatedly.
	for i := 0; i < sessionSamples; i++ {
		client := mcpinfra.NewClient(ctx, httpClient, urlx.Path)
		if _, err := client.Initialize(); err != nil {
			continue
		}
		if sid := client.SessionID(); sid != "" {
			samples = append(samples, sid)
		}
	}

	if len(samples) >= 2 {
		shortest := samples[0]
		for _, s := range samples {
			if len(s) < len(shortest) {
				shortest = s
			}
		}
		ent := shannonEntropy(shortest)
		if len(shortest) < minAcceptableLength || ent < minAcceptableEntropy {
			findings = append(findings, &output.ResultEvent{
				URL:              urlx.String(),
				Matched:          urlx.String(),
				ExtractedResults: append([]string{fmt.Sprintf("len=%d entropy=%.2f", len(shortest), ent)}, samples...),
				Info: output.Info{
					Name:        "MCP Session ID Weakness",
					Description: fmt.Sprintf("Mcp-Session-Id values are short or low-entropy. Length=%d, Shannon entropy=%.2f bits/char.", len(shortest), ent),
					Severity:    severity.Medium,
					Confidence:  severity.Firm,
					Tags:        []string{"mcp", "session", "weak-secret"},
				},
			})
		}
	}

	// 2. Anonymous tools/list attempt.
	{
		client := mcpinfra.NewClient(ctx, httpClient, urlx.Path)
		// Skip initialize -- talk straight to tools/list.
		body, _, err := client.PostRaw(mcpinfra.BuildToolsListRequest())
		if err == nil {
			if r, perr := mcpinfra.ParseToolsListResponse(body); perr == nil && r != nil && len(r.Tools) > 0 {
				findings = append(findings, &output.ResultEvent{
					URL:              urlx.String(),
					Matched:          urlx.String(),
					ExtractedResults: []string{fmt.Sprintf("%d tools enumerable without session", len(r.Tools))},
					Info: output.Info{
						Name:        "MCP Anonymous Tool Enumeration (No Session Required)",
						Description: "tools/list succeeded without performing initialize or supplying Mcp-Session-Id - the server does not require a session.",
						Severity:    severity.Medium,
						Confidence:  severity.Certain,
						Tags:        []string{"mcp", "auth-bypass", "session"},
					},
				})
			}
		}
	}

	// 3. Session fixation: provide our own Mcp-Session-Id header during initialize.
	{
		client := mcpinfra.NewClient(ctx, httpClient, urlx.Path)
		client.SetSessionID(fixationCandidate)
		if _, err := client.Initialize(); err == nil {
			if got := client.SessionID(); got == fixationCandidate {
				if tools, err := client.ListTools(); err == nil && tools != nil {
					findings = append(findings, &output.ResultEvent{
						URL:              urlx.String(),
						Matched:          urlx.String(),
						ExtractedResults: []string{fmt.Sprintf("server accepted client-supplied SID %q", fixationCandidate)},
						Info: output.Info{
							Name:        "MCP Session Fixation (Attacker-Supplied Mcp-Session-Id)",
							Description: "Server accepted an attacker-controlled Mcp-Session-Id during initialize and continued to honour it for tools/list. This is a session-fixation primitive.",
							Severity:    severity.High,
							Confidence:  severity.Firm,
							Tags:        []string{"mcp", "session", "auth-bypass"},
						},
					})
				}
			}
		}
	}

	return findings, nil
}

// shannonEntropy returns the Shannon entropy of s in bits per character.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	var ent float64
	n := float64(len(s))
	for _, c := range counts {
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent
}
