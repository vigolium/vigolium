package mcp_completion_enum

import (
	"fmt"
	"regexp"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	mcpinfra "github.com/vigolium/vigolium/pkg/modules/infra/mcp"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	maxPrompts   = 8
	maxArgs      = 6
	maxTemplates = 8
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
		ds: dedup.LazyDiskSet("mcp_completion_enum"),
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

	client := mcpinfra.NewClient(ctx, httpClient, urlx.Path)
	if _, err := client.Initialize(); err != nil {
		return nil, nil
	}
	_ = client.SendInitializedNotification()

	var findings []*output.ResultEvent

	// Prompt argument completion
	if prompts, err := client.ListPrompts(); err == nil && prompts != nil {
		limit := len(prompts.Prompts)
		if limit > maxPrompts {
			limit = maxPrompts
		}
		for i := 0; i < limit; i++ {
			p := prompts.Prompts[i]
			argLimit := len(p.Arguments)
			if argLimit > maxArgs {
				argLimit = maxArgs
			}
			for ai := 0; ai < argLimit; ai++ {
				arg := p.Arguments[ai]
				res, _, err := client.CompletePrompt(3000+i*100+ai, p.Name, arg.Name, "")
				if err != nil || res == nil || len(res.Completion.Values) == 0 {
					continue
				}
				findings = append(findings, &output.ResultEvent{
					URL:     urlx.String(),
					Matched: urlx.String(),
					ExtractedResults: append(
						[]string{fmt.Sprintf("prompt=%s arg=%s", p.Name, arg.Name)},
						res.Completion.Values...,
					),
					Info: output.Info{
						Name: "MCP Prompt Argument Values Disclosed via completion/complete",
						Description: fmt.Sprintf(
							"Prompt %q exposes %d completion value(s) for argument %q without authentication.",
							p.Name, len(res.Completion.Values), arg.Name),
						Severity:   severity.Medium,
						Confidence: severity.Firm,
						Tags:       []string{"mcp", "info-disclosure", "enumeration"},
						Reference:  []string{"https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/completion"},
					},
				})
			}
		}
	}

	// Resource template placeholder completion
	if templates, err := client.ListResourceTemplates(); err == nil && templates != nil {
		limit := len(templates.ResourceTemplates)
		if limit > maxTemplates {
			limit = maxTemplates
		}
		for ti := 0; ti < limit; ti++ {
			tpl := templates.ResourceTemplates[ti]
			placeholders := extractPlaceholders(tpl.URITemplate)
			for pi, ph := range placeholders {
				res, _, err := client.CompleteResource(4000+ti*100+pi, tpl.URITemplate, ph, "")
				if err != nil || res == nil || len(res.Completion.Values) == 0 {
					continue
				}
				findings = append(findings, &output.ResultEvent{
					URL:     urlx.String(),
					Matched: tpl.URITemplate,
					ExtractedResults: append(
						[]string{fmt.Sprintf("template=%s placeholder=%s", tpl.URITemplate, ph)},
						res.Completion.Values...,
					),
					Info: output.Info{
						Name: "MCP Resource Template Values Disclosed via completion/complete",
						Description: fmt.Sprintf(
							"Resource template %q exposes %d completion value(s) for placeholder %q without authentication.",
							tpl.URITemplate, len(res.Completion.Values), ph),
						Severity:   severity.Medium,
						Confidence: severity.Firm,
						Tags:       []string{"mcp", "info-disclosure", "enumeration"},
						Reference:  []string{"https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/completion"},
					},
				})
			}
		}
	}

	return findings, nil
}

var placeholderRe = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`)

func extractPlaceholders(tpl string) []string {
	matches := placeholderRe.FindAllStringSubmatch(tpl, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if _, ok := seen[m[1]]; ok {
			continue
		}
		seen[m[1]] = struct{}{}
		out = append(out, m[1])
	}
	return out
}
