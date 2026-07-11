package mcp_completion_enum

import (
	"fmt"
	"regexp"
	"strings"

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

	var findings []*output.ResultEvent
	identity := ctx.Request().IdentityFingerprint()

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
				kind, grade, sev, reason := classifyCompletionValues(res.Completion.Values)
				findings = append(findings, &output.ResultEvent{
					ModuleID:      ModuleID,
					RecordKind:    kind,
					EvidenceGrade: grade,
					URL:           urlx.String(),
					Matched:       urlx.String(),
					Request:       string(ctx.Request().Raw()),
					ExtractedResults: append(
						[]string{fmt.Sprintf("prompt=%s arg=%s", p.Name, arg.Name)},
						safeCompletionValues(res.Completion.Values)...,
					),
					Info: output.Info{
						Name: "MCP Prompt Argument Completion Values Returned",
						Description: fmt.Sprintf(
							"Prompt %q returned %d completion value(s) for argument %q. %s",
							p.Name, len(res.Completion.Values), arg.Name, reason),
						Severity:   sev,
						Confidence: confidenceForCompletion(kind),
						Tags:       []string{"mcp", "info-disclosure", "enumeration"},
						Reference:  []string{"https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/completion"},
					},
					Metadata: map[string]any{"identity": identity, "anonymous": identity == "anonymous", "value_count": len(res.Completion.Values), "authorization_compared": false},
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
				kind, grade, sev, reason := classifyCompletionValues(res.Completion.Values)
				findings = append(findings, &output.ResultEvent{
					ModuleID:      ModuleID,
					RecordKind:    kind,
					EvidenceGrade: grade,
					URL:           urlx.String(),
					Matched:       tpl.URITemplate,
					Request:       string(ctx.Request().Raw()),
					ExtractedResults: append(
						[]string{fmt.Sprintf("template=%s placeholder=%s", tpl.URITemplate, ph)},
						safeCompletionValues(res.Completion.Values)...,
					),
					Info: output.Info{
						Name: "MCP Resource Template Completion Values Returned",
						Description: fmt.Sprintf(
							"Resource template %q returned %d completion value(s) for placeholder %q. %s",
							tpl.URITemplate, len(res.Completion.Values), ph, reason),
						Severity:   sev,
						Confidence: confidenceForCompletion(kind),
						Tags:       []string{"mcp", "info-disclosure", "enumeration"},
						Reference:  []string{"https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/completion"},
					},
					Metadata: map[string]any{"identity": identity, "anonymous": identity == "anonymous", "value_count": len(res.Completion.Values), "authorization_compared": false},
				})
			}
		}
	}

	return findings, nil
}

var placeholderRe = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`)
var sensitiveCompletionValue = regexp.MustCompile(`(?i)(?:^gh[pousr]_[0-9a-z]{36,}$|^xox[abprs]-[0-9a-z-]{10,}$|^sk_live_[0-9a-z]{16,}$|^-----BEGIN .*PRIVATE KEY-----|^[^@\s]+@[^@\s]+\.[^@\s]+$|^(?:/etc/|/home/|/users/|~?/?\.ssh/|[a-z]:\\))`)

func classifyCompletionValues(values []string) (output.RecordKind, output.EvidenceGrade, severity.Severity, string) {
	for _, value := range values {
		if sensitiveCompletionValue.MatchString(strings.TrimSpace(value)) {
			return output.RecordKindCandidate, output.EvidenceGradeCandidate, severity.Medium,
				"At least one value resembles identity data, a private credential, or a sensitive filesystem path. Authorization and downstream access were not tested."
		}
	}
	return output.RecordKindObservation, output.EvidenceGradeObservation, severity.Info,
		"Returning completion values is normal MCP behavior; value sensitivity and authorization were not established."
}

func safeCompletionValues(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if sensitiveCompletionValue.MatchString(trimmed) && (strings.HasPrefix(trimmed, "gh") || strings.HasPrefix(trimmed, "xox") || strings.HasPrefix(trimmed, "sk_live_") || strings.Contains(trimmed, "PRIVATE KEY")) {
			result = append(result, "<credential-shaped completion value redacted>")
			continue
		}
		result = append(result, modkit.Truncate(trimmed, 160))
	}
	return result
}

func confidenceForCompletion(kind output.RecordKind) severity.Confidence {
	if kind == output.RecordKindCandidate {
		return severity.Firm
	}
	return severity.Tentative
}

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
