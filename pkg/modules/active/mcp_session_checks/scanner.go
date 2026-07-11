package mcp_session_checks

import (
	"fmt"
	"math"
	"sort"

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
			uniqueLengths, uniqueCount := summarizeSessionSamples(samples)
			kind := output.RecordKindObservation
			grade := output.EvidenceGradeObservation
			sev := severity.Low
			description := fmt.Sprintf("Sampled Mcp-Session-Id values use short length or low character diversity (minimum length=%d, diversity=%.2f bits/char). This is a hardening observation, not a measured brute-force probability.", len(shortest), ent)
			if uniqueCount < len(samples) {
				kind = output.RecordKindCandidate
				grade = output.EvidenceGradeDifferential
				sev = severity.Medium
				description = fmt.Sprintf("Repeated initialization returned only %d unique Mcp-Session-Id value(s) across %d samples, alongside weak length/diversity characteristics. Cross-client session reuse or hijack impact was not tested.", uniqueCount, len(samples))
			}
			findings = append(findings, &output.ResultEvent{
				ModuleID:      ModuleID,
				RecordKind:    kind,
				EvidenceGrade: grade,
				URL:           urlx.String(),
				Matched:       urlx.String(),
				Request:       string(ctx.Request().Raw()),
				ExtractedResults: []string{
					fmt.Sprintf("sample_count=%d unique_count=%d", len(samples), uniqueCount),
					fmt.Sprintf("minimum_length=%d character_diversity=%.2f", len(shortest), ent),
					fmt.Sprintf("observed_lengths=%v (session values redacted)", uniqueLengths),
				},
				Info: output.Info{
					Name:        "MCP Session ID Weakness",
					Description: description,
					Severity:    sev,
					Confidence:  severity.Firm,
					Tags:        []string{"mcp", "session", "weak-secret"},
				},
				Metadata: map[string]any{"sample_count": len(samples), "unique_count": uniqueCount, "session_values_redacted": true, "hijack_tested": false},
			})
		}
	}

	// issuesSessions is true when the server handed us at least one Mcp-Session-Id
	// during sampling. A server that never issues a session header can't be
	// vulnerable to *session* fixation (there is no session to fixate), and our
	// client would otherwise still report the injected candidate SID simply
	// because the server never replaced it — the original false-positive source.
	issuesSessions := len(samples) > 0

	// 2. Anonymous tools/list attempt.
	anonymousWorks := false
	{
		client := mcpinfra.NewClient(ctx, httpClient, urlx.Path)
		// Skip initialize -- talk straight to tools/list (fresh client, no session).
		if r, err := client.ListTools(); err == nil && r != nil && len(r.Tools) > 0 {
			anonymousWorks = true
			findings = append(findings, &output.ResultEvent{
				ModuleID:         ModuleID,
				RecordKind:       output.RecordKindObservation,
				EvidenceGrade:    output.EvidenceGradeObservation,
				URL:              urlx.String(),
				Matched:          urlx.String(),
				Request:          string(ctx.Request().Raw()),
				ExtractedResults: []string{fmt.Sprintf("%d tools enumerable without an MCP session", len(r.Tools))},
				Info: output.Info{
					Name:        "MCP Tool List Available Without Session",
					Description: "tools/list succeeded without initialize or Mcp-Session-Id. MCP sessions are optional and existing HTTP credentials may still apply, so this is protocol inventory rather than an authentication bypass.",
					Severity:    severity.Info,
					Confidence:  severity.Certain,
					Tags:        []string{"mcp", "enumeration", "session"},
				},
				Metadata: map[string]any{"mcp_session_supplied": false, "http_identity": ctx.Request().IdentityFingerprint(), "authentication_bypass_proven": false},
			})
		}
	}

	// 3. Session fixation: provide our own Mcp-Session-Id header during initialize.
	// Only meaningful when the server (a) actually issues session IDs and (b)
	// enforces them — i.e. anonymous tools/list was refused above. Without both
	// preconditions a "success" here is just a sessionless/open server, not a
	// fixation primitive, so we skip to avoid the false positive.
	if issuesSessions && !anonymousWorks {
		client := mcpinfra.NewClient(ctx, httpClient, urlx.Path)
		client.SetSessionID(fixationCandidate)
		if _, err := client.Initialize(); err == nil {
			if got := client.IssuedSessionID(); got == fixationCandidate {
				if tools, err := client.ListTools(); err == nil && tools != nil {
					findings = append(findings, &output.ResultEvent{
						ModuleID:         ModuleID,
						RecordKind:       output.RecordKindCandidate,
						EvidenceGrade:    output.EvidenceGradeDifferential,
						URL:              urlx.String(),
						Matched:          urlx.String(),
						Request:          string(ctx.Request().Raw()),
						ExtractedResults: []string{"initialize response explicitly echoed the attacker-chosen Mcp-Session-Id (value redacted)", "tools/list subsequently succeeded with that ID"},
						Info: output.Info{
							Name:        "MCP Session Fixation Candidate (Attacker-Supplied Mcp-Session-Id)",
							Description: "The initialize response explicitly echoed an attacker-chosen Mcp-Session-Id and tools/list honored it. This is a fixation candidate; adoption by a victim identity and reuse from a second client were not demonstrated.",
							Severity:    severity.High,
							Confidence:  severity.Firm,
							Tags:        []string{"mcp", "session", "auth-bypass"},
						},
						Metadata: map[string]any{"server_echoed_supplied_id": true, "second_client_replay_tested": false, "victim_adoption_tested": false},
					})
				}
			}
		}
	}

	return findings, nil
}

func summarizeSessionSamples(samples []string) ([]int, int) {
	lengths := make([]int, 0, len(samples))
	unique := make(map[string]bool)
	for _, sample := range samples {
		lengths = append(lengths, len(sample))
		unique[sample] = true
	}
	sort.Ints(lengths)
	return lengths, len(unique)
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
