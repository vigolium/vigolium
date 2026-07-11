package mcp_tool_definition_drift

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	mcpinfra "github.com/vigolium/vigolium/pkg/modules/infra/mcp"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// toolsListIDs are the DISTINCT JSON-RPC ids used for the repeated tools/list
// probes. The vigolium http.Requester caches on request bytes, so reusing one
// id would return the same cached response and mask a mutating server. Distinct
// ids force three real round-trips.
var toolsListIDs = []int{2, 1002, 2002}

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
		ds: dedup.LazyDiskSet("mcp_tool_definition_drift"),
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

	// Snapshot tools/list several times, each with a DISTINCT id so the response
	// cache can't hide a mutating server. Each snapshot is a name -> Tool map so
	// tool ORDER is irrelevant (map iteration order is not drift).
	var fetches []map[string]mcpinfra.Tool
	for _, id := range toolsListIDs {
		body, _, err := client.PostRaw(mcpinfra.MarshalRequest(id, "tools/list", nil))
		if err != nil || body == "" {
			continue
		}
		res, err := mcpinfra.ParseToolsListResponse(body)
		if err != nil || res == nil || len(res.Tools) == 0 {
			continue
		}
		byName := make(map[string]mcpinfra.Tool, len(res.Tools))
		for _, t := range res.Tools {
			byName[t.Name] = t
		}
		fetches = append(fetches, byName)
	}

	// Need at least two comparable snapshots to conclude anything.
	if len(fetches) < 2 {
		return nil, nil
	}

	// Union of tool names across every successful snapshot, sorted so ordering
	// differences never register as drift.
	nameSet := map[string]struct{}{}
	for _, f := range fetches {
		for name := range f {
			nameSet[name] = struct{}{}
		}
	}
	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	sort.Strings(names)

	var evidence []string
	definitionChanges := 0
	availabilityChanges := 0
	for _, name := range names {
		// Collect the distinct fingerprints for this tool across snapshots and
		// track whether it was absent from any snapshot.
		var variants []mcpinfra.Tool
		seenFP := map[string]struct{}{}
		presentCount := 0
		for _, f := range fetches {
			t, ok := f[name]
			if !ok {
				continue
			}
			presentCount++
			fp := fingerprint(t)
			if _, dup := seenFP[fp]; dup {
				continue
			}
			seenFP[fp] = struct{}{}
			variants = append(variants, t)
		}

		missingSomewhere := presentCount < len(fetches)
		// A stable tool is present in every snapshot with one fingerprint.
		if len(seenFP) <= 1 && !missingSomewhere {
			continue
		}

		if missingSomewhere {
			availabilityChanges++
			evidence = append(evidence, fmt.Sprintf(
				"tool %q present in only %d/%d tools/list fetches (definition appears/disappears)",
				name, presentCount, len(fetches),
			))
		}
		if len(variants) > 1 {
			definitionChanges++
			a, b := variants[0], variants[1]
			evidence = append(evidence, fmt.Sprintf(
				"tool %q changed between fetches: description %q -> %q; inputSchema %s -> %s",
				name,
				modkit.Truncate(a.Description, 150), modkit.Truncate(b.Description, 150),
				modkit.Truncate(string(a.InputSchema), 150), modkit.Truncate(string(b.InputSchema), 150),
			))
		}
	}

	// No drift across all snapshots -> a stable server, which must NOT be
	// flagged. This is what keeps the module from firing on every MCP server.
	if len(evidence) == 0 {
		return nil, nil
	}
	kind := output.RecordKindObservation
	grade := output.EvidenceGradeObservation
	sev := severity.Info
	name := "MCP Tool Availability Drift Observed"
	description := fmt.Sprintf("MCP server at %s returned a changing tool set across repeated tools/list calls. Dynamic catalogs, routing, or authorization context may explain this; no approved definition was replaced.", urlx.Host)
	if definitionChanges > 0 {
		kind = output.RecordKindCandidate
		grade = output.EvidenceGradeDifferential
		sev = severity.Medium
		name = "MCP Tool Definition Drift Candidate"
		description = fmt.Sprintf("MCP server at %s returned different descriptions or input schemas for the same tool across repeated calls. This is a rug-pull candidate; client approval state and post-approval replacement were not observed.", urlx.Host)
	}

	return []*output.ResultEvent{{
		ModuleID:         ModuleID,
		RecordKind:       kind,
		EvidenceGrade:    grade,
		Host:             urlx.Host,
		URL:              urlx.String(),
		Matched:          urlx.String(),
		Request:          string(ctx.Request().Raw()),
		MatcherStatus:    true,
		ExtractedResults: evidence,
		Info: output.Info{
			Name:        name,
			Description: description,
			Severity:    sev,
			Confidence:  severity.Tentative,
			Tags:        []string{"mcp", "rug-pull", "integrity"},
			Reference:   []string{"https://modelcontextprotocol.io/specification/2025-11-25/server/tools"},
		},
		Metadata: map[string]any{"snapshot_count": len(fetches), "definition_changes": definitionChanges, "availability_changes": availabilityChanges, "client_approval_observed": false, "rug_pull_confirmed": false},
	}}, nil
}

// fingerprint canonicalises a tool's mutable surface: its description and raw
// input schema. A NUL separator avoids collisions between the two fields.
func fingerprint(t mcpinfra.Tool) string {
	description := strings.Join(strings.Fields(t.Description), " ")
	schema := string(t.InputSchema)
	var parsed any
	if json.Unmarshal(t.InputSchema, &parsed) == nil {
		if canonical, err := json.Marshal(parsed); err == nil {
			schema = string(canonical)
		}
	}
	return description + "\x00" + schema
}
