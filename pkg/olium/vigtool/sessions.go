package vigtool

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium/tool"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	defaultSessionListLimit = 25
	maxSessionListLimit     = 200
	defaultFindingsLimit    = 50
	maxFindingsLimit        = 500
)

// NewListSessionsTool returns the list_sessions tool — a paginated list of
// agent runs (autopilot, swarm, query, …) for the configured project.
func NewListSessionsTool(ctx *SessionsContext) tool.Tool {
	return &listSessionsTool{ctx: ctx}
}

type listSessionsTool struct{ ctx *SessionsContext }

func (*listSessionsTool) Name() string     { return "list_sessions" }
func (*listSessionsTool) Label() string    { return "List agent sessions" }
func (*listSessionsTool) Category() string { return tool.CategoryVigolium }
func (*listSessionsTool) IsReadOnly() bool { return true }
func (*listSessionsTool) Description() string {
	return "List prior vigolium agent sessions (autopilot/swarm/query/pipeline runs) for the current project, " +
		"newest first. Each entry includes the run UUID, mode, status, target, finding count, and timing. " +
		"Use get_session for full detail of a specific run."
}

func (*listSessionsTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"mode": map[string]any{
				"type":        "string",
				"enum":        []string{"autopilot", "swarm", "query", "pipeline", "scan"},
				"description": "Filter by run mode. Empty = all modes.",
			},
			"limit": map[string]any{
				"type":        "integer",
				"description": fmt.Sprintf("Max sessions to return (default %d, cap %d).", defaultSessionListLimit, maxSessionListLimit),
			},
			"offset": map[string]any{
				"type":        "integer",
				"description": "Pagination offset. Default 0.",
			},
		},
	}
}

func (l *listSessionsTool) Execute(ctx context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	if res, ok := requireRepo(l.ctx.repo(), "list_sessions"); !ok {
		return res, nil
	}

	limit := clampLimit(argsInt(args, "limit"), defaultSessionListLimit, maxSessionListLimit)
	offset := argsInt(args, "offset")
	if offset < 0 {
		offset = 0
	}
	mode := argsString(args, "mode")

	runs, total, err := l.ctx.Repo.ListAgenticScans(ctx, l.ctx.ProjectUUID, mode, limit, offset)
	if err != nil {
		return tool.Result{
			Content: fmt.Sprintf("list_sessions: %v", err),
			IsError: true,
		}, nil
	}

	out := struct {
		Total    int64           `json:"total"`
		Limit    int             `json:"limit"`
		Offset   int             `json:"offset"`
		Sessions []sessionRecord `json:"sessions"`
	}{
		Total:    total,
		Limit:    limit,
		Offset:   offset,
		Sessions: make([]sessionRecord, 0, len(runs)),
	}
	for _, r := range runs {
		out.Sessions = append(out.Sessions, summarizeSession(r))
	}

	body, _ := json.Marshal(out)
	return tool.Result{
		Content: string(body),
		Details: map[string]any{
			"total":    total,
			"returned": len(runs),
		},
	}, nil
}

// NewGetSessionTool returns the get_session tool — full detail for one run.
func NewGetSessionTool(ctx *SessionsContext) tool.Tool {
	return &getSessionTool{ctx: ctx}
}

type getSessionTool struct{ ctx *SessionsContext }

func (*getSessionTool) Name() string     { return "get_session" }
func (*getSessionTool) Label() string    { return "Get agent session" }
func (*getSessionTool) Category() string { return tool.CategoryVigolium }
func (*getSessionTool) IsReadOnly() bool { return true }
func (*getSessionTool) Description() string {
	return "Fetch the full record for a single agent session by UUID. Returns config, status, " +
		"timing, token usage, finding/record counts, and the session directory path so you can " +
		"read its artifacts (runtime.log, extensions/, attack-plan, etc.) with read_file / ls."
}

func (*getSessionTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"uuid": map[string]any{
				"type":        "string",
				"description": "Session UUID (from list_sessions).",
			},
		},
		"required": []string{"uuid"},
	}
}

func (g *getSessionTool) Execute(ctx context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	if res, ok := requireRepo(g.ctx.repo(), "get_session"); !ok {
		return res, nil
	}
	uuid := argsString(args, "uuid")
	if uuid == "" {
		return tool.Result{
			Content: "get_session: 'uuid' is required",
			IsError: true,
		}, nil
	}

	run, err := g.ctx.Repo.GetAgenticScan(ctx, uuid)
	if err != nil {
		return tool.Result{
			Content: fmt.Sprintf("get_session: %v", err),
			IsError: true,
		}, nil
	}
	// Tenant isolation: GetAgenticScan looks up by UUID alone, so a cross-project
	// UUID would otherwise leak another project's session record. Match the guard
	// used by replay_request / list_sessions and refuse out-of-project reads.
	if g.ctx.ProjectUUID != "" && run.ProjectUUID != g.ctx.ProjectUUID {
		return tool.Result{
			Content: fmt.Sprintf("get_session: session %q does not belong to the current project", uuid),
			IsError: true,
		}, nil
	}

	out := struct {
		sessionRecord
		PhasesRun             []string               `json:"phases_run,omitempty"`
		ModuleNames           []string               `json:"module_names,omitempty"`
		Model                 string                 `json:"model,omitempty"`
		AgentName             string                 `json:"agent_name,omitempty"`
		Protocol              string                 `json:"protocol,omitempty"`
		SessionDir            string                 `json:"session_dir,omitempty"`
		SessionID             string                 `json:"session_id,omitempty"`
		ParentAgenticScanUUID string                 `json:"parent_agentic_scan_uuid,omitempty"`
		ErrorMessage          string                 `json:"error_message,omitempty"`
		TokenUsage            map[string]interface{} `json:"token_usage,omitempty"`
		EstCostUSD            float64                `json:"estimated_cost_usd,omitempty"`
	}{
		sessionRecord:         summarizeSession(run),
		PhasesRun:             run.PhasesRun,
		ModuleNames:           run.ModuleNames,
		Model:                 run.Model,
		AgentName:             run.AgentName,
		Protocol:              run.Protocol,
		SessionDir:            run.SessionDir,
		SessionID:             run.SessionID,
		ParentAgenticScanUUID: run.ParentAgenticScanUUID,
		ErrorMessage:          run.ErrorMessage,
		TokenUsage:            run.TokenUsage,
		EstCostUSD:            run.EstimatedCostUSD,
	}

	body, _ := json.MarshalIndent(out, "", "  ")
	return tool.Result{
		Content: string(body),
		Details: map[string]any{
			"uuid":          run.UUID,
			"mode":          run.Mode,
			"status":        run.Status,
			"finding_count": run.FindingCount,
		},
	}, nil
}

// NewListFindingsTool returns the list_findings tool — paginated findings
// with optional severity / module / scan filters.
func NewListFindingsTool(ctx *SessionsContext) tool.Tool {
	return &listFindingsTool{ctx: ctx}
}

type listFindingsTool struct{ ctx *SessionsContext }

func (*listFindingsTool) Name() string     { return "list_findings" }
func (*listFindingsTool) Label() string    { return "List findings" }
func (*listFindingsTool) Category() string { return tool.CategoryVigolium }
func (*listFindingsTool) IsReadOnly() bool { return true }
func (*listFindingsTool) Description() string {
	return "Query findings persisted by vigolium scans, with optional filters by scan UUID, severity, " +
		"module, and free-text search. Returns the most recent matches first. Use this to inspect what " +
		"a prior scan or extension produced before deciding what to do next."
}

func (*listFindingsTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"scan_uuid": map[string]any{
				"type":        "string",
				"description": "Restrict to a single scan UUID (from run_scan / list_sessions).",
			},
			"severity": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string", "enum": severity.AllNames()},
				"description": "Severity allowlist. Empty = all severities.",
			},
			"module": map[string]any{
				"type":        "string",
				"description": "Substring match against module name (e.g. 'xss', 'sqli').",
			},
			"search": map[string]any{
				"type":        "string",
				"description": "Free-text search across description / module ID / matched-at field.",
			},
			"limit": map[string]any{
				"type":        "integer",
				"description": fmt.Sprintf("Max findings to return (default %d, cap %d).", defaultFindingsLimit, maxFindingsLimit),
			},
			"offset": map[string]any{
				"type":        "integer",
				"description": "Pagination offset. Default 0.",
			},
		},
	}
}

func (l *listFindingsTool) Execute(ctx context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	if res, ok := requireRepo(l.ctx.repo(), "list_findings"); !ok {
		return res, nil
	}

	filters := database.QueryFilters{
		ProjectUUID: l.ctx.ProjectUUID,
		ScanUUID:    argsString(args, "scan_uuid"),
		ModuleName:  argsString(args, "module"),
		SearchTerm:  argsString(args, "search"),
		Severity:    argsStringArray(args, "severity"),
		Limit:       clampLimit(argsInt(args, "limit"), defaultFindingsLimit, maxFindingsLimit),
		Offset:      argsInt(args, "offset"),
	}
	if filters.Offset < 0 {
		filters.Offset = 0
	}

	findings, total, err := l.ctx.Repo.ListFindings(ctx, filters)
	if err != nil {
		return tool.Result{
			Content: fmt.Sprintf("list_findings: %v", err),
			IsError: true,
		}, nil
	}

	out := struct {
		Total    int64            `json:"total"`
		Limit    int              `json:"limit"`
		Offset   int              `json:"offset"`
		Findings []findingSummary `json:"findings"`
	}{
		Total:    total,
		Limit:    filters.Limit,
		Offset:   filters.Offset,
		Findings: make([]findingSummary, 0, len(findings)),
	}
	for _, f := range findings {
		out.Findings = append(out.Findings, summarizeFinding(f))
	}
	body, _ := json.Marshal(out)
	return tool.Result{
		Content: string(body),
		Details: map[string]any{
			"total":    total,
			"returned": len(findings),
		},
	}, nil
}

// sessionRecord is the compact session shape both list_sessions and
// get_session emit. Keep this small — get_session adds extra fields by
// composing into an outer struct.
type sessionRecord struct {
	UUID         string `json:"uuid"`
	Mode         string `json:"mode"`
	Status       string `json:"status"`
	CurrentPhase string `json:"current_phase,omitempty"`
	TargetURL    string `json:"target_url,omitempty"`
	InputType    string `json:"input_type,omitempty"`
	FindingCount int    `json:"finding_count"`
	RecordCount  int    `json:"record_count"`
	StartedAt    string `json:"started_at,omitempty"`
	CompletedAt  string `json:"completed_at,omitempty"`
	DurationMs   int64  `json:"duration_ms"`
}

func summarizeSession(r *database.AgenticScan) sessionRecord {
	rec := sessionRecord{
		UUID:         r.UUID,
		Mode:         r.Mode,
		Status:       r.Status,
		CurrentPhase: r.CurrentPhase,
		TargetURL:    r.TargetURL,
		InputType:    r.InputType,
		FindingCount: r.FindingCount,
		RecordCount:  r.RecordCount,
		DurationMs:   r.DurationMs,
	}
	rec.StartedAt = formatRFC3339(r.StartedAt)
	rec.CompletedAt = formatRFC3339(r.CompletedAt)
	return rec
}

type findingSummary struct {
	ID          int64    `json:"id"`
	ScanUUID    string   `json:"scan_uuid,omitempty"`
	URL         string   `json:"url,omitempty"`
	Module      string   `json:"module"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence,omitempty"`
	Status      string   `json:"status,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	FoundAt     string   `json:"found_at,omitempty"`
}

func summarizeFinding(f *database.Finding) findingSummary {
	desc := f.Description
	if len(desc) > 500 {
		desc = desc[:497] + "…"
	}
	rec := findingSummary{
		ID:          f.ID,
		ScanUUID:    f.ScanUUID,
		URL:         f.URL,
		Module:      strings.TrimSpace(f.ModuleName),
		Severity:    f.Severity,
		Confidence:  f.Confidence,
		Status:      f.Status,
		Description: desc,
		Tags:        f.Tags,
	}
	rec.FoundAt = formatRFC3339(f.FoundAt)
	return rec
}

func clampLimit(req, def, max int) int {
	if req <= 0 {
		return def
	}
	if req > max {
		return max
	}
	return req
}
