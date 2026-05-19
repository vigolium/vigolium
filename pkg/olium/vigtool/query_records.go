package vigtool

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

const (
	defaultQueryRecordsLimit = 25
	maxQueryRecordsLimit     = 200
)

// NewQueryRecordsTool returns the query_records tool — a paginated lookup
// over the project's persisted HTTP traffic with filters. Returns compact
// summaries; full request/response bodies + insertion points come from
// inspect_record.
func NewQueryRecordsTool(ctx *SessionsContext) tool.Tool {
	return &queryRecordsTool{ctx: ctx}
}

type queryRecordsTool struct{ ctx *SessionsContext }

func (*queryRecordsTool) Name() string     { return "query_records" }
func (*queryRecordsTool) Label() string    { return "Query HTTP records" }
func (*queryRecordsTool) Category() string { return tool.CategoryVigolium }
func (*queryRecordsTool) IsReadOnly() bool { return true }
func (*queryRecordsTool) Description() string {
	return "Query the project's persisted HTTP traffic with optional filters (host, method, path, " +
		"status code, content-type, source, free-text search). Returns compact summaries — UUID, " +
		"method, URL, status, content-type, response length, source, parameter count. Use this to " +
		"discover what surface vigolium has already observed, then pass a record_uuid into " +
		"inspect_record / replay_request to act on a specific entry."
}

func (*queryRecordsTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"host": map[string]any{
				"type":        "string",
				"description": "Hostname filter. Supports '*' wildcards (e.g. 'api.*'). Empty = all hosts.",
			},
			"method": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "HTTP method allowlist (e.g. ['GET','POST']). Empty = all methods.",
			},
			"path": map[string]any{
				"type":        "string",
				"description": "Path substring or wildcard (e.g. '/api/users/*'). Empty = all paths.",
			},
			"status": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "integer"},
				"description": "Status-code allowlist (e.g. [200,302]). Empty = all statuses.",
			},
			"content_type": map[string]any{
				"type":        "string",
				"description": "Response content-type substring (e.g. 'json', 'html'). Empty = all.",
			},
			"source": map[string]any{
				"type":        "string",
				"description": "Record source filter (e.g. 'scanner', 'ingest-cli', 'browser-probe').",
			},
			"has_params": map[string]any{
				"type":        "boolean",
				"description": "When true, only return records that have at least one parameter. Useful for attack-surface narrowing.",
			},
			"search": map[string]any{
				"type":        "string",
				"description": "Free-text substring across url and path.",
			},
			"scan_uuid": map[string]any{
				"type":        "string",
				"description": "Restrict to records produced by a specific scan UUID.",
			},
			"limit": map[string]any{
				"type":        "integer",
				"description": fmt.Sprintf("Max records to return (default %d, cap %d).", defaultQueryRecordsLimit, maxQueryRecordsLimit),
			},
			"offset": map[string]any{
				"type":        "integer",
				"description": "Pagination offset. Default 0.",
			},
		},
	}
}

type recordSummary struct {
	UUID         string `json:"uuid"`
	ScanUUID     string `json:"scan_uuid,omitempty"`
	Method       string `json:"method"`
	URL          string `json:"url"`
	Hostname     string `json:"hostname,omitempty"`
	Path         string `json:"path,omitempty"`
	Status       int    `json:"status"`
	ContentType  string `json:"content_type,omitempty"`
	ResponseLen  int64  `json:"response_length"`
	ParamCount   int    `json:"param_count"`
	Source       string `json:"source,omitempty"`
	IsAuthed     bool   `json:"is_authenticated,omitempty"`
	SentAt       string `json:"sent_at,omitempty"`
}

func (q *queryRecordsTool) Execute(ctx context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	if res, ok := requireRepo(q.ctx.repo(), "query_records"); !ok {
		return res, nil
	}
	repo := q.ctx.Repo

	limit := clampLimit(argsInt(args, "limit"), defaultQueryRecordsLimit, maxQueryRecordsLimit)
	offset := argsInt(args, "offset")
	if offset < 0 {
		offset = 0
	}

	statusCodes := argsIntArray(args, "status")
	methods := argsStringArray(args, "method")
	for i, m := range methods {
		methods[i] = strings.ToUpper(m)
	}

	filters := database.QueryFilters{
		ProjectUUID: q.ctx.ProjectUUID,
		HostPattern: argsString(args, "host"),
		Methods:     methods,
		PathPattern: argsString(args, "path"),
		StatusCodes: statusCodes,
		ContentType: argsString(args, "content_type"),
		Source:      argsString(args, "source"),
		SearchTerm:  argsString(args, "search"),
		ScanUUID:    argsString(args, "scan_uuid"),
		Limit:       limit,
		Offset:      offset,
	}

	qb := database.NewQueryBuilder(repo.DB(), filters)
	// Pull just the summary columns we render — raw_request/raw_response are
	// multi-KB blobs and the agent gets the full bytes from inspect_record
	// when it wants them. Single ScanAndCount roundtrip vs separate
	// Count+Execute.
	sq := qb.BuildRecordsQuery().ExcludeColumn("raw_request", "raw_response")
	records := make([]*database.HTTPRecord, 0, limit)
	total, err := sq.ScanAndCount(ctx, &records)
	if err != nil {
		return tool.Result{
			Content: fmt.Sprintf("query_records: %v", err),
			IsError: true,
		}, nil
	}

	hasParams := argsBool(args, "has_params")
	summaries := make([]recordSummary, 0, len(records))
	for _, rec := range records {
		if hasParams && len(rec.Parameters) == 0 {
			continue
		}
		summaries = append(summaries, summarizeRecord(rec))
	}

	out := struct {
		Total       int64           `json:"total"`
		Limit       int             `json:"limit"`
		Offset      int             `json:"offset"`
		Records     []recordSummary `json:"records"`
		HasParamsOn bool            `json:"has_params_filter,omitempty"`
		Hint        string          `json:"hint,omitempty"`
	}{
		Total:       int64(total),
		Limit:       limit,
		Offset:      offset,
		Records:     summaries,
		HasParamsOn: hasParams,
	}
	// has_params is a post-filter, so the returned page may be smaller than
	// the limit even when more matches exist; flag it so the model doesn't
	// assume returned<limit means end-of-list.
	if hasParams && len(summaries) < len(records) {
		out.Hint = "has_params filtered some rows after pagination; bump limit or page through to see more."
	}
	body, _ := json.Marshal(out)
	return tool.Result{
		Content: string(body),
		Details: map[string]any{
			"total":    out.Total,
			"returned": len(summaries),
		},
	}, nil
}

func summarizeRecord(r *database.HTTPRecord) recordSummary {
	rec := recordSummary{
		UUID:        r.UUID,
		ScanUUID:    r.ScanUUID,
		Method:      r.Method,
		URL:         r.URL,
		Hostname:    r.Hostname,
		Path:        r.Path,
		Status:      r.StatusCode,
		ContentType: r.ResponseContentType,
		ResponseLen: r.ResponseContentLength,
		ParamCount:  len(r.Parameters),
		Source:      r.Source,
		IsAuthed:    r.IsAuthenticated,
	}
	rec.SentAt = formatRFC3339(r.SentAt)
	return rec
}
