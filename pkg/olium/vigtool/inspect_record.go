package vigtool

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

const (
	// inspectRecordRawCap bounds how much raw request/response text the model
	// gets per record. Bigger payloads spill via the SpillDir mechanism in
	// engine if SpillDir is set; otherwise the head+tail truncation in the
	// engine kicks in. We pre-clip here so even with no spill the model
	// doesn't get a megabyte of HTML.
	inspectRecordRawCap = 8 * 1024
)

// NewInspectRecordTool returns the inspect_record tool — fetches one
// HTTPRecord by UUID and returns its raw request/response plus a parsed
// insertion-point list (name, type, value). This is the bridge between
// "I see a record" and "I know where I can attack it".
func NewInspectRecordTool(ctx *SessionsContext) tool.Tool {
	return &inspectRecordTool{ctx: ctx}
}

type inspectRecordTool struct{ ctx *SessionsContext }

func (*inspectRecordTool) Name() string     { return "inspect_record" }
func (*inspectRecordTool) Label() string    { return "Inspect HTTP record" }
func (*inspectRecordTool) Category() string { return tool.CategoryVigolium }
func (*inspectRecordTool) IsReadOnly() bool { return true }
func (*inspectRecordTool) Description() string {
	return "Fetch a single HTTP record by UUID and return full request/response (truncated to ~8KB " +
		"each), the parsed insertion-point list, and key metadata. Insertion points are the canonical " +
		"injection positions vigolium's active modules use — name (parameter name), type (URL_PARAM, " +
		"BODY_PARAM, JSON_PARAM, COOKIE, HEADER, etc.), and current base value. Feed an insertion-point " +
		"name into replay_request to mutate that position with custom payloads."
}

func (*inspectRecordTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"uuid": map[string]any{
				"type":        "string",
				"description": "Record UUID (from query_records).",
			},
			"include_nested": map[string]any{
				"type":        "boolean",
				"description": "Discover nested insertion points (JSON-in-param, base64-encoded JSON, etc.). Default false — turn on for deep nested-payload work.",
				"default":     false,
			},
		},
		"required": []string{"uuid"},
	}
}

type insertionPointEntry struct {
	Index     int    `json:"index"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	BaseValue string `json:"base_value,omitempty"`
}

type inspectRecordOut struct {
	UUID            string                `json:"uuid"`
	ScanUUID        string                `json:"scan_uuid,omitempty"`
	Method          string                `json:"method"`
	URL             string                `json:"url"`
	Hostname        string                `json:"hostname"`
	Status          int                   `json:"status"`
	ContentType     string                `json:"content_type,omitempty"`
	ResponseLen     int64                 `json:"response_length"`
	IsAuthenticated bool                  `json:"is_authenticated,omitempty"`
	Source          string                `json:"source,omitempty"`
	Technology      []string              `json:"technology,omitempty"`
	Headers         map[string]string     `json:"request_headers,omitempty"`
	RawRequest      string                `json:"raw_request,omitempty"`
	RawResponse     string                `json:"raw_response,omitempty"`
	RawReqTruncated bool                  `json:"raw_request_truncated,omitempty"`
	RawRespTruncat  bool                  `json:"raw_response_truncated,omitempty"`
	ParamCount      int                   `json:"parameter_count"`
	InsertionPoints []insertionPointEntry `json:"insertion_points"`
}

func (i *inspectRecordTool) Execute(ctx context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	if res, ok := requireRepo(i.ctx.repo(), "inspect_record"); !ok {
		return res, nil
	}
	uuid := argsString(args, "uuid")
	if uuid == "" {
		return tool.Result{
			Content: "inspect_record: 'uuid' is required",
			IsError: true,
		}, nil
	}

	rec, err := i.ctx.Repo.GetRecordByUUID(ctx, uuid)
	if errors.Is(err, sql.ErrNoRows) || rec == nil {
		return tool.Result{
			Content: fmt.Sprintf("inspect_record: no record with uuid %q. Use query_records to discover valid UUIDs first — don't guess.", uuid),
			IsError: true,
		}, nil
	}
	if err != nil {
		return tool.Result{
			Content: fmt.Sprintf("inspect_record: %v", err),
			IsError: true,
		}, nil
	}
	// Scope guard: don't let one project's agent inspect another project's
	// records via a leaked UUID. The repository accepts any UUID; we enforce
	// project-uuid match at the tool boundary so SessionsContext acts as the
	// authorization barrier.
	if i.ctx.ProjectUUID != "" && rec.ProjectUUID != i.ctx.ProjectUUID {
		return tool.Result{
			Content: fmt.Sprintf("inspect_record: record %q does not belong to the current project", uuid),
			IsError: true,
		}, nil
	}

	includeNested := argsBool(args, "include_nested")
	points, perr := httpmsg.CreateAllInsertionPoints(rec.RawRequest, includeNested)
	ipEntries := make([]insertionPointEntry, 0, len(points))
	if perr == nil {
		for idx, p := range points {
			ipEntries = append(ipEntries, insertionPointEntry{
				Index:     idx,
				Name:      p.Name(),
				Type:      p.Type().String(),
				BaseValue: truncateText(p.BaseValue(), 256),
			})
		}
	}

	// Pull headers via AnalyzeRequest so the model can see auth-relevant
	// values without parsing raw bytes itself.
	headers := map[string]string{}
	if info, err := httpmsg.AnalyzeRequest(rec.RawRequest); err == nil {
		// info.Headers[0] is the request line ("GET / HTTP/1.1") — ParseHttpHeader
		// returns an empty HttpHeader for it since there's no colon.
		for _, h := range info.Headers {
			parsed := httpmsg.ParseHttpHeader(h)
			if parsed.Name != "" {
				headers[parsed.Name] = parsed.Value
			}
		}
	}

	rawReq, reqTrunc := clipBytes(rec.RawRequest, inspectRecordRawCap)
	rawResp, respTrunc := clipBytes(rec.RawResponse, inspectRecordRawCap)

	out := inspectRecordOut{
		UUID:            rec.UUID,
		ScanUUID:        rec.ScanUUID,
		Method:          rec.Method,
		URL:             rec.URL,
		Hostname:        rec.Hostname,
		Status:          rec.StatusCode,
		ContentType:     rec.ResponseContentType,
		ResponseLen:     rec.ResponseContentLength,
		IsAuthenticated: rec.IsAuthenticated,
		Source:          rec.Source,
		Technology:      rec.Technology,
		Headers:         headers,
		RawRequest:      rawReq,
		RawResponse:     rawResp,
		RawReqTruncated: reqTrunc,
		RawRespTruncat:  respTrunc,
		ParamCount:      len(rec.Parameters),
		InsertionPoints: ipEntries,
	}

	body, _ := json.Marshal(out)
	details := map[string]any{
		"uuid":             rec.UUID,
		"status":           rec.StatusCode,
		"insertion_points": len(ipEntries),
	}
	if perr != nil {
		details["ip_parse_error"] = perr.Error()
	}
	return tool.Result{
		Content: string(body),
		Details: details,
	}, nil
}

// clipBytes returns up to limit bytes of b as a string. Returns the
// truncation flag so callers can surface that the model is looking at a
// partial payload (versus a body that happens to be exactly the limit).
func clipBytes(b []byte, limit int) (string, bool) {
	if len(b) <= limit {
		return string(b), false
	}
	return string(b[:limit]), true
}

func truncateText(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}
