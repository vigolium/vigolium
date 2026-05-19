package vigtool

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

const (
	defaultOASTPollLimit = 50
	maxOASTPollLimit     = 200
)

// NewOASTPollTool returns the oast_poll tool — queries OAST (out-of-band)
// interactions persisted for the project. Out-of-band callbacks are how the
// agent confirms blind SSRF / RCE / XXE attacks: send a payload that asks
// the target to contact a callback URL, then poll for the hit.
func NewOASTPollTool(ctx *SessionsContext) tool.Tool {
	return &oastPollTool{ctx: ctx}
}

type oastPollTool struct{ ctx *SessionsContext }

func (*oastPollTool) Name() string     { return "oast_poll" }
func (*oastPollTool) Label() string    { return "Poll OAST interactions" }
func (*oastPollTool) Category() string { return tool.CategoryVigolium }
func (*oastPollTool) IsReadOnly() bool { return true }
func (*oastPollTool) Description() string {
	return "Query out-of-band (OAST) interactions that vigolium's interactsh integration captured " +
		"for the current project. Use this to confirm blind SSRF / RCE / XXE / SQLi after sending " +
		"a payload that asks the target to call back to a unique URL. Filter by scan UUID, protocol " +
		"(dns, http, smtp, ldap), module id, or substring search across target_url/parameter_name/" +
		"unique_id. Returns the most recent interactions first."
}

func (*oastPollTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"scan_uuid": map[string]any{
				"type":        "string",
				"description": "Restrict to interactions tied to a specific scan UUID (from run_scan / list_sessions).",
			},
			"protocol": map[string]any{
				"type":        "string",
				"description": "Protocol filter (e.g. 'dns', 'http', 'smtp', 'ldap'). Empty = all.",
			},
			"module": map[string]any{
				"type":        "string",
				"description": "Module ID filter (which module's payload triggered the callback).",
			},
			"search": map[string]any{
				"type":        "string",
				"description": "Substring search across target_url, parameter_name, and unique_id.",
			},
			"since_seconds": map[string]any{
				"type":        "integer",
				"description": "When >0, only return interactions received in the last N seconds. Useful when polling right after firing a payload.",
			},
			"limit": map[string]any{
				"type":        "integer",
				"description": fmt.Sprintf("Max interactions to return (default %d, cap %d).", defaultOASTPollLimit, maxOASTPollLimit),
			},
			"offset": map[string]any{
				"type":        "integer",
				"description": "Pagination offset. Default 0.",
			},
		},
	}
}

type oastInteractionSummary struct {
	ID            int64  `json:"id"`
	ScanUUID      string `json:"scan_uuid,omitempty"`
	UniqueID      string `json:"unique_id"`
	FullID        string `json:"full_id,omitempty"`
	Protocol      string `json:"protocol"`
	QType         string `json:"q_type,omitempty"`
	RemoteAddress string `json:"remote_address,omitempty"`
	InteractedAt  string `json:"interacted_at"`
	TargetURL     string `json:"target_url,omitempty"`
	ParameterName string `json:"parameter_name,omitempty"`
	InjectionType string `json:"injection_type,omitempty"`
	ModuleID      string `json:"module_id,omitempty"`
	Payload       string `json:"payload,omitempty"`
	FindingID     int64  `json:"finding_id,omitempty"`
}

func (o *oastPollTool) Execute(ctx context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	if res, ok := requireRepo(o.ctx.repo(), "oast_poll"); !ok {
		return res, nil
	}

	limit := clampLimit(argsInt(args, "limit"), defaultOASTPollLimit, maxOASTPollLimit)
	offset := argsInt(args, "offset")
	if offset < 0 {
		offset = 0
	}

	scanUUID := argsString(args, "scan_uuid")
	protocol := strings.ToLower(argsString(args, "protocol"))
	moduleID := argsString(args, "module")
	search := argsString(args, "search")

	interactions, total, err := o.ctx.Repo.ListOASTInteractions(
		ctx, o.ctx.ProjectUUID, scanUUID, protocol, moduleID, search, limit, offset,
	)
	if err != nil {
		return tool.Result{Content: fmt.Sprintf("oast_poll: %v", err), IsError: true}, nil
	}

	since := argsInt(args, "since_seconds")
	cutoff := time.Time{}
	if since > 0 {
		cutoff = time.Now().Add(-time.Duration(since) * time.Second)
	}

	summaries := make([]oastInteractionSummary, 0, len(interactions))
	for _, it := range interactions {
		if !cutoff.IsZero() && it.InteractedAt.Before(cutoff) {
			continue
		}
		summaries = append(summaries, summarizeOASTInteraction(it))
	}

	out := struct {
		Total        int64                    `json:"total_matching"`
		Returned     int                      `json:"returned"`
		Limit        int                      `json:"limit"`
		Offset       int                      `json:"offset"`
		Interactions []oastInteractionSummary `json:"interactions"`
		Hint         string                   `json:"hint,omitempty"`
	}{
		Total:        total,
		Returned:     len(summaries),
		Limit:        limit,
		Offset:       offset,
		Interactions: summaries,
	}
	switch {
	case len(summaries) == 0:
		out.Hint = "No interactions matched. If you just fired a payload, wait a few seconds and poll again — DNS in particular can take 1-3s to land."
	case since > 0 && len(summaries) < len(interactions):
		out.Hint = "since_seconds is applied after the repo paginated by limit; 'total_matching' counts all interactions matching the other filters, not just those within the window."
	}

	body, _ := json.Marshal(out)
	return tool.Result{
		Content: string(body),
		Details: map[string]any{
			"total":    total,
			"returned": len(summaries),
		},
	}, nil
}

func summarizeOASTInteraction(it *database.OASTInteraction) oastInteractionSummary {
	rec := oastInteractionSummary{
		ID:            it.ID,
		ScanUUID:      it.ScanUUID,
		UniqueID:      it.UniqueID,
		FullID:        it.FullID,
		Protocol:      it.Protocol,
		QType:         it.QType,
		RemoteAddress: it.RemoteAddress,
		TargetURL:     it.TargetURL,
		ParameterName: it.ParameterName,
		InjectionType: it.InjectionType,
		ModuleID:      it.ModuleID,
		Payload:       it.Payload,
		FindingID:     it.FindingID,
	}
	rec.InteractedAt = formatRFC3339(it.InteractedAt)
	return rec
}
