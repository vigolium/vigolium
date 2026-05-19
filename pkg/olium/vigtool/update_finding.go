package vigtool

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// NewUpdateFindingTool returns the update_finding tool — the agent's
// write-side handle for triaging existing findings. Wraps
// repo.UpdateFindingStatus so verdicts produced by the autopilot loop
// (after validating an existing finding with replay_request / inspect_record)
// land in the project DB instead of evaporating in the transcript.
func NewUpdateFindingTool(ctx *SessionsContext) tool.Tool {
	return &updateFindingTool{ctx: ctx}
}

type updateFindingTool struct{ ctx *SessionsContext }

func (*updateFindingTool) Name() string     { return "update_finding" }
func (*updateFindingTool) Label() string    { return "Update finding status" }
func (*updateFindingTool) Category() string { return tool.CategoryVigolium }
func (*updateFindingTool) IsReadOnly() bool { return false }
func (*updateFindingTool) Description() string {
	return "Update the lifecycle status of an existing finding after triaging it. Use this when " +
		"you've verified an existing finding (via inspect_record + replay_request, or by reading " +
		"the relevant code), and have a verdict: 'triaged' (confirmed real), 'false_positive' " +
		"(not exploitable / scanner noise), 'accepted_risk' (real but the operator is keeping it), " +
		"or 'fixed' (resolved). Triage is the primary value-add for the autopilot when a pre-scan " +
		"has already produced findings — confirm or refute them rather than re-discovering."
}

func (*updateFindingTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"id": map[string]any{
				"type":        "integer",
				"description": "Finding ID (from list_findings).",
			},
			"status": map[string]any{
				"type":        "string",
				"enum":        []string{database.StatusTriaged, database.StatusFalsePositive, database.StatusAcceptedRisk, database.StatusFixed, database.StatusDraft},
				"description": "New lifecycle status. 'triaged' confirms a real bug; 'false_positive' rejects it; 'accepted_risk' keeps it but acknowledges; 'fixed' marks it resolved.",
			},
		},
		"required": []string{"id", "status"},
	}
}

func (u *updateFindingTool) Execute(ctx context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	if res, ok := requireRepo(u.ctx.repo(), "update_finding"); !ok {
		return res, nil
	}

	id := int64(argsInt(args, "id"))
	if id <= 0 {
		return tool.Result{Content: "update_finding: 'id' is required and must be > 0", IsError: true}, nil
	}
	status := argsString(args, "status")
	if !database.IsValidFindingStatus(status) {
		return tool.Result{
			Content: fmt.Sprintf("update_finding: invalid status %q (allowed: triaged, false_positive, accepted_risk, fixed, draft)", status),
			IsError: true,
		}, nil
	}

	// Scope guard: refuse cross-project writes even when the agent supplies
	// a finding ID from another project. The tool's SessionsContext is the
	// authorization boundary.
	if u.ctx.ProjectUUID != "" {
		f, gerr := u.ctx.Repo.GetFindingByID(ctx, id)
		if errors.Is(gerr, sql.ErrNoRows) || f == nil {
			return tool.Result{
				Content: fmt.Sprintf("update_finding: no finding with id %d. Use list_findings to discover valid IDs.", id),
				IsError: true,
			}, nil
		}
		if gerr != nil {
			return tool.Result{Content: fmt.Sprintf("update_finding: %v", gerr), IsError: true}, nil
		}
		if f.ProjectUUID != u.ctx.ProjectUUID {
			return tool.Result{
				Content: fmt.Sprintf("update_finding: finding %d does not belong to the current project", id),
				IsError: true,
			}, nil
		}
	}

	if err := u.ctx.Repo.UpdateFindingStatus(ctx, id, status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return tool.Result{
				Content: fmt.Sprintf("update_finding: no finding with id %d", id),
				IsError: true,
			}, nil
		}
		return tool.Result{Content: fmt.Sprintf("update_finding: %v", err), IsError: true}, nil
	}

	body, _ := json.Marshal(map[string]any{
		"id":     id,
		"status": status,
		"ok":     true,
	})
	return tool.Result{
		Content: string(body),
		Details: map[string]any{
			"id":     id,
			"status": status,
		},
	}, nil
}
