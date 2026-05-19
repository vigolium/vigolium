package vigtool

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// NewAuthSessionLookupTool returns the auth_session_lookup tool — a
// read-only query that returns hydrated auth headers for a hostname so the
// agent can pipe them into web_fetch / run_extension without manually
// re-implementing the login flow.
func NewAuthSessionLookupTool(ctx *SessionsContext) tool.Tool {
	return &authSessionLookupTool{ctx: ctx}
}

type authSessionLookupTool struct{ ctx *SessionsContext }

func (*authSessionLookupTool) Name() string     { return "auth_session_lookup" }
func (*authSessionLookupTool) Label() string    { return "Lookup auth session" }
func (*authSessionLookupTool) Category() string { return tool.CategoryVigolium }
func (*authSessionLookupTool) IsReadOnly() bool { return true }
func (*authSessionLookupTool) Description() string {
	return "Look up a hydrated authentication session for a hostname. Returns the session name, role, " +
		"and headers (cookies / Authorization / API key) you can pass into web_fetch as the `headers` " +
		"argument to make authenticated requests. When no name is given, returns the first session " +
		"registered for that hostname (typically the primary user's session). Returns an empty list " +
		"if no sessions are stored for this hostname yet — the operator must run the login flow first."
}

func (*authSessionLookupTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"hostname": map[string]any{
				"type":        "string",
				"description": "Hostname to look up (e.g. 'app.example.com'). Required.",
			},
			"name": map[string]any{
				"type":        "string",
				"description": "Optional session name. When omitted, returns the first session at this hostname. Use list_auth_sessions to see what's available.",
			},
		},
		"required": []string{"hostname"},
	}
}

func (a *authSessionLookupTool) Execute(ctx context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	hostname := argsString(args, "hostname")
	if hostname == "" {
		return tool.Result{
			Content: "auth_session_lookup: 'hostname' is required",
			IsError: true,
		}, nil
	}
	if res, ok := requireRepo(a.ctx.repo(), "auth_session_lookup"); !ok {
		return res, nil
	}
	name := argsString(args, "name")

	rows, err := a.ctx.Repo.GetAuthenticationHostnamesByHostname(ctx, a.ctx.ProjectUUID, hostname)
	if err != nil {
		return tool.Result{
			Content: fmt.Sprintf("auth_session_lookup: %v", err),
			IsError: true,
		}, nil
	}
	if len(rows) == 0 {
		return tool.Result{
			Content: fmt.Sprintf(`{"hostname":%q,"sessions":[]}`, hostname),
			Details: map[string]any{"hostname": hostname, "matches": 0},
		}, nil
	}

	var picked *database.AuthenticationHostname
	if name != "" {
		for _, r := range rows {
			if r.SessionName == name {
				picked = r
				break
			}
		}
		if picked == nil {
			return tool.Result{
				Content: fmt.Sprintf("auth_session_lookup: no session %q registered for %s. Available: %s",
					name, hostname, joinSessionNames(rows)),
				IsError: true,
			}, nil
		}
	} else {
		picked = rows[0]
	}

	out := summarizeAuthSession(picked)
	body, _ := json.MarshalIndent(out, "", "  ")
	return tool.Result{
		Content: string(body),
		Details: map[string]any{
			"hostname":     hostname,
			"name":         picked.SessionName,
			"role":         picked.SessionRole,
			"header_count": len(picked.Headers),
		},
	}, nil
}

// NewListAuthSessionsTool returns the list_auth_sessions tool — a read-only
// summary of all auth sessions the operator has prepared (or that prior
// scans hydrated). Useful for the agent to discover what's available
// before deciding which one to pull headers from.
func NewListAuthSessionsTool(ctx *SessionsContext) tool.Tool {
	return &listAuthSessionsTool{ctx: ctx}
}

type listAuthSessionsTool struct{ ctx *SessionsContext }

func (*listAuthSessionsTool) Name() string     { return "list_auth_sessions" }
func (*listAuthSessionsTool) Label() string    { return "List auth sessions" }
func (*listAuthSessionsTool) Category() string { return tool.CategoryVigolium }
func (*listAuthSessionsTool) IsReadOnly() bool { return true }
func (*listAuthSessionsTool) Description() string {
	return "List auth sessions registered for the current project, optionally filtered by hostname. " +
		"Returns a compact summary (hostname, name, role, hydrated state) — fetch full headers via " +
		"auth_session_lookup."
}

func (*listAuthSessionsTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"hostname": map[string]any{
				"type":        "string",
				"description": "Optional hostname filter (e.g. 'app.example.com'). Empty = all hostnames in the project.",
			},
		},
	}
}

func (l *listAuthSessionsTool) Execute(ctx context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	if res, ok := requireRepo(l.ctx.repo(), "list_auth_sessions"); !ok {
		return res, nil
	}

	hostname := argsString(args, "hostname")
	var rows []*database.AuthenticationHostname
	var err error
	if hostname != "" {
		rows, err = l.ctx.Repo.GetAuthenticationHostnamesByHostname(ctx, l.ctx.ProjectUUID, hostname)
	} else {
		rows, err = l.ctx.Repo.GetAuthenticationHostnamesByProject(ctx, l.ctx.ProjectUUID)
	}
	if err != nil {
		return tool.Result{
			Content: fmt.Sprintf("list_auth_sessions: %v", err),
			IsError: true,
		}, nil
	}

	out := struct {
		Hostname string               `json:"hostname,omitempty"`
		Sessions []authSessionSummary `json:"sessions"`
	}{
		Hostname: hostname,
		Sessions: make([]authSessionSummary, 0, len(rows)),
	}
	for _, r := range rows {
		out.Sessions = append(out.Sessions, authSessionSummary{
			Hostname:    r.Hostname,
			Name:        r.SessionName,
			Role:        r.SessionRole,
			HeaderCount: len(r.Headers),
			Hydrated:    r.HydratedAt != nil,
			Source:      r.Source,
		})
	}
	body, _ := json.Marshal(out)
	return tool.Result{
		Content: string(body),
		Details: map[string]any{
			"count": len(rows),
		},
	}, nil
}

type authSessionDetail struct {
	Hostname   string            `json:"hostname"`
	Name       string            `json:"name"`
	Role       string            `json:"role,omitempty"`
	Headers    map[string]string `json:"headers"`
	Hydrated   bool              `json:"hydrated"`
	HydratedAt string            `json:"hydrated_at,omitempty"`
	Source     string            `json:"source,omitempty"`
	UsageHint  string            `json:"usage_hint"`
}

type authSessionSummary struct {
	Hostname    string `json:"hostname"`
	Name        string `json:"name"`
	Role        string `json:"role,omitempty"`
	HeaderCount int    `json:"header_count"`
	Hydrated    bool   `json:"hydrated"`
	Source      string `json:"source,omitempty"`
}

func summarizeAuthSession(r *database.AuthenticationHostname) authSessionDetail {
	out := authSessionDetail{
		Hostname: r.Hostname,
		Name:     r.SessionName,
		Role:     r.SessionRole,
		Headers:  r.Headers,
		Hydrated: r.HydratedAt != nil,
		Source:   r.Source,
		UsageHint: "Pass `headers` into web_fetch (or any custom request) to make this request authenticated. " +
			"If hydrated=false, the operator hasn't completed the login flow yet — the headers may be empty or stale.",
	}
	if r.HydratedAt != nil {
		out.HydratedAt = formatRFC3339(*r.HydratedAt)
	}
	if out.Headers == nil {
		out.Headers = map[string]string{}
	}
	return out
}

func joinSessionNames(rows []*database.AuthenticationHostname) string {
	names := make([]string, 0, len(rows))
	for _, r := range rows {
		names = append(names, r.SessionName)
	}
	return strings.Join(names, ", ")
}
