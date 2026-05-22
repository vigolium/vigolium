package vigtool

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	gohttp "net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/tool"
	"github.com/vigolium/vigolium/pkg/replay"
	"golang.org/x/net/publicsuffix"
)

const (
	// replayPerRunCap bounds total mutations the agent can fire in a single
	// autopilot session. High enough to actually test an attack surface,
	// low enough that a runaway loop doesn't hammer a target.
	replayPerRunCap = 200

	// replayPerRecordCap bounds mutations against a single record. Stops the
	// agent from re-firing 100 payloads at one endpoint when the response
	// pattern is already clear after a handful.
	replayPerRecordCap = 30

	// replayHTTPTimeout is the per-request wall-clock budget. Generous so a
	// slow target doesn't murder the loop, but bounded so a hung connection
	// doesn't either.
	replayHTTPTimeout = 25 * time.Second
)

// NewReplayRequestTool returns the replay_request tool — sends a mutated
// version of a stored HTTP record and reports a baseline-vs-replay diff so
// the agent can judge whether a payload triggered anything interesting.
func NewReplayRequestTool(ctx *SessionsContext) tool.Tool {
	return &replayRequestTool{ctx: ctx}
}

type replayRequestTool struct {
	ctx       *SessionsContext
	totalRun  atomic.Int64
	perRecMu  sync.Mutex
	perRecord map[string]int

	// Shared client + cookie jar across all replays in this autopilot run.
	// Cookies set by one response are visible to the next call so multi-step
	// auth flows (login → CSRF cookie → action) work without the model
	// manually threading them. Lazy-init under clientOnce so the cost is
	// only paid when replay_request actually fires.
	clientOnce sync.Once
	client     *gohttp.Client
}

func (*replayRequestTool) Name() string     { return "replay_request" }
func (*replayRequestTool) Label() string    { return "Replay HTTP request" }
func (*replayRequestTool) Category() string { return tool.CategoryVigolium }
func (*replayRequestTool) IsReadOnly() bool { return false }
func (*replayRequestTool) Description() string {
	return "Take a stored HTTP record, mutate one or more insertion points with custom payloads, " +
		"send the result, and return a baseline-vs-replay diff (status, length, content-hash, " +
		"payload reflection, response-time delta). Use this to confirm attacks suggested by " +
		"inspect_record — pull payloads from attack_kit or compose your own. Optionally pass an " +
		"auth_session name to fold in cookies/headers from list_auth_sessions. Cookies set by one " +
		"replay persist to the next (multi-step auth flows work). Honours HTTP_PROXY / HTTPS_PROXY " +
		"env vars so the operator can route replays through Burp. Capped at 30 calls per record and " +
		"200 per run to prevent runaway loops."
}

func (*replayRequestTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"record_uuid": map[string]any{
				"type":        "string",
				"description": "UUID of the record to base the replay on (from query_records / inspect_record).",
			},
			"mutations": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"name": map[string]any{
							"type":        "string",
							"description": "Insertion-point name (parameter or header name). Match against inspect_record output.",
						},
						"type": map[string]any{
							"type":        "string",
							"description": "Optional insertion-point type to disambiguate (e.g. 'URL_PARAM', 'HEADER', 'JSON_PARAM'). Useful when the same name appears in multiple positions.",
						},
						"payload": map[string]any{
							"type":        "string",
							"description": "Payload to inject. Required.",
						},
					},
					"required": []string{"name", "payload"},
				},
				"description": "Insertion-point mutations to apply. Mutually exclusive with raw_request.",
			},
			"raw_request": map[string]any{
				"type":        "string",
				"description": "Optional fully-formed raw HTTP request to send verbatim. Mutually exclusive with mutations. Useful for hand-crafted attacks that don't fit the insertion-point model.",
			},
			"auth_session": map[string]any{
				"type":        "string",
				"description": "Optional auth session name (from list_auth_sessions). When set, headers from that session are merged into the replay request, overriding the originals.",
			},
			"extra_headers": map[string]any{
				"type":        "object",
				"description": "Extra request headers to add/override (object of string→string).",
			},
			"no_redirects": map[string]any{
				"type":        "boolean",
				"description": "If true, do not follow redirects. Default false.",
			},
		},
		"required": []string{"record_uuid"},
	}
}

func (r *replayRequestTool) Execute(ctx context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	if res, ok := requireRepo(r.ctx.repo(), "replay_request"); !ok {
		return res, nil
	}

	if cur := r.totalRun.Load(); cur >= replayPerRunCap {
		return tool.Result{
			Content: fmt.Sprintf(
				"replay_request rate-limited: %d replays this run (cap=%d). "+
					"If you still need to validate, halt and resume with a fresh run.",
				cur, replayPerRunCap),
			IsError: true,
		}, nil
	}

	uuid := argsString(args, "record_uuid")
	if uuid == "" {
		return tool.Result{Content: "replay_request: 'record_uuid' is required", IsError: true}, nil
	}

	rec, err := r.ctx.Repo.GetRecordByUUID(ctx, uuid)
	if errors.Is(err, sql.ErrNoRows) || rec == nil {
		return tool.Result{
			Content: fmt.Sprintf("replay_request: no record with uuid %q. Use query_records to discover valid UUIDs first — don't guess.", uuid),
			IsError: true,
		}, nil
	}
	if err != nil {
		return tool.Result{Content: fmt.Sprintf("replay_request: %v", err), IsError: true}, nil
	}
	if r.ctx.ProjectUUID != "" && rec.ProjectUUID != r.ctx.ProjectUUID {
		return tool.Result{
			Content: fmt.Sprintf("replay_request: record %q does not belong to the current project", uuid),
			IsError: true,
		}, nil
	}

	if cur := r.perRecordCount(uuid); cur >= replayPerRecordCap {
		return tool.Result{
			Content: fmt.Sprintf("replay_request: %d replays already against record %s (cap=%d). "+
				"Pick a different record or vary the payload class.", cur, uuid, replayPerRecordCap),
			IsError: true,
		}, nil
	}

	mutations, mutErr := parseMutations(args["mutations"])
	if mutErr != nil {
		return tool.Result{Content: "replay_request: " + mutErr.Error(), IsError: true}, nil
	}
	rawOverride := argsString(args, "raw_request")
	if rawOverride == "" && len(mutations) == 0 {
		return tool.Result{
			Content: "replay_request: provide either 'mutations' or 'raw_request'",
			IsError: true,
		}, nil
	}
	if rawOverride != "" && len(mutations) > 0 {
		return tool.Result{
			Content: "replay_request: 'mutations' and 'raw_request' are mutually exclusive",
			IsError: true,
		}, nil
	}

	overlay := map[string]string{}
	if name := argsString(args, "auth_session"); name != "" {
		hdrs, err := r.lookupAuthHeaders(ctx, rec.Hostname, name)
		if err != nil {
			return tool.Result{Content: fmt.Sprintf("replay_request: auth_session %q: %v", name, err), IsError: true}, nil
		}
		for k, v := range hdrs {
			overlay[k] = v
		}
	}
	if extra, ok := args["extra_headers"].(map[string]any); ok {
		for k, v := range extra {
			if s, ok := v.(string); ok {
				overlay[k] = s
			}
		}
	}

	opts := replay.Options{
		BaselineRequest:      rec.RawRequest,
		BaselineResponse:     rec.RawResponse,
		BaselineStatus:       rec.StatusCode,
		BaselineResponseTime: rec.ResponseTimeMs,
		Mutations:            mutations,
		Scheme:               rec.Scheme,
		Hostname:             rec.Hostname,
		Port:                 rec.Port,
		HeaderOverlay:        overlay,
		NoRedirects:          argsBool(args, "no_redirects"),
		Client:               r.getClient(),
	}
	if rawOverride != "" {
		opts.RawRequest = []byte(rawOverride)
	}

	r.incPerRecord(uuid)
	r.totalRun.Add(1)

	result, err := replay.Do(ctx, opts)
	if err != nil {
		return tool.Result{Content: fmt.Sprintf("replay_request: %v", err), IsError: true}, nil
	}

	// Embedding the engine's Result means future field additions to the
	// shared schema land in the tool's output automatically, instead of
	// silently drifting from the autopilot prompts that read it.
	out := struct {
		RecordUUID string `json:"record_uuid"`
		*replay.Result
	}{RecordUUID: uuid, Result: result}
	body, _ := json.Marshal(out)

	details := map[string]any{
		"record_uuid":     uuid,
		"status":          result.Replay.Status,
		"length_delta":    result.Diff.LengthDelta,
		"content_changed": result.Diff.ContentChanged,
	}
	if len(result.Diff.ReflectsPayload) > 0 {
		details["reflects_payload"] = true
	}
	if result.AdditionalGroups > 0 {
		details["additional_payload_groups"] = result.AdditionalGroups
	}
	return tool.Result{
		Content: string(body),
		Details: details,
	}, nil
}

// perRecordCount reads the current attempt count for uuid without
// incrementing — used by the cap check so we don't mutate state on the
// rejection path.
func (r *replayRequestTool) perRecordCount(uuid string) int {
	r.perRecMu.Lock()
	defer r.perRecMu.Unlock()
	return r.perRecord[uuid]
}

func (r *replayRequestTool) incPerRecord(uuid string) {
	r.perRecMu.Lock()
	defer r.perRecMu.Unlock()
	if r.perRecord == nil {
		r.perRecord = map[string]int{}
	}
	r.perRecord[uuid]++
}

func (r *replayRequestTool) lookupAuthHeaders(ctx context.Context, hostname, name string) (map[string]string, error) {
	rows, err := r.ctx.Repo.GetAuthenticationHostnamesByHostname(ctx, r.ctx.ProjectUUID, hostname)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.SessionName == name {
			return row.Headers, nil
		}
	}
	return nil, fmt.Errorf("no auth session %q for hostname %s", name, hostname)
}

// parseMutations decodes the args["mutations"] payload, accepting both
// concrete []replay.Mutation shapes and the more common JSON-decoded
// []any-of-map.
func parseMutations(raw any) ([]replay.Mutation, error) {
	if raw == nil {
		return nil, nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("'mutations' must be an array")
	}
	out := make([]replay.Mutation, 0, len(arr))
	for i, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("'mutations[%d]' must be an object", i)
		}
		name, _ := obj["name"].(string)
		payload, _ := obj["payload"].(string)
		typ, _ := obj["type"].(string)
		if strings.TrimSpace(name) == "" || payload == "" {
			return nil, fmt.Errorf("'mutations[%d]': name and payload are required", i)
		}
		out = append(out, replay.Mutation{Name: name, Type: typ, Payload: payload})
	}
	return out, nil
}

// getClient returns the shared http.Client for this tool, lazy-initializing
// on first call. The client carries a per-run cookie jar so cookies set by
// one replay are visible to the next (multi-step auth flows: login → CSRF
// → action). The transport honours HTTP_PROXY / HTTPS_PROXY so an operator
// can pipe replays through Burp by exporting the env var before launching
// the autopilot.
func (r *replayRequestTool) getClient() *gohttp.Client {
	r.clientOnce.Do(func() {
		jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
		r.client = replay.NewDefaultClient(jar, replayHTTPTimeout)
	})
	return r.client
}
