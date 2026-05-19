package vigtool

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	gohttp "net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/olium/tool"
	"github.com/vigolium/vigolium/pkg/utils"
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

	// replayResponseBytesCap clips the response excerpt we return to the
	// model. Full body length and hash are reported separately so the model
	// can see when it's looking at a truncated view.
	replayResponseBytesCap = 4 * 1024
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

type mutationSpec struct {
	Name    string
	Type    string
	Payload string
}

type replaySummary struct {
	Status         int         `json:"status"`
	ResponseLen    int         `json:"response_length"`
	ContentHash    string      `json:"content_hash,omitempty"`
	ResponseTimeMs int64       `json:"response_time_ms"`
	Headers        gohttp.Header `json:"headers,omitempty"`
	Excerpt        string      `json:"excerpt,omitempty"`
	Truncated      bool        `json:"excerpt_truncated,omitempty"`
	Error          string      `json:"error,omitempty"`
}

type replayDiff struct {
	StatusChanged    bool   `json:"status_changed"`
	LengthDelta      int    `json:"length_delta"`
	ContentChanged   bool   `json:"content_changed"`
	ReflectsPayload  []string `json:"reflects_payload,omitempty"`
	BaselineStatus   int    `json:"baseline_status"`
	BaselineLen      int    `json:"baseline_length"`
	BaselineHash     string `json:"baseline_content_hash,omitempty"`
	Interpretation   string `json:"interpretation,omitempty"`
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

	var mutated []byte
	var matchedPayloads []string
	var additionalGroups int
	if rawOverride != "" {
		mutated = []byte(rawOverride)
	} else {
		points, err := httpmsg.CreateAllInsertionPoints(rec.RawRequest, false)
		if err != nil {
			return tool.Result{
				Content: fmt.Sprintf("replay_request: parse insertion points: %v", err),
				IsError: true,
			}, nil
		}
		payloadMap := httpmsg.PayloadMap{}
		unmatched := []string{}
		matchedPayloads = make([]string, 0, len(mutations))
		for _, m := range mutations {
			ip := findInsertionPoint(points, m.Name, m.Type)
			if ip == nil {
				unmatched = append(unmatched, m.Name)
				continue
			}
			payloadMap[ip] = []byte(m.Payload)
			matchedPayloads = append(matchedPayloads, m.Payload)
		}
		if len(payloadMap) == 0 {
			return tool.Result{
				Content: fmt.Sprintf("replay_request: no insertion points matched. unmatched names: %s. "+
					"Use inspect_record to see the actual insertion-point list.", strings.Join(unmatched, ", ")),
				IsError: true,
			}, nil
		}
		built, err := httpmsg.BuildRequestWithPayloads(rec.RawRequest, payloadMap)
		if err != nil {
			return tool.Result{Content: fmt.Sprintf("replay_request: build mutated request: %v", err), IsError: true}, nil
		}
		// BuildRequestWithPayloads can return multiple non-conflicting groups
		// when nested IPs conflict with parents. We send the first one and
		// surface the leftover count so the agent can re-call if it needs
		// to fire the other groups too.
	mutated = built[0]
		additionalGroups = len(built) - 1
	}
	r.incPerRecord(uuid)

	// Header overlays: auth-session merge + extra_headers. Both override
	// whatever was in the original request.
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
	if len(overlay) > 0 {
		mutated = overlayHeaders(mutated, overlay)
	}

	r.totalRun.Add(1)

	noRedir := argsBool(args, "no_redirects")
	replay := r.sendRawHTTP(ctx, mutated, rec.Scheme, rec.Hostname, rec.Port, noRedir)

	baseline := baselineFromRecord(rec)
	diff := computeDiff(baseline, replay, matchedPayloads)

	// Echo the sent bytes back so the agent can audit exactly what landed
	// on the wire after IP mutation + header overlay. Truncated to the same
	// excerpt cap as the response.
	sentReq, sentTrunc := clipBytes(mutated, replayResponseBytesCap)

	out := struct {
		RecordUUID       string         `json:"record_uuid"`
		MutatedRequest   string         `json:"mutated_request"`
		RequestTruncated bool           `json:"mutated_request_truncated,omitempty"`
		Baseline         *replaySummary `json:"baseline"`
		Replay           *replaySummary `json:"replay"`
		Diff             *replayDiff    `json:"diff"`
		AdditionalGroups int            `json:"additional_payload_groups,omitempty"`
	}{
		RecordUUID:       uuid,
		MutatedRequest:   sentReq,
		RequestTruncated: sentTrunc,
		Baseline:         baseline,
		Replay:           replay,
		Diff:             diff,
		AdditionalGroups: additionalGroups,
	}
	body, _ := json.Marshal(out)

	details := map[string]any{
		"record_uuid":     uuid,
		"status":          replay.Status,
		"length_delta":    diff.LengthDelta,
		"content_changed": diff.ContentChanged,
	}
	if len(diff.ReflectsPayload) > 0 {
		details["reflects_payload"] = true
	}
	if additionalGroups > 0 {
		details["additional_payload_groups"] = additionalGroups
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
// concrete []mutationSpec shapes and the more common JSON-decoded
// []any-of-map.
func parseMutations(raw any) ([]mutationSpec, error) {
	if raw == nil {
		return nil, nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("'mutations' must be an array")
	}
	out := make([]mutationSpec, 0, len(arr))
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
		out = append(out, mutationSpec{Name: name, Type: typ, Payload: payload})
	}
	return out, nil
}

// findInsertionPoint locates the first IP that matches name (and, if
// non-empty, the requested type string). Type strings come from
// InsertionPointType.String() — e.g. "URL_PARAM", "HEADER", "JSON_PARAM".
func findInsertionPoint(points []httpmsg.InsertionPoint, name, typeStr string) httpmsg.InsertionPoint {
	for _, p := range points {
		if p.Name() != name {
			continue
		}
		if typeStr == "" || strings.EqualFold(p.Type().String(), typeStr) {
			return p
		}
	}
	return nil
}

// overlayHeaders rewrites the header block of a raw HTTP request, replacing
// existing headers (case-insensitive name match) and appending new ones.
// Body is preserved verbatim. Delegates per-key to utils.AddOrReplaceHeader
// so case-handling and offset math stay in one place.
func overlayHeaders(raw []byte, overlay map[string]string) []byte {
	for k, v := range overlay {
		raw = utils.AddOrReplaceHeader(raw, k, v)
	}
	return raw
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
		r.client = &gohttp.Client{
			Timeout: replayHTTPTimeout,
			Jar:     jar,
			Transport: &gohttp.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				Proxy:           proxyFromEnv,
			},
		}
	})
	return r.client
}

// proxyFromEnv mirrors the precedence vigolium's own Requester uses:
// HTTP_PROXY / HTTPS_PROXY (uppercase first, lowercase fallback). We do not
// honour NO_PROXY because attack-validation traffic is rarely something
// you'd want to bypass the proxy for, and a misconfigured NO_PROXY hides
// the very traffic the operator wants to inspect.
func proxyFromEnv(req *gohttp.Request) (*url.URL, error) {
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		if v := os.Getenv(k); v != "" {
			return url.Parse(v)
		}
	}
	return nil, nil
}

// sendRawHTTP parses raw request bytes back into a net/http.Request, sends
// it via the shared client, and returns a replaySummary. Network and parse
// errors land in summary.Error rather than as Go errors so the model
// always gets a structured response.
func (r *replayRequestTool) sendRawHTTP(ctx context.Context, raw []byte, scheme, hostname string, port int, noRedirects bool) *replaySummary {
	req, err := gohttp.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return &replaySummary{Error: fmt.Sprintf("parse mutated request: %v", err)}
	}
	defer func() {
		if req.Body != nil {
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
		}
	}()

	// http.ReadRequest gives us a server-side Request; rewrite the URL so
	// the standard client can dispatch it.
	if scheme == "" {
		scheme = "http"
	}
	host := hostname
	if port > 0 && (scheme != "http" || port != 80) && (scheme != "https" || port != 443) {
		host = fmt.Sprintf("%s:%d", hostname, port)
	}
	target := &url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     req.URL.Path,
		RawQuery: req.URL.RawQuery,
	}
	req.URL = target
	req.Host = hostname
	req.RequestURI = ""

	// Set a recognisable UA if the request didn't carry one — some WAFs
	// reject empty UA outright, which would manifest as a misleading 403
	// vs baseline and waste agent turns debugging.
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (vigolium-autopilot replay_request)")
	}

	// We share a client across calls but per-call redirect policy varies,
	// so use a copy when no_redirects is set rather than mutating the
	// shared instance.
	client := r.getClient()
	if noRedirects {
		client = &gohttp.Client{
			Timeout:   client.Timeout,
			Transport: client.Transport,
			Jar:       client.Jar,
			CheckRedirect: func(*gohttp.Request, []*gohttp.Request) error {
				return gohttp.ErrUseLastResponse
			},
		}
	}

	req = req.WithContext(ctx)
	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return &replaySummary{
			Error:          fmt.Sprintf("request failed: %v", err),
			ResponseTimeMs: elapsed.Milliseconds(),
		}
	}
	defer func() { _ = resp.Body.Close() }()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	sum := sha256.Sum256(bodyBytes)
	excerpt, truncated := clipBytes(bodyBytes, replayResponseBytesCap)

	return &replaySummary{
		Status:         resp.StatusCode,
		ResponseLen:    len(bodyBytes),
		ContentHash:    hex.EncodeToString(sum[:8]),
		ResponseTimeMs: elapsed.Milliseconds(),
		Headers:        resp.Header,
		Excerpt:        excerpt,
		Truncated:      truncated,
	}
}

// baselineFromRecord builds a comparison baseline from the originally stored
// response. We hash the body content so the diff catches changes that don't
// shift content-length.
func baselineFromRecord(rec *database.HTTPRecord) *replaySummary {
	body := extractResponseBody(rec.RawResponse)
	sum := sha256.Sum256(body)
	excerpt, truncated := clipBytes(body, replayResponseBytesCap)
	return &replaySummary{
		Status:         rec.StatusCode,
		ResponseLen:    len(body),
		ContentHash:    hex.EncodeToString(sum[:8]),
		ResponseTimeMs: rec.ResponseTimeMs,
		Excerpt:        excerpt,
		Truncated:      truncated,
	}
}

// extractResponseBody splits a raw HTTP response at the header/body
// separator and returns just the body. Defers to utils.GetBodyStart so
// LF-only / CRLF handling stays in one place.
func extractResponseBody(raw []byte) []byte {
	return raw[utils.GetBodyStart(raw):]
}

// computeDiff compares baseline and replay, emitting flags and an
// interpretation hint the model can quote in its reasoning.
func computeDiff(baseline, replay *replaySummary, payloads []string) *replayDiff {
	d := &replayDiff{
		BaselineStatus: baseline.Status,
		BaselineLen:    baseline.ResponseLen,
		BaselineHash:   baseline.ContentHash,
	}
	if replay.Error != "" {
		d.Interpretation = "replay returned a network error; see replay.error"
		return d
	}
	d.StatusChanged = replay.Status != baseline.Status
	d.LengthDelta = replay.ResponseLen - baseline.ResponseLen
	d.ContentChanged = replay.ContentHash != baseline.ContentHash

	for _, p := range payloads {
		if p == "" {
			continue
		}
		if strings.Contains(replay.Excerpt, p) {
			d.ReflectsPayload = append(d.ReflectsPayload, p)
		}
	}

	switch {
	case len(d.ReflectsPayload) > 0:
		d.Interpretation = "payload reflected verbatim in response body — likely candidate for XSS / template injection / SSRF reflection; verify context."
	case d.StatusChanged && replay.Status >= 500:
		d.Interpretation = "server error after mutation — possible injection causing exception; inspect excerpt for stack trace / error message."
	case d.StatusChanged:
		d.Interpretation = fmt.Sprintf("status changed %d → %d; possible auth/logic effect.", baseline.Status, replay.Status)
	case d.ContentChanged && abs(d.LengthDelta) > 64:
		d.Interpretation = "response content materially different from baseline; worth manual inspection."
	case d.ContentChanged:
		d.Interpretation = "response content differs in small ways from baseline (formatting / timestamps / nonces typical)."
	default:
		d.Interpretation = "response identical to baseline; payload likely did not take effect."
	}
	return d
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
