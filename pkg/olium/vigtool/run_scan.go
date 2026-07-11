package vigtool

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/detect"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// runScanCallCap is the per-run hard cap on run_scan invocations. A
// well-behaved agent issues 1–3 scans per session; past this the loop is
// almost always thrashing and burning project budget.
const runScanCallCap = 5

// NewRunScanTool returns the run_scan tool that launches a vigolium native
// scan and blocks until completion. The returned tool shares a counter
// across calls so the cap is per-run.
func NewRunScanTool(ctx *ScanContext) tool.Tool {
	return &runScanTool{ctx: ctx}
}

type runScanTool struct {
	ctx   *ScanContext
	count atomic.Int64
}

func (*runScanTool) Name() string     { return "run_native_scan" }
func (*runScanTool) Label() string    { return "Run vigolium native scan" }
func (*runScanTool) Category() string { return tool.CategoryVigolium }
func (*runScanTool) IsReadOnly() bool { return false }
func (*runScanTool) Description() string {
	return "Launch vigolium's native (deterministic, Go-module) scanner and wait for it to complete. " +
		"Returns the scan UUID, status, and finding counts by severity. Provide either `targets` " +
		"(URLs/hostnames) or `raw_request` (a raw HTTP request or curl command as a string — same " +
		"surface as `vigolium scan-request`); raw_request mode is ideal when you have a captured " +
		"request you want to fuzz directly. For one-off custom JS logic, use run_extension instead."
}

func (*runScanTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"targets": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "URLs or hostnames to scan. Provide either this or raw_request.",
			},
			"raw_request": map[string]any{
				"type":        "string",
				"description": "Alternative to targets: a full raw HTTP request or curl command. Vigolium parses, persists it as an http_record (source='agent-input'), then scans that record. Mirrors `vigolium scan-request`. Useful when you've crafted a specific request you want fuzzed.",
			},
			"raw_request_target": map[string]any{
				"type":        "string",
				"description": "Optional scheme://host override when raw_request lacks an absolute URL (e.g. relative paths). Ignored if raw_request is absent.",
			},
			"modules": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "Optional active-module allowlist (e.g. ['xss','sqli','spring']). Empty = all modules.",
			},
			"passive_modules": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "Optional passive-module allowlist. Empty = all passive modules.",
			},
			"scanning_strategy": map[string]any{
				"type":        "string",
				"enum":        []string{"lite", "balanced", "deep"},
				"description": "Optional named scanning strategy. Default uses settings default.",
			},
			"enable_discovery": map[string]any{
				"type":        "boolean",
				"description": "Enable content-discovery phase (slower). Default false.",
				"default":     false,
			},
			"enable_spidering": map[string]any{
				"type":        "boolean",
				"description": "Enable browser-based spidering (much slower). Default false.",
				"default":     false,
			},
			"concurrency": map[string]any{
				"type":        "integer",
				"description": "Worker count override. Default uses settings default.",
			},
			"only_phase": map[string]any{
				"type":        "string",
				"description": "Isolate one or more scan phases (comma-separated). Valid: discovery, spidering, dynamic-assessment, known-issue-scan, external-harvest, extension. Aliases accepted: deparos=discovery, dast/audit=dynamic-assessment, ext=extension. Mutually exclusive with skip_phases.",
			},
			"skip_phases": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "Phases to skip (e.g. ['discovery','spidering']). Mutually exclusive with only_phase.",
			},
		},
	}
}

func (r *runScanTool) Execute(ctx context.Context, args map[string]any, onUpdate tool.UpdateFn) (tool.Result, error) {
	if r.ctx == nil {
		return tool.Result{
			Content: "run_native_scan unavailable: no scan context configured for this run",
			IsError: true,
		}, nil
	}
	if cur := r.count.Load(); cur >= runScanCallCap {
		return tool.Result{
			Content: fmt.Sprintf(
				"run_native_scan rate-limited: %d scans already launched this run (cap=%d). "+
					"If you need another, halt and let the operator re-launch.",
				cur, runScanCallCap),
			IsError: true,
		}, nil
	}

	targets := argsStringArray(args, "targets")
	rawReq := argsString(args, "raw_request")
	if len(targets) == 0 && rawReq == "" {
		return tool.Result{
			Content: "run_native_scan: provide either 'targets' or 'raw_request'",
			IsError: true,
		}, nil
	}
	if len(targets) > 0 && rawReq != "" {
		return tool.Result{
			Content: "run_native_scan: 'targets' and 'raw_request' are mutually exclusive",
			IsError: true,
		}, nil
	}

	onlyPhase := argsString(args, "only_phase")
	skipPhases := argsStringArray(args, "skip_phases")
	source := "agent-input"

	if rawReq != "" {
		rr, perr := parseAgentRawRequest(rawReq, argsString(args, "raw_request_target"))
		if perr != nil {
			return tool.Result{Content: "run_native_scan: " + perr.Error(), IsError: true}, nil
		}
		// Persist the parsed request so the dynamic-assessment phase has
		// something to pick up. Scoping the scan to its target URL keeps
		// other records out of this run.
		if _, err := r.ctx.Repo.SaveRecord(ctx, rr, source, r.ctx.ProjectUUID); err != nil {
			return tool.Result{Content: fmt.Sprintf("run_native_scan: persist raw_request: %v", err), IsError: true}, nil
		}
		targets = []string{rr.Target()}
		// Raw-request mode is always a single-record audit — force
		// dynamic-assessment only so the runner doesn't crawl out from the
		// supplied request.
		if onlyPhase == "" {
			onlyPhase = "dynamic-assessment"
		}
	}

	params := runner.LaunchParams{
		Targets:          targets,
		ProjectUUID:      r.ctx.ProjectUUID,
		ConfigPath:       r.ctx.ConfigPath,
		Modules:          argsStringArray(args, "modules"),
		PassiveModules:   argsStringArray(args, "passive_modules"),
		ScanningStrategy: argsString(args, "scanning_strategy"),
		EnableDiscovery:  argsBool(args, "enable_discovery"),
		EnableSpidering:  argsBool(args, "enable_spidering"),
		Repository:       r.ctx.Repo,
		Concurrency:      argsInt(args, "concurrency"),
		OnlyPhase:        onlyPhase,
		SkipPhases:       skipPhases,
	}

	if onUpdate != nil {
		onUpdate(tool.Result{
			Content: fmt.Sprintf("starting scan: targets=%s", strings.Join(targets, ",")),
		})
	}
	r.count.Add(1)

	res, err := runner.LaunchScan(ctx, params)
	if err != nil {
		uuid := ""
		if res != nil {
			uuid = res.ScanUUID
		}
		return tool.Result{
			Content: fmt.Sprintf("scan failed (uuid=%s): %v", uuid, err),
			IsError: true,
		}, nil
	}

	// Attribute this child scan (and its findings) to the parent agentic scan.
	// The scan blocked to completion above, so every finding exists by now.
	r.ctx.attributeChildScan(ctx, res.ScanUUID)

	body, _ := json.Marshal(res)
	return tool.Result{
		Content: string(body),
		Details: map[string]any{
			"scan_uuid":     res.ScanUUID,
			"status":        res.Status,
			"finding_count": res.FindingCount,
			"duration_ms":   res.DurationMs,
		},
	}, nil
}

// parseAgentRawRequest accepts either a curl command or a raw HTTP request
// (auto-detected) and returns a parsed HttpRequestResponse. Mirrors the
// CLI's `scan-request` parsing path so behaviour stays identical.
func parseAgentRawRequest(raw, targetOverride string) (*httpmsg.HttpRequestResponse, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("raw_request: empty")
	}
	if detect.DetectStdinFormat(raw) == detect.FormatCurl {
		items, err := detect.ParseStdinContent(raw, detect.FormatCurl)
		if err != nil {
			return nil, fmt.Errorf("parse curl: %w", err)
		}
		if len(items) == 0 {
			return nil, fmt.Errorf("parse curl: no request extracted")
		}
		return items[0], nil
	}
	if targetOverride != "" {
		rr, err := httpmsg.ParseRawRequestWithURL(raw, targetOverride)
		if err != nil {
			return nil, fmt.Errorf("parse raw request: %w", err)
		}
		return rr, nil
	}
	rr, err := httpmsg.ParseRawRequest(raw)
	if err != nil {
		return nil, fmt.Errorf("parse raw request: %w", err)
	}
	return rr, nil
}
