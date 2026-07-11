package vigtool

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// runExtensionCallCap is the per-run hard cap on run_extension invocations.
// Higher than run_scan because iterating on a custom script is the whole
// point of the tool — but still a ceiling so the loop can't run forever.
const runExtensionCallCap = 20

// NewRunExtensionTool returns the run_extension tool that loads a single
// JS extension and runs it against one or more targets in isolation.
func NewRunExtensionTool(ctx *ScanContext) tool.Tool {
	return &runExtensionTool{ctx: ctx}
}

type runExtensionTool struct {
	ctx   *ScanContext
	count atomic.Int64
}

func (*runExtensionTool) Name() string     { return "run_extension" }
func (*runExtensionTool) Label() string    { return "Run JS extension" }
func (*runExtensionTool) Category() string { return tool.CategoryVigolium }
func (*runExtensionTool) IsReadOnly() bool { return false }
func (*runExtensionTool) Description() string {
	return "Run a single vigolium JavaScript extension against one or more targets and return its findings. " +
		"Provide either 'script_path' (path to an existing .js file) or 'script_source' (inline JS code). " +
		"By default the supplied script runs in isolation — built-in modules are skipped. " +
		"Use this for ad-hoc custom logic; for full scanner coverage, use run_scan. " +
		"See the 'write-jsext' skill for the vigolium.* JS API surface."
}

func (*runExtensionTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"targets": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "URLs or hostnames the extension should run against.",
			},
			"script_path": map[string]any{
				"type":        "string",
				"description": "Path to an existing .js extension file. Mutually exclusive with script_source.",
			},
			"script_source": map[string]any{
				"type":        "string",
				"description": "Inline JS extension source. The tool writes it to a temp file and loads that. Mutually exclusive with script_path.",
			},
			"include_builtins": map[string]any{
				"type":        "boolean",
				"description": "Run built-in scanner modules alongside the extension. Default false (extension-only).",
				"default":     false,
			},
			"concurrency": map[string]any{
				"type":        "integer",
				"description": "Worker count override. Default uses settings default.",
			},
		},
		"required": []string{"targets"},
	}
}

func (r *runExtensionTool) Execute(ctx context.Context, args map[string]any, onUpdate tool.UpdateFn) (tool.Result, error) {
	if r.ctx == nil {
		return tool.Result{
			Content: "run_extension unavailable: no scan context configured for this run",
			IsError: true,
		}, nil
	}
	if cur := r.count.Load(); cur >= runExtensionCallCap {
		return tool.Result{
			Content: fmt.Sprintf(
				"run_extension rate-limited: %d extension runs this session (cap=%d). "+
					"If you're still iterating, halt and resume with a fresh run.",
				cur, runExtensionCallCap),
			IsError: true,
		}, nil
	}

	targets := argsStringArray(args, "targets")
	if len(targets) == 0 {
		return tool.Result{
			Content: "run_extension: 'targets' is required and must be non-empty",
			IsError: true,
		}, nil
	}

	scriptPath := argsString(args, "script_path")
	scriptSource := argsString(args, "script_source")
	if scriptPath == "" && scriptSource == "" {
		return tool.Result{
			Content: "run_extension: provide either 'script_path' or 'script_source'",
			IsError: true,
		}, nil
	}
	if scriptPath != "" && scriptSource != "" {
		return tool.Result{
			Content: "run_extension: 'script_path' and 'script_source' are mutually exclusive",
			IsError: true,
		}, nil
	}

	resolved, cleanup, err := resolveExtensionPath(scriptPath, scriptSource)
	if err != nil {
		return tool.Result{
			Content: fmt.Sprintf("run_extension: %v", err),
			IsError: true,
		}, nil
	}
	if cleanup != nil {
		defer cleanup()
	}

	includeBuiltins := argsBool(args, "include_builtins")
	params := runner.LaunchParams{
		Targets:        targets,
		ProjectUUID:    r.ctx.ProjectUUID,
		ConfigPath:     r.ctx.ConfigPath,
		ExtensionPaths: []string{resolved},
		ExtensionsOnly: !includeBuiltins,
		Repository:     r.ctx.Repo,
		Concurrency:    argsInt(args, "concurrency"),
	}

	if onUpdate != nil {
		onUpdate(tool.Result{
			Content: fmt.Sprintf("loading extension %s; targets=%s", filepath.Base(resolved), strings.Join(targets, ",")),
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
			Content: fmt.Sprintf("extension run failed (uuid=%s): %v", uuid, err),
			IsError: true,
		}, nil
	}

	// Attribute this child scan (and its findings) to the parent agentic scan.
	r.ctx.attributeChildScan(ctx, res.ScanUUID)

	body, _ := json.Marshal(res)
	return tool.Result{
		Content: string(body),
		Details: map[string]any{
			"scan_uuid":     res.ScanUUID,
			"status":        res.Status,
			"finding_count": res.FindingCount,
			"duration_ms":   res.DurationMs,
			"script":        filepath.Base(resolved),
		},
	}, nil
}

// resolveExtensionPath returns an absolute path to the script the runner
// should load. When inline source is supplied, writes it to a temp file
// and returns a cleanup func; the caller is responsible for invoking
// cleanup once the scan finishes.
func resolveExtensionPath(scriptPath, scriptSource string) (string, func(), error) {
	if scriptPath != "" {
		abs, err := filepath.Abs(scriptPath)
		if err != nil {
			return "", nil, fmt.Errorf("resolve %q: %w", scriptPath, err)
		}
		if _, err := os.Stat(abs); err != nil {
			return "", nil, fmt.Errorf("script_path: %w", err)
		}
		return abs, nil, nil
	}

	tmp, err := os.CreateTemp("", "vigolium-run-extension-*.js")
	if err != nil {
		return "", nil, fmt.Errorf("create temp script: %w", err)
	}
	if _, err := tmp.WriteString(scriptSource); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", nil, fmt.Errorf("write temp script: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", nil, fmt.Errorf("close temp script: %w", err)
	}
	cleanup := func() { _ = os.Remove(tmp.Name()) }
	return tmp.Name(), cleanup, nil
}
