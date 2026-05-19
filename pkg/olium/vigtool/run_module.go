package vigtool

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// runModuleCallCap bounds invocations per run. Higher than run_scan because
// run_module is the intended primitive for iterative module-focused validation,
// but still bounded so a misbehaving agent can't fire dozens of full scans.
const runModuleCallCap = 10

// NewRunModuleTool returns the run_module tool — runs a focused
// dynamic-assessment scan using a specific module set (by id, tag, or both)
// against one or more targets. Skips discovery/spidering so the run is
// narrow and fast compared to run_scan.
func NewRunModuleTool(ctx *ScanContext) tool.Tool {
	return &runModuleTool{ctx: ctx}
}

type runModuleTool struct {
	ctx   *ScanContext
	count atomic.Int64
}

func (*runModuleTool) Name() string     { return "run_module" }
func (*runModuleTool) Label() string    { return "Run focused module scan" }
func (*runModuleTool) Category() string { return tool.CategoryVigolium }
func (*runModuleTool) IsReadOnly() bool { return false }
func (*runModuleTool) Description() string {
	return "Run a focused vigolium scan with a narrow module set against one or more targets. " +
		"Either supply 'modules' (exact ids or substring patterns — same matching as the CLI's " +
		"-m flag) or 'tags' (e.g. 'xss', 'spring') or both; the union is scanned. By default " +
		"runs just the dynamic-assessment phase (no discovery, no spidering) — for fresh targets " +
		"where the project has no records yet, set scope='fresh' to also enable discovery. Use " +
		"list_modules to find valid ids/tags first. Cheaper than run_scan when you already know " +
		"what you want to confirm."
}

func (*runModuleTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"targets": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "URLs or hostnames to scan. Required.",
			},
			"modules": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "Module ids or substring patterns (e.g. ['xss-reflected','sqli']). At least one of modules/tags is required.",
			},
			"tags": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "Module tags to include (e.g. ['xss','injection']). At least one of modules/tags is required.",
			},
			"scope": map[string]any{
				"type":        "string",
				"enum":        []string{"rescan", "fresh"},
				"description": "rescan = re-use existing project records (only dynamic-assessment). fresh = also run discovery first. Default rescan.",
			},
		},
		"required": []string{"targets"},
	}
}

func (r *runModuleTool) Execute(ctx context.Context, args map[string]any, onUpdate tool.UpdateFn) (tool.Result, error) {
	if r.ctx == nil {
		return tool.Result{Content: "run_module unavailable: no scan context configured for this run", IsError: true}, nil
	}
	if cur := r.count.Load(); cur >= runModuleCallCap {
		return tool.Result{
			Content: fmt.Sprintf("run_module rate-limited: %d focused scans this session (cap=%d).", cur, runModuleCallCap),
			IsError: true,
		}, nil
	}

	targets := argsStringArray(args, "targets")
	if len(targets) == 0 {
		return tool.Result{Content: "run_module: 'targets' is required and must be non-empty", IsError: true}, nil
	}

	rawModules := argsStringArray(args, "modules")
	tags := argsStringArray(args, "tags")
	if len(rawModules) == 0 && len(tags) == 0 {
		return tool.Result{Content: "run_module: at least one of 'modules' or 'tags' is required", IsError: true}, nil
	}

	resolved := resolveModuleSet(rawModules, tags)
	if len(resolved) == 0 {
		return tool.Result{
			Content: fmt.Sprintf("run_module: no modules matched modules=%v tags=%v. Use list_modules to discover valid ids.", rawModules, tags),
			IsError: true,
		}, nil
	}

	scope := strings.ToLower(argsString(args, "scope"))
	if scope == "" {
		scope = "rescan"
	}
	var onlyPhase string
	switch scope {
	case "rescan":
		onlyPhase = "dynamic-assessment"
	case "fresh":
		onlyPhase = "discovery,dynamic-assessment"
	default:
		return tool.Result{Content: fmt.Sprintf("run_module: unknown scope %q (use rescan|fresh)", scope), IsError: true}, nil
	}

	params := runner.LaunchParams{
		Targets:     targets,
		ProjectUUID: r.ctx.ProjectUUID,
		ConfigPath:  r.ctx.ConfigPath,
		Modules:     resolved,
		Repository:  r.ctx.Repo,
		OnlyPhase:   onlyPhase,
	}

	if onUpdate != nil {
		onUpdate(tool.Result{
			Content: fmt.Sprintf("run_module: scanning %d target(s) with %d module(s); scope=%s",
				len(targets), len(resolved), scope),
		})
	}
	r.count.Add(1)

	res, err := runner.LaunchScan(ctx, params)
	if err != nil {
		uuid := ""
		if res != nil {
			uuid = res.ScanUUID
		}
		return tool.Result{Content: fmt.Sprintf("run_module failed (uuid=%s): %v", uuid, err), IsError: true}, nil
	}

	body, _ := json.Marshal(res)
	return tool.Result{
		Content: string(body),
		Details: map[string]any{
			"scan_uuid":     res.ScanUUID,
			"status":        res.Status,
			"finding_count": res.FindingCount,
			"modules_used":  len(resolved),
		},
	}, nil
}

// resolveModuleSet folds module-id patterns and tag patterns into one
// deduplicated list of concrete module IDs.
func resolveModuleSet(modulesArg, tags []string) []string {
	seen := map[string]bool{}
	out := []string{}

	if len(modulesArg) > 0 {
		for _, id := range modules.DefaultRegistry.ResolveModulePatterns(modulesArg) {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	if len(tags) > 0 {
		for _, id := range modules.DefaultRegistry.ResolveModuleTags(tags) {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}
