package tool

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// ---------- grep ----------

type grepTool struct{}

func NewGrep() Tool { return &grepTool{} }

func (grepTool) Name() string     { return "grep" }
func (grepTool) Label() string    { return "Grep files" }
func (grepTool) Category() string { return CategoryBuiltin }
func (grepTool) IsReadOnly() bool { return true }
func (grepTool) Description() string {
	return "Search for a regex pattern in files. Uses ripgrep (rg) if available, else a native Go regex scan. Returns file:line:match lines."
}
func (grepTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"pattern":     map[string]any{"type": "string", "description": "Regex pattern."},
			"path":        map[string]any{"type": "string", "description": "Directory or file to search. Defaults to '.'"},
			"glob":        map[string]any{"type": "string", "description": "Optional filename glob (e.g. '*.go')."},
			"max_matches": map[string]any{"type": "integer", "default": 200},
			"ignore_case": map[string]any{"type": "boolean", "default": false},
		},
		"required": []string{"pattern"},
	}
}

func (grepTool) Execute(ctx context.Context, args map[string]any, onUpdate UpdateFn) (Result, error) {
	pattern, _ := args["pattern"].(string)
	if pattern == "" {
		return Result{Content: "error: pattern is required", IsError: true}, nil
	}
	searchPath, _ := args["path"].(string)
	if searchPath == "" {
		searchPath = "."
	}
	globPat, _ := args["glob"].(string)
	maxMatches := 200
	if v, ok := args["max_matches"].(float64); ok && int(v) > 0 {
		maxMatches = int(v)
	}
	ignoreCase, _ := args["ignore_case"].(bool)

	if _, err := exec.LookPath("rg"); err == nil {
		return runRipgrep(ctx, pattern, searchPath, globPat, maxMatches, ignoreCase)
	}
	return runNativeGrep(ctx, pattern, searchPath, globPat, maxMatches, ignoreCase)
}

func runRipgrep(ctx context.Context, pattern, path, glob string, maxMatches int, ignoreCase bool) (Result, error) {
	args := []string{"--no-heading", "--line-number", "--color", "never", "--max-count", fmt.Sprintf("%d", maxMatches)}
	if ignoreCase {
		args = append(args, "-i")
	}
	if glob != "" {
		args = append(args, "-g", glob)
	}
	args = append(args, pattern, path)

	cmd := exec.CommandContext(ctx, "rg", args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return Result{Content: "(no matches)"}, nil
		}
		return Result{Content: fmt.Sprintf("rg error: %v\n%s", err, string(out)), IsError: true}, nil
	}
	return Result{
		Content: string(out),
		Details: map[string]any{"engine": "ripgrep"},
	}, nil
}

func runNativeGrep(ctx context.Context, pattern, root, glob string, maxMatches int, ignoreCase bool) (Result, error) {
	flags := ""
	if ignoreCase {
		flags = "(?i)"
	}
	re, err := regexp.Compile(flags + pattern)
	if err != nil {
		return Result{Content: fmt.Sprintf("invalid regex: %v", err), IsError: true}, nil
	}

	var (
		out     strings.Builder
		matches int
	)

	walkErr := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if info.IsDir() {
			// Skip common noise dirs to keep native grep useful.
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" || name == ".venv" {
				return filepath.SkipDir
			}
			return nil
		}
		if glob != "" {
			matched, _ := filepath.Match(glob, filepath.Base(p))
			if !matched {
				return nil
			}
		}
		// Skip obvious binaries.
		if looksBinary(p) {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if re.MatchString(line) {
				fmt.Fprintf(&out, "%s:%d:%s\n", p, i+1, line)
				matches++
				if matches >= maxMatches {
					return filepath.SkipAll
				}
			}
		}
		return nil
	})
	if walkErr != nil && walkErr != context.Canceled {
		return Result{Content: fmt.Sprintf("walk error: %v", walkErr), IsError: true}, nil
	}
	if matches == 0 {
		return Result{Content: "(no matches)"}, nil
	}
	return Result{
		Content: out.String(),
		Details: map[string]any{"engine": "native", "matches": matches},
	}, nil
}

func looksBinary(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".tar", ".gz", ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".class", ".jar":
		return true
	}
	return false
}

// ---------- glob ----------

type globTool struct{}

func NewGlob() Tool { return &globTool{} }

func (globTool) Name() string     { return "glob" }
func (globTool) Label() string    { return "Glob files" }
func (globTool) Category() string { return CategoryBuiltin }
func (globTool) IsReadOnly() bool { return true }
func (globTool) Description() string {
	return "Find files matching a glob pattern. Supports ** for recursive matching."
}
func (globTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"pattern": map[string]any{"type": "string", "description": "Glob pattern, e.g. '**/*.go' or 'cmd/**/main.go'."},
			"root":    map[string]any{"type": "string", "description": "Root directory. Default '.'"},
		},
		"required": []string{"pattern"},
	}
}

func (globTool) Execute(ctx context.Context, args map[string]any, onUpdate UpdateFn) (Result, error) {
	pattern, _ := args["pattern"].(string)
	root, _ := args["root"].(string)
	if root == "" {
		root = "."
	}
	if pattern == "" {
		return Result{Content: "error: pattern is required", IsError: true}, nil
	}

	// Use doublestar-style walk: "**" matches zero or more path segments.
	// For simplicity we translate the pattern into a regex and walk.
	re, err := globToRegex(pattern)
	if err != nil {
		return Result{Content: fmt.Sprintf("invalid glob: %v", err), IsError: true}, nil
	}

	var (
		matches []string
		limit   = 1000
	)
	err = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" || name == ".venv" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if re.MatchString(rel) || re.MatchString(p) {
			matches = append(matches, p)
			if len(matches) >= limit {
				return filepath.SkipAll
			}
		}
		return nil
	})
	if err != nil && err != context.Canceled {
		return Result{Content: fmt.Sprintf("walk error: %v", err), IsError: true}, nil
	}
	if len(matches) == 0 {
		return Result{Content: "(no matches)"}, nil
	}
	return Result{
		Content: strings.Join(matches, "\n"),
		Details: map[string]any{"count": len(matches)},
	}, nil
}

// globToRegex converts a shell-style glob with ** support to a Go regex.
// Unlike filepath.Match, this handles recursive `**` segments.
func globToRegex(glob string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	i := 0
	for i < len(glob) {
		c := glob[i]
		switch c {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				b.WriteString(".*")
				i += 2
				if i < len(glob) && glob[i] == '/' {
					i++
				}
			} else {
				b.WriteString("[^/]*")
				i++
			}
		case '?':
			b.WriteString("[^/]")
			i++
		case '.', '+', '(', ')', '|', '^', '$', '{', '}', '[', ']', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
			i++
		default:
			b.WriteByte(c)
			i++
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}
