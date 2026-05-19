package tool

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ---------- read_file ----------

type readFileTool struct{}

func NewReadFile() Tool { return &readFileTool{} }

func (readFileTool) Name() string     { return "read_file" }
func (readFileTool) Label() string    { return "Read file" }
func (readFileTool) Category() string { return CategoryBuiltin }
func (readFileTool) IsReadOnly() bool { return true }
func (readFileTool) Description() string {
	return "Read a file from the filesystem. Returns the content as UTF-8 text with line numbers. Use for inspecting source, configs, logs."
}
func (readFileTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{"type": "string", "description": "Absolute or relative path."},
			"offset": map[string]any{
				"type":        "integer",
				"description": "1-indexed line number to start from. Default 1.",
				"default":     1,
			},
			"limit": map[string]any{
				"type":        "integer",
				"description": "Max lines to return. Default 2000.",
				"default":     2000,
			},
		},
		"required": []string{"path"},
	}
}

func (readFileTool) Execute(ctx context.Context, args map[string]any, onUpdate UpdateFn) (Result, error) {
	path, _ := args["path"].(string)
	if path == "" {
		return Result{Content: "error: path is required", IsError: true}, nil
	}
	offset := 1
	if v, ok := args["offset"].(float64); ok && int(v) > 0 {
		offset = int(v)
	}
	limit := 2000
	if v, ok := args["limit"].(float64); ok && int(v) > 0 {
		limit = int(v)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Result{Content: fmt.Sprintf("read error: %v", err), IsError: true}, nil
	}
	lines := strings.Split(string(data), "\n")

	start := offset - 1
	if start < 0 {
		start = 0
	}
	if start >= len(lines) {
		return Result{Content: fmt.Sprintf("(empty range; file has %d lines)", len(lines))}, nil
	}
	end := start + limit
	if end > len(lines) {
		end = len(lines)
	}

	var out strings.Builder
	for i := start; i < end; i++ {
		fmt.Fprintf(&out, "%5d\t%s\n", i+1, lines[i])
	}
	if end < len(lines) {
		fmt.Fprintf(&out, "\n... (%d more lines not shown; use offset/limit)\n", len(lines)-end)
	}
	return Result{
		Content: out.String(),
		Details: map[string]any{"total_lines": len(lines), "shown": end - start, "path": path},
	}, nil
}

// ---------- write_file ----------

type writeFileTool struct{}

func NewWriteFile() Tool { return &writeFileTool{} }

func (writeFileTool) Name() string     { return "write_file" }
func (writeFileTool) Label() string    { return "Write file" }
func (writeFileTool) Category() string { return CategoryBuiltin }
func (writeFileTool) IsReadOnly() bool { return false }
func (writeFileTool) Description() string {
	return "Create or overwrite a file with the given content. Parent directories must exist."
}
func (writeFileTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path":    map[string]any{"type": "string"},
			"content": map[string]any{"type": "string"},
		},
		"required": []string{"path", "content"},
	}
}

func (writeFileTool) Execute(ctx context.Context, args map[string]any, onUpdate UpdateFn) (Result, error) {
	path, _ := args["path"].(string)
	content, _ := args["content"].(string)
	if path == "" {
		return Result{Content: "error: path is required", IsError: true}, nil
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return Result{Content: fmt.Sprintf("write error: %v", err), IsError: true}, nil
	}
	return Result{
		Content: fmt.Sprintf("wrote %d bytes to %s", len(content), path),
		Details: map[string]any{"path": path, "bytes": len(content)},
	}, nil
}

// ---------- edit_file ----------

type editFileTool struct{}

func NewEditFile() Tool { return &editFileTool{} }

func (editFileTool) Name() string     { return "edit_file" }
func (editFileTool) Label() string    { return "Edit file" }
func (editFileTool) Category() string { return CategoryBuiltin }
func (editFileTool) IsReadOnly() bool { return false }
func (editFileTool) Description() string {
	return "Replace exact occurrences of a string in a file. old_string must match uniquely unless replace_all is true. Preserves indentation — pass the literal text."
}
func (editFileTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path":        map[string]any{"type": "string"},
			"old_string":  map[string]any{"type": "string", "description": "Exact text to replace."},
			"new_string":  map[string]any{"type": "string", "description": "Replacement text."},
			"replace_all": map[string]any{"type": "boolean", "default": false},
		},
		"required": []string{"path", "old_string", "new_string"},
	}
}

func (editFileTool) Execute(ctx context.Context, args map[string]any, onUpdate UpdateFn) (Result, error) {
	path, _ := args["path"].(string)
	oldStr, _ := args["old_string"].(string)
	newStr, _ := args["new_string"].(string)
	replaceAll, _ := args["replace_all"].(bool)

	if path == "" || oldStr == "" {
		return Result{Content: "error: path and old_string are required", IsError: true}, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return Result{Content: fmt.Sprintf("read error: %v", err), IsError: true}, nil
	}
	content := string(raw)

	count := strings.Count(content, oldStr)
	if count == 0 {
		return Result{Content: "old_string not found in file", IsError: true}, nil
	}
	if !replaceAll && count > 1 {
		return Result{
			Content: fmt.Sprintf("old_string appears %d times; either pass replace_all=true or expand the old_string with more context", count),
			IsError: true,
		}, nil
	}

	var updated string
	if replaceAll {
		updated = strings.ReplaceAll(content, oldStr, newStr)
	} else {
		updated = strings.Replace(content, oldStr, newStr, 1)
	}
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		return Result{Content: fmt.Sprintf("write error: %v", err), IsError: true}, nil
	}
	return Result{
		Content: fmt.Sprintf("edited %s (%d replacement%s)", path, map[bool]int{true: count, false: 1}[replaceAll], plural(count)),
		Details: map[string]any{"path": path, "replacements": map[bool]int{true: count, false: 1}[replaceAll]},
	}, nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// ---------- ls ----------

type lsTool struct{}

func NewLs() Tool { return &lsTool{} }

func (lsTool) Name() string     { return "ls" }
func (lsTool) Label() string    { return "List directory" }
func (lsTool) Category() string { return CategoryBuiltin }
func (lsTool) IsReadOnly() bool { return true }
func (lsTool) Description() string {
	return "List entries in a directory. Returns names with size and type (file/dir)."
}
func (lsTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{"type": "string", "description": "Directory path. Defaults to current working directory."},
		},
	}
}

func (lsTool) Execute(ctx context.Context, args map[string]any, onUpdate UpdateFn) (Result, error) {
	path, _ := args["path"].(string)
	if path == "" {
		path = "."
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return Result{Content: fmt.Sprintf("ls error: %v", err), IsError: true}, nil
	}
	var out strings.Builder
	for _, e := range entries {
		info, ierr := e.Info()
		kind := "file"
		size := int64(0)
		if ierr == nil {
			size = info.Size()
		}
		if e.IsDir() {
			kind = "dir"
		}
		fmt.Fprintf(&out, "%-5s %10d  %s\n", kind, size, e.Name())
	}
	abs, _ := filepath.Abs(path)
	return Result{
		Content: out.String(),
		Details: map[string]any{"path": abs, "count": len(entries)},
	}, nil
}
