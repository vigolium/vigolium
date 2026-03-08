package sourcetools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/toolexec"
	"go.uber.org/zap"
)

// Runner orchestrates running third-party security tools against source repos.
type Runner struct {
	config *config.ThirdPartyIntegrationConfig
	repo   *database.Repository
}

// New creates a Runner for executing third-party tools.
func New(cfg *config.ThirdPartyIntegrationConfig, repo *database.Repository) *Runner {
	return &Runner{
		config: cfg,
		repo:   repo,
	}
}

// RunResult holds the output of RunAll, including both raw and grouped counts.
type RunResult struct {
	Findings  []database.Finding
	RawCount  int
	GroupedAt int // number of grouped findings (same as len(Findings))
}

// RunAll runs all enabled tools against the given source repo.
// It saves findings to the database and returns them.
func (r *Runner) RunAll(ctx context.Context, sr *database.SourceRepo) (*RunResult, error) {
	result := &RunResult{}

	if !r.config.Enabled {
		return result, nil
	}

	timeout := r.config.TimeoutDuration()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var firstErr error

	for name, tool := range r.config.Tools {
		if !tool.Enabled {
			continue
		}

		// Check if tool binary exists
		if _, err := exec.LookPath(tool.Command); err != nil {
			zap.L().Debug("Third-party tool not found, skipping",
				zap.String("tool", name),
				zap.String("command", tool.Command))
			continue
		}

		var rawFindings []RawFinding
		var err error
		if len(tool.Steps) > 0 {
			rawFindings, err = r.RunMultiStepTool(ctx, name, tool, sr.RootPath)
		} else {
			rawFindings, err = r.RunTool(ctx, name, tool, sr.RootPath)
		}
		if err != nil {
			zap.L().Warn("Third-party tool failed",
				zap.String("tool", name),
				zap.Error(err))
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", name, err)
			}
			continue
		}

		result.RawCount += len(rawFindings)

		grouped := GroupFindings(rawFindings, sr)
		for i := range grouped {
			if r.repo != nil {
				if err := r.repo.SaveFindingDirect(ctx, &grouped[i]); err != nil {
					zap.L().Debug("Failed to save finding", zap.Error(err))
				}
			}
		}
		result.Findings = append(result.Findings, grouped...)
	}

	result.GroupedAt = len(result.Findings)
	return result, firstErr
}

// RunTool runs a single tool and returns parsed findings.
// When tool.OutputFile is set, a temp file is created for the tool to write its
// output to (kept on disk for later review). Otherwise stdout is used.
func (r *Runner) RunTool(ctx context.Context, name string, tool config.ToolConfig, repoPath string) ([]RawFinding, error) {
	var outputPath string

	// Create temp output file if the tool is configured to write to one.
	if tool.OutputFile != "" {
		f, err := os.CreateTemp("", fmt.Sprintf("sast-%s-*.sarif", name))
		if err != nil {
			return nil, fmt.Errorf("tool %s: create temp output file: %w", name, err)
		}
		outputPath = f.Name()
		f.Close()
	}

	// Build args, expanding {{output}} placeholder if present.
	args := make([]string, 0, len(tool.Args)+1)
	for _, arg := range tool.Args {
		if outputPath != "" {
			arg = strings.ReplaceAll(arg, "{{output}}", outputPath)
		}
		args = append(args, arg)
	}
	args = append(args, repoPath)

	startTime := time.Now()

	result, err := toolexec.Run(ctx, tool.Command, args...)
	elapsed := time.Since(startTime)

	// Context cancellation returns nil result.
	if result == nil {
		return nil, fmt.Errorf("tool %s failed: %w", name, err)
	}

	zap.L().Debug("Third-party tool finished",
		zap.String("tool", name),
		zap.Duration("elapsed", elapsed),
		zap.Int("exit_code", result.ExitCode),
		zap.Int("stdout_bytes", len(result.Stdout)))

	if err != nil {
		return nil, fmt.Errorf("tool %s failed: %w (stderr: %s)", name, err, string(result.Stderr))
	}

	// Read output from file when configured, otherwise fall back to stdout.
	if outputPath != "" {
		zap.L().Debug("Third-party tool output file",
			zap.String("tool", name),
			zap.String("output_file", outputPath))

		data, readErr := os.ReadFile(outputPath)
		if readErr != nil {
			return nil, fmt.Errorf("tool %s: read output file: %w", name, readErr)
		}
		if len(data) == 0 {
			return nil, nil
		}
		return parseToolOutput(name, data)
	}

	if len(result.Stdout) == 0 {
		return nil, nil
	}

	return parseToolOutput(name, result.Stdout)
}

// RunMultiStepTool runs a tool with multiple execution steps (e.g. CodeQL).
// It creates temp directories for intermediate artifacts (cleaned up after)
// and a temp output file (kept on disk for later review).
func (r *Runner) RunMultiStepTool(ctx context.Context, name string, tool config.ToolConfig, repoPath string) ([]RawFinding, error) {
	dbDir, err := os.MkdirTemp("", fmt.Sprintf("sast-%s-db-*", name))
	if err != nil {
		return nil, fmt.Errorf("failed to create temp db dir: %w", err)
	}
	defer os.RemoveAll(dbDir)

	outputFile, err := os.CreateTemp("", fmt.Sprintf("sast-%s-*.sarif", name))
	if err != nil {
		return nil, fmt.Errorf("failed to create temp output file: %w", err)
	}
	outputPath := outputFile.Name()
	outputFile.Close()

	language := tool.Language
	if language == "" || strings.EqualFold(language, "auto") {
		detected := DetectRepoLanguage(repoPath)
		zap.L().Debug("Auto-detected repo language",
			zap.String("tool", name),
			zap.String("language", detected),
			zap.String("repo", repoPath))
		language = detected
	}

	vars := map[string]string{
		"{{repo}}":     repoPath,
		"{{db}}":       dbDir,
		"{{output}}":   outputPath,
		"{{language}}": language,
	}

	startTime := time.Now()

	var lastOutputFile string
	for i, step := range tool.Steps {
		expandedArgs := expandPlaceholders(step.Args, vars)

		result, err := toolexec.Run(ctx, tool.Command, expandedArgs...)
		if result == nil {
			return nil, fmt.Errorf("tool %s step %d failed: %w", name, i+1, err)
		}
		if err != nil {
			return nil, fmt.Errorf("tool %s step %d failed: %w (stderr: %s)", name, i+1, err, string(result.Stderr))
		}

		if step.OutputFile != "" {
			lastOutputFile = expandPlaceholders([]string{step.OutputFile}, vars)[0]
		}
	}

	elapsed := time.Since(startTime)
	zap.L().Debug("Third-party multi-step tool finished",
		zap.String("tool", name),
		zap.Duration("elapsed", elapsed),
		zap.String("output_file", lastOutputFile))

	if lastOutputFile == "" {
		return nil, nil
	}

	data, err := os.ReadFile(lastOutputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read output from %s: %w", name, err)
	}

	if len(data) == 0 {
		return nil, nil
	}

	return parseToolOutput(name, data)
}

// expandPlaceholders replaces placeholder strings in args with values from vars.
func expandPlaceholders(args []string, vars map[string]string) []string {
	expanded := make([]string, len(args))
	for i, arg := range args {
		expanded[i] = arg
		for placeholder, value := range vars {
			expanded[i] = strings.ReplaceAll(expanded[i], placeholder, value)
		}
	}
	return expanded
}

// parseToolOutput dispatches to the appropriate parser based on tool name.
// It first checks if the output is SARIF format and routes accordingly,
// falling back to tool-specific JSON parsers for backward compatibility.
func parseToolOutput(toolName string, data []byte) ([]RawFinding, error) {
	if isSARIF(data) {
		return ParseSARIF(data, toolName)
	}

	switch toolName {
	case "semgrep":
		return ParseSemgrepOutput(data)
	case "trivy":
		return ParseTrivyOutput(data)
	default:
		return ParseGenericJSON(data, toolName)
	}
}

// codeqlExtensions maps file extensions to CodeQL language identifiers.
// CodeQL supports: javascript, python, java, csharp, cpp, go, ruby, swift, kotlin.
var codeqlExtensions = map[string]string{
	".js":   "javascript",
	".jsx":  "javascript",
	".ts":   "javascript",
	".tsx":  "javascript",
	".mjs":  "javascript",
	".cjs":  "javascript",
	".py":   "python",
	".pyw":  "python",
	".java": "java",
	".cs":   "csharp",
	".c":    "cpp",
	".cc":   "cpp",
	".cpp":  "cpp",
	".cxx":  "cpp",
	".h":    "cpp",
	".hpp":  "cpp",
	".go":   "go",
	".rb":   "ruby",
	".erb":  "ruby",
	".swift": "swift",
	".kt":   "kotlin",
	".kts":  "kotlin",
}

// DetectRepoLanguage walks the repo directory and returns the most common
// CodeQL-supported language based on file extension counts. Falls back to
// "javascript" if no supported files are found.
func DetectRepoLanguage(repoPath string) string {
	counts := make(map[string]int)
	_ = filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			base := d.Name()
			// Skip common non-source directories
			if base == "node_modules" || base == ".git" || base == "vendor" || base == "__pycache__" || base == ".venv" || base == "venv" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if lang, ok := codeqlExtensions[ext]; ok {
			counts[lang]++
		}
		return nil
	})

	if len(counts) == 0 {
		return "javascript"
	}

	var best string
	var bestCount int
	for lang, count := range counts {
		if count > bestCount {
			best = lang
			bestCount = count
		}
	}
	return best
}

// isSARIF performs a fast byte-level check to detect SARIF format output.
// It looks for a "$schema" field containing "sarif", or the structural
// presence of both "version" and "runs" keys in a JSON object.
func isSARIF(data []byte) bool {
	// Quick check: must be a JSON object.
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false
	}

	// Fast path: look for "$schema" containing "sarif".
	if bytes.Contains(data, []byte(`"$schema"`)) && bytes.Contains(data, []byte("sarif")) {
		return true
	}

	// Structural probe: parse top-level keys only.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	_, hasVersion := probe["version"]
	_, hasRuns := probe["runs"]
	return hasVersion && hasRuns
}
