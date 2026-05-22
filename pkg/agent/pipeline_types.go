package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/pkg/agent/parsing"
	"github.com/vigolium/vigolium/pkg/modules"
	"go.uber.org/zap"
)

// sanitizeExtensionFilename ensures a filename is safe for writing to disk.
// It strips path components to prevent traversal, converts to a URL-friendly
// slug (lowercase, alphanumeric + hyphens), and falls back to a numbered
// default for empty or dot-only names.
func sanitizeExtensionFilename(name string, index int) string {
	name = filepath.Base(name)
	if name == "" || name == "." || name == ".." {
		return fmt.Sprintf("extension-%d.js", index)
	}

	// Strip .js extension for slug processing, re-add after
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	if ext == "" {
		ext = ".js"
	}

	// Slugify: lowercase, replace non-alphanumeric with hyphens, collapse, trim
	slug := strings.ToLower(base)
	var sb strings.Builder
	prevHyphen := false
	for _, r := range slug {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
			prevHyphen = false
		} else if !prevHyphen {
			sb.WriteRune('-')
			prevHyphen = true
		}
	}
	slug = strings.Trim(sb.String(), "-")

	if slug == "" {
		return fmt.Sprintf("extension-%d.js", index)
	}
	return slug + ext
}

// WriteCheckpointToDir persists a SwarmCheckpoint to the session directory (exported for CLI use).
func WriteCheckpointToDir(sessionDir string, cp *SwarmCheckpoint) error {
	return writeCheckpoint(sessionDir, cp)
}

// writeCheckpoint persists a SwarmCheckpoint to the session directory.
func writeCheckpoint(sessionDir string, cp *SwarmCheckpoint) error {
	if sessionDir == "" {
		return nil
	}
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint: %w", err)
	}
	// Atomic write: write to temp file then rename, so a crash mid-write
	// never leaves a corrupt checkpoint that breaks resume.
	target := filepath.Join(sessionDir, "checkpoint.json")
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("failed to write checkpoint temp file: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		return fmt.Errorf("failed to rename checkpoint temp file: %w", err)
	}
	return nil
}

// loadCheckpoint reads a SwarmCheckpoint from the session directory.
func loadCheckpoint(sessionDir string) (*SwarmCheckpoint, error) {
	data, err := os.ReadFile(filepath.Join(sessionDir, "checkpoint.json"))
	if err != nil {
		return nil, err
	}
	var cp SwarmCheckpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("failed to parse checkpoint: %w", err)
	}
	return &cp, nil
}

// RepairHTTPRecordsWithLLM attempts to fix garbled HTTP records output by sending
// the raw text to the configured LLM agent with a repair prompt. The repaired output
// is re-parsed through the JSONL + garbled recovery pipeline.
func RepairHTTPRecordsWithLLM(ctx context.Context, engine *Engine, rawOutput string, cfg RepairConfig) []AgentHTTPRecord {
	if engine == nil || rawOutput == "" {
		return nil
	}

	// Truncate to 32KB to fit context
	const maxRepairBytes = 32 * 1024
	if len(rawOutput) > maxRepairBytes {
		rawOutput = rawOutput[:maxRepairBytes]
	}

	prompt := buildHTTPRecordRepairPrompt(rawOutput)

	result, err := engine.Run(ctx, Options{
		AgentName:    cfg.AgentName,
		PromptInline: prompt,
		ShowPrompt:   cfg.ShowPrompt,
	})
	if err != nil {
		zap.L().Warn("LLM repair for HTTP records failed", zap.Error(err))
		return nil
	}

	output := result.RawOutput

	// Try JSONL from ```jsonl block first
	if jsonlContent, err := parsing.ExtractJSONLFromFencedBlock(output); err == nil {
		records, _ := parsing.ParseHTTPRecordJSONL(jsonlContent)
		if len(records) > 0 {
			zap.L().Info("LLM repair recovered HTTP records via JSONL",
				zap.Int("count", len(records)))
			return records
		}
	}

	// Try standard JSON parsing
	records, parseErr := parsing.ParseHTTPRecords(output)
	if parseErr == nil && len(records) > 0 {
		zap.L().Info("LLM repair recovered HTTP records via JSON",
			zap.Int("count", len(records)))
		return records
	}

	// Try garbled recovery on the repaired output
	records, _ = parsing.ExtractRecordsFromGarbled(output)
	if len(records) > 0 {
		zap.L().Info("LLM repair recovered HTTP records via garbled extraction",
			zap.Int("count", len(records)))
		return records
	}

	zap.L().Warn("LLM repair produced no parseable HTTP records")
	return nil
}

// buildHTTPRecordRepairPrompt constructs the prompt for the HTTP record repair LLM call.
func buildHTTPRecordRepairPrompt(rawOutput string) string {
	var sb strings.Builder
	sb.WriteString("The following output was supposed to contain HTTP records (routes extracted from source code) but has JSON syntax errors.\n")
	sb.WriteString("Fix the JSON errors and return the records as JSONL (one JSON object per line) in a ```jsonl fenced code block.\n")
	sb.WriteString("Each line must be a valid JSON object like: {\"method\":\"GET\",\"url\":\"http://...\",\"headers\":{},\"body\":\"\",\"notes\":\"...\"}\n")
	sb.WriteString("Do NOT change the data — only fix syntax errors. Do NOT add explanations outside the code block.\n\n")
	sb.WriteString("## Garbled Output\n\n")
	sb.WriteString("```\n")
	sb.WriteString(rawOutput)
	sb.WriteString("\n```\n")
	return sb.String()
}

// EnsureSessionDir creates the session directory for a given run ID under the specified base directory.
// If baseDir is empty, defaults to ~/.vigolium/agent-sessions/.
// Returns the absolute path to the created directory.
func EnsureSessionDir(baseDir, agenticScanUUID string) (string, error) {
	if baseDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get home dir: %w", err)
		}
		baseDir = filepath.Join(home, ".vigolium", "agent-sessions")
	}
	dir := filepath.Join(baseDir, agenticScanUUID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create session dir: %w", err)
	}
	return dir, nil
}

// writeSessionArtifact best-effort writes a session artifact (per-phase agent
// output, plans, recon reports) for post-hoc inspection. A write failure is
// logged but never aborts the run — these files are diagnostic, not control
// flow. Centralizes the justification for the dropped write errors at the call
// sites across the agent pipeline.
func writeSessionArtifact(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		zap.L().Debug("failed to write session artifact", zap.String("path", path), zap.Error(err))
	}
}

// WriteExtensionsToSessionDir writes generated JavaScript extensions to <sessionDir>/extensions/
// and returns the extensions subdirectory path.
func WriteExtensionsToSessionDir(extensions []GeneratedExtension, sessionDir string) (string, error) {
	extDir := filepath.Join(sessionDir, "extensions")
	if err := os.MkdirAll(extDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create extensions dir: %w", err)
	}
	for i, ext := range extensions {
		filename := sanitizeExtensionFilename(ext.Filename, i)
		path := filepath.Join(extDir, filename)
		if writeErr := os.WriteFile(path, []byte(ext.Code), 0644); writeErr != nil {
			zap.L().Warn("Failed to write extension",
				zap.String("filename", ext.Filename), zap.Error(writeErr))
			continue
		}
		zap.L().Info("Generated extension",
			zap.String("filename", ext.Filename),
			zap.String("reason", ext.Reason),
			zap.String("path", path))
	}
	return extDir, nil
}

// RepairSessionConfigWithLLM attempts to fix garbled session config output by sending
// the raw text to the configured LLM agent with a repair prompt. The repaired output
// is re-parsed through parsing.ExtractSessionConfigFromGarbled().
func RepairSessionConfigWithLLM(ctx context.Context, engine *Engine, rawOutput string, cfg RepairConfig) *AgentSessionConfig {
	if engine == nil || rawOutput == "" {
		return nil
	}

	// Truncate to 32KB to fit context
	const maxRepairBytes = 32 * 1024
	if len(rawOutput) > maxRepairBytes {
		rawOutput = rawOutput[:maxRepairBytes]
	}

	prompt := buildSessionConfigRepairPrompt(rawOutput)

	result, err := engine.Run(ctx, Options{
		AgentName:    cfg.AgentName,
		PromptInline: prompt,
		ShowPrompt:   cfg.ShowPrompt,
	})
	if err != nil {
		zap.L().Warn("LLM repair for session config failed", zap.Error(err))
		return nil
	}

	repaired := parsing.ExtractSessionConfigFromGarbled(result.RawOutput)
	if repaired != nil && len(repaired.Sessions) > 0 {
		zap.L().Info("LLM repair recovered session config",
			zap.Int("sessions", len(repaired.Sessions)))
		return repaired
	}

	zap.L().Warn("LLM repair produced no parseable session config")
	return nil
}

// buildSessionConfigRepairPrompt constructs the prompt for the session config repair LLM call.
func buildSessionConfigRepairPrompt(rawOutput string) string {
	var sb strings.Builder
	sb.WriteString("The following output was supposed to contain session configuration for authenticated scanning but has JSON syntax errors.\n")
	sb.WriteString("Fix the JSON errors and return a valid JSON object in a ```json fenced code block.\n")
	sb.WriteString("Do NOT change the data — only fix syntax errors. Do NOT add explanations outside the code block.\n\n")
	sb.WriteString("## Expected Schema\n\n")
	sb.WriteString("```json\n")
	sb.WriteString(`{
  "sessions": [
    {
      "name": "session-name",
      "role": "primary",
      "login": {
        "url": "http://example.com/api/login",
        "method": "POST",
        "content_type": "application/json",
        "body": "{\"username\":\"admin\",\"password\":\"admin\"}",
        "extract": [
          {
            "source": "json",
            "path": "$.token",
            "apply_as": "Authorization: Bearer {value}"
          }
        ]
      }
    }
  ]
}`)
	sb.WriteString("\n```\n\n")
	sb.WriteString("CRITICAL: The `extract` rules are essential — they define how auth tokens are extracted from login responses. Do NOT omit them.\n\n")
	sb.WriteString("## Garbled Output\n\n")
	sb.WriteString("```\n")
	sb.WriteString(rawOutput)
	sb.WriteString("\n```\n")
	return sb.String()
}

// ResolveModulesFromPlan converts agent-suggested tags and IDs into a deduplicated
// module ID list. Falls back to ["all"] when no modules are resolved.
func ResolveModulesFromPlan(tags []string, ids []string) []string {
	moduleSet := make(map[string]bool)

	if len(tags) > 0 {
		resolved := modules.ResolveModuleTags(tags)
		for _, id := range resolved {
			moduleSet[id] = true
		}
	}

	for _, id := range ids {
		moduleSet[id] = true
	}

	if len(moduleSet) == 0 {
		return []string{"all"}
	}

	result := make([]string, 0, len(moduleSet))
	for id := range moduleSet {
		result = append(result, id)
	}
	return result
}

// WriteExtensionsToTempDir writes generated JavaScript extensions to a temporary
// directory and returns the directory path. Caller is responsible for cleanup.
func WriteExtensionsToTempDir(extensions []GeneratedExtension, prefix string) (string, error) {
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	for i, ext := range extensions {
		filename := sanitizeExtensionFilename(ext.Filename, i)
		path := filepath.Join(dir, filename)
		if writeErr := os.WriteFile(path, []byte(ext.Code), 0644); writeErr != nil {
			zap.L().Warn("Failed to write extension",
				zap.String("filename", ext.Filename),
				zap.Error(writeErr))
			continue
		}
		zap.L().Info("Generated extension",
			zap.String("filename", ext.Filename),
			zap.String("reason", ext.Reason))
	}

	return dir, nil
}
