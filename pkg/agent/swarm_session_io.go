package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/pkg/authentication"
	"github.com/vigolium/vigolium/pkg/httpmsg"

	"go.uber.org/zap"
)

// writeExtensionsToDir writes extensions to the session dir if available, otherwise to a temp dir.
func writeExtensionsToDir(extensions []GeneratedExtension, sessionDir string) (string, error) {
	if sessionDir != "" {
		return WriteExtensionsToSessionDir(extensions, sessionDir)
	}
	return WriteExtensionsToTempDir(extensions, "vigolium-swarm-ext-*")
}

// writeSessionConfigToDir writes session config JSON to the session directory.
func writeSessionConfigToDir(cfg *AgentSessionConfig, sessionDir string) {
	if sessionDir == "" {
		return
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		zap.L().Warn("Failed to marshal session config", zap.Error(err))
		return
	}
	path := filepath.Join(sessionDir, "session-config.json")
	if writeErr := os.WriteFile(path, data, 0644); writeErr != nil {
		zap.L().Warn("Failed to write session config", zap.Error(writeErr))
		return
	}
	zap.L().Info("Session config written", zap.String("path", path))
}

// writeSourceExtensionsToSessionDir writes source-analysis/SAST-review generated extensions
// to the session directory immediately when discovered. This ensures extensions are
// preserved as artifacts even if subsequent phases fail. The extensions/ subdirectory
// is used, matching the same location that the final merged extensions are written to.
func writeSourceExtensionsToSessionDir(extensions []GeneratedExtension, sessionDir string) {
	if len(extensions) == 0 || sessionDir == "" {
		return
	}
	extDir := filepath.Join(sessionDir, "extensions")
	if err := os.MkdirAll(extDir, 0755); err != nil {
		zap.L().Warn("Failed to create extensions dir for source extensions", zap.Error(err))
		return
	}
	for i, ext := range extensions {
		filename := sanitizeExtensionFilename(ext.Filename, i)
		path := filepath.Join(extDir, filename)
		if writeErr := os.WriteFile(path, []byte(ext.Code), 0644); writeErr != nil {
			zap.L().Warn("Failed to write source extension",
				zap.String("filename", filename),
				zap.Error(writeErr))
			continue
		}
		zap.L().Info("Source extension written to session dir",
			zap.String("filename", filename),
			zap.String("reason", ext.Reason))
	}
}

// writePromptToSessionDir saves a rendered prompt to the session directory.
func writePromptToSessionDir(sessionDir, filename, prompt string) {
	if sessionDir == "" || prompt == "" {
		return
	}
	path := filepath.Join(sessionDir, filename)
	if err := os.WriteFile(path, []byte(prompt), 0644); err != nil {
		zap.L().Warn("Failed to write prompt to session dir",
			zap.String("filename", filename), zap.Error(err))
		return
	}
	zap.L().Debug("Prompt written to session dir", zap.String("path", path))
}

// writeInputsToSessionDir saves the normalized input records and source path as JSON to the session directory.
func writeInputsToSessionDir(sessionDir string, records []*httpmsg.HttpRequestResponse, sourcePath string) {
	if sessionDir == "" || (len(records) == 0 && sourcePath == "") {
		return
	}
	type inputRecord struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers,omitempty"`
		Body    string            `json:"body,omitempty"`
	}
	type inputsFile struct {
		SourcePath string        `json:"source_path,omitempty"`
		Records    []inputRecord `json:"records"`
	}
	var inputRecords []inputRecord
	for _, rr := range records {
		ir := inputRecord{}
		if rr.Request() != nil {
			ir.Method = rr.Request().Method()
			if u, err := rr.URL(); err == nil {
				ir.URL = u.String()
			}
			ir.Headers = make(map[string]string)
			for _, h := range rr.Request().Headers() {
				ir.Headers[h.Name] = h.Value
			}
			if body := rr.Request().Body(); len(body) > 0 {
				ir.Body = string(body)
			}
		}
		inputRecords = append(inputRecords, ir)
	}
	out := inputsFile{
		SourcePath: sourcePath,
		Records:    inputRecords,
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		zap.L().Warn("Failed to marshal inputs", zap.Error(err))
		return
	}
	path := filepath.Join(sessionDir, "inputs.json")
	if writeErr := os.WriteFile(path, data, 0644); writeErr != nil {
		zap.L().Warn("Failed to write inputs to session dir", zap.Error(writeErr))
		return
	}
	zap.L().Debug("Inputs written to session dir", zap.String("path", path), zap.Int("count", len(inputRecords)))
}

// ExtensionMergeResult holds the merged extensions plus any rename tracking info.
type ExtensionMergeResult struct {
	Extensions []GeneratedExtension
	Renames    map[string]string // original filename -> renamed filename
}

// mergeExtensionsTracked combines source-analysis and plan extensions by filename,
// tracking any renames that occur during collision resolution.
// On collision with identical code, the duplicate is dropped.
// On collision with different code, the plan extension is renamed with a -2, -3 suffix.
func mergeExtensionsTracked(source, plan []GeneratedExtension) ExtensionMergeResult {
	renames := make(map[string]string)
	if len(source) == 0 {
		return ExtensionMergeResult{Extensions: plan, Renames: renames}
	}
	if len(plan) == 0 {
		return ExtensionMergeResult{Extensions: source, Renames: renames}
	}

	existing := make(map[string]string, len(source)) // filename -> code
	nameSet := make(map[string]bool, len(source))    // maintained for deduplicateExtensionFilename
	result := make([]GeneratedExtension, 0, len(source)+len(plan))

	// Source extensions first
	for _, ext := range source {
		existing[ext.Filename] = ext.Code
		nameSet[ext.Filename] = true
		result = append(result, ext)
	}

	// Plan extensions: rename on collision with different code, skip on identical code
	for _, ext := range plan {
		if existingCode, collision := existing[ext.Filename]; collision {
			if existingCode == ext.Code {
				zap.L().Info("Skipping duplicate extension (same content)",
					zap.String("filename", ext.Filename))
				continue
			}
			// Different code — rename to avoid losing the extension
			originalName := ext.Filename
			ext.Filename = deduplicateExtensionFilename(ext.Filename, nameSet)
			renames[originalName] = ext.Filename
			zap.L().Info("Renamed colliding extension",
				zap.String("original", originalName),
				zap.String("new_filename", ext.Filename))
		}
		existing[ext.Filename] = ext.Code
		nameSet[ext.Filename] = true
		result = append(result, ext)
	}

	return ExtensionMergeResult{Extensions: result, Renames: renames}
}

// hydrateSessionConfig executes login flows for all sessions in the agent session config,
// populates their Headers maps with extracted credentials, and returns the primary
// session's auth headers for immediate use. Mutates cfg.Sessions[].Headers in place
// so that callers (e.g. AgentSessionConfigToAuthenticationHostnames) see the hydrated values.
func hydrateSessionConfig(cfg *AgentSessionConfig) map[string]string {
	if cfg == nil || len(cfg.Sessions) == 0 {
		return nil
	}

	var primaryHeaders map[string]string

	for i := range cfg.Sessions {
		entry := &cfg.Sessions[i]

		// Prefer static headers if provided (agent may have discovered hardcoded tokens)
		if len(entry.Headers) > 0 {
			zap.L().Info("Using static auth headers from source analysis",
				zap.String("session", entry.Name),
				zap.Int("header_count", len(entry.Headers)))
			if primaryHeaders == nil {
				primaryHeaders = entry.Headers
			}
			continue
		}

		// Execute login flow to obtain real credentials
		if entry.Login == nil {
			continue
		}

		sess := &authentication.Session{
			Name: entry.Name,
			Role: authentication.Role(entry.Role),
			Login: &authentication.LoginFlow{
				URL:         entry.Login.URL,
				Method:      entry.Login.Method,
				ContentType: entry.Login.ContentType,
				Body:        entry.Login.Body,
				// Carry the type/token_path shorthand and the expect block
				// across the agent → authentication boundary. Without these,
				// configs produced by source-analysis (which prefer the
				// shorthand over an explicit extract array) hydrate to zero
				// headers because authentication.NormalizeLoginFlow has
				// nothing to expand. Mirrors AgentLoginFlow → LoginFlow.
				Type:      authentication.LoginType(entry.Login.Type),
				TokenPath: entry.Login.TokenPath,
			},
		}
		if entry.Login.Expect != nil {
			sess.Login.Expect = &authentication.ExpectResponse{
				Status:       append([]int(nil), entry.Login.Expect.Status...),
				BodyContains: entry.Login.Expect.BodyContains,
			}
		}
		for _, rule := range entry.Login.Extract {
			sess.Login.Extract = append(sess.Login.Extract, authentication.ExtractRule{
				Source:  authentication.ExtractSource(rule.Source),
				Name:    rule.Name,
				Path:    rule.Path,
				ApplyAs: rule.ApplyAs,
			})
		}

		// Use the session manager to execute the login flow
		mgr, mgrErr := authentication.NewManager([]*authentication.Session{sess})
		if mgrErr != nil {
			zap.L().Debug("Failed to create session manager for hydration",
				zap.String("session", entry.Name), zap.Error(mgrErr))
			continue
		}
		if hydErr := mgr.HydrateSessions(); hydErr != nil {
			zap.L().Debug("Failed to hydrate session from source analysis",
				zap.String("session", entry.Name), zap.Error(hydErr))
			continue
		}

		headers := mgr.PrimaryHeaders()
		if len(headers) > 0 {
			result := make(map[string]string, len(headers))
			for _, h := range headers {
				parts := strings.SplitN(h, ": ", 2)
				if len(parts) == 2 {
					result[parts[0]] = parts[1]
				}
			}
			if len(result) > 0 {
				zap.L().Info("Hydrated auth headers via login flow",
					zap.String("session", entry.Name),
					zap.Int("header_count", len(result)))
				// Store hydrated headers back on the entry for persistence
				entry.Headers = result
				if primaryHeaders == nil {
					primaryHeaders = result
				}
			}
		}
	}

	return primaryHeaders
}
