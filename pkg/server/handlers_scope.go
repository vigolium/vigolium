package server

import (
	"encoding/json"
	"fmt"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/internal/config"
	"go.uber.org/zap"
)

// HandleGetScope handles GET /api/scope — returns the current scope config.
func (h *Handlers) HandleGetScope(c fiber.Ctx) error {
	if h.settings == nil {
		return c.JSON(config.DefaultScopeConfig())
	}
	return c.JSON(h.settings.Scope)
}

// HandleUpdateScope handles POST /api/scope — updates the scope config.
func (h *Handlers) HandleUpdateScope(c fiber.Ctx) error {
	if h.settings == nil {
		return respondErrorMsg(c, fiber.StatusInternalServerError, "settings not available")
	}

	var incoming config.ScopeConfig
	if err := c.Bind().JSON(&incoming); err != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
	}

	// Merge: only overwrite fields that have non-empty Include or Exclude
	// slices. Each overwritten list is also recorded as an in-place edit of
	// the raw config file, so the file keeps its comments and ${VAR}
	// placeholders (h.settings holds expanded values and must never be
	// marshalled back over it).
	current := &h.settings.Scope
	var edits []config.RawEdit
	for _, r := range []struct {
		name     string
		dst, src *config.ScopeRule
	}{
		{"host", &current.Host, &incoming.Host},
		{"path", &current.Path, &incoming.Path},
		{"status_code", &current.StatusCode, &incoming.StatusCode},
		{"request_content_type", &current.RequestContentType, &incoming.RequestContentType},
		{"response_content_type", &current.ResponseContentType, &incoming.ResponseContentType},
		{"request_string", &current.RequestString, &incoming.RequestString},
		{"response_string", &current.ResponseString, &incoming.ResponseString},
	} {
		if r.src.Include != nil {
			edits = append(edits, config.SetPathEdit("scope."+r.name+".include", r.src.Include))
		}
		if r.src.Exclude != nil {
			edits = append(edits, config.SetPathEdit("scope."+r.name+".exclude", r.src.Exclude))
		}
		mergeScopeRule(r.dst, r.src)
	}

	// Handle applied_on_ingest: only update if explicitly present in JSON body
	var rawBody map[string]json.RawMessage
	if err := json.Unmarshal(c.Body(), &rawBody); err == nil {
		if _, exists := rawBody["applied_on_ingest"]; exists {
			current.AppliedOnIngest = incoming.AppliedOnIngest
			edits = append(edits, config.SetPathEdit("scope.applied_on_ingest", incoming.AppliedOnIngest))
		}
	}

	// Mark self-write to prevent watcher from triggering a redundant reload
	if h.configWatcher != nil {
		h.configWatcher.MarkSelfWrite()
	}

	// Persist to disk
	if _, err := config.EditConfigFile(h.effectiveConfigPath(), edits...); err != nil {
		zap.L().Error("Failed to save scope config", zap.Error(err))
		return respondErrorMsg(c, fiber.StatusInternalServerError, "failed to save config", err.Error())
	}

	// Invalidate cached scope matcher (MarkSelfWrite suppresses the watcher callback)
	h.resetScopeMatcher()

	return c.JSON(ScopeUpdateResponse{
		Message: "Scope updated successfully",
		Scope:   h.settings.Scope,
	})
}

// mergeScopeRule overwrites dst with src if src has non-nil slices.
func mergeScopeRule(dst, src *config.ScopeRule) {
	if src.Include != nil {
		dst.Include = src.Include
	}
	if src.Exclude != nil {
		dst.Exclude = src.Exclude
	}
}
