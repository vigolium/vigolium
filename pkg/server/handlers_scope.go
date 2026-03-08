package server

import (
	"encoding/json"

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
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "settings not available",
			Code:  fiber.StatusInternalServerError,
		})
	}

	var incoming config.ScopeConfig
	if err := c.Bind().JSON(&incoming); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid JSON: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	// Merge: only overwrite fields that have non-empty Include or Exclude slices
	current := &h.settings.Scope
	mergeScopeRule(&current.Host, &incoming.Host)
	mergeScopeRule(&current.Path, &incoming.Path)
	mergeScopeRule(&current.StatusCode, &incoming.StatusCode)
	mergeScopeRule(&current.RequestContentType, &incoming.RequestContentType)
	mergeScopeRule(&current.ResponseContentType, &incoming.ResponseContentType)
	mergeScopeRule(&current.RequestString, &incoming.RequestString)
	mergeScopeRule(&current.ResponseString, &incoming.ResponseString)

	// Handle applied_on_ingest: only update if explicitly present in JSON body
	var rawBody map[string]json.RawMessage
	if err := json.Unmarshal(c.Body(), &rawBody); err == nil {
		if _, exists := rawBody["applied_on_ingest"]; exists {
			current.AppliedOnIngest = incoming.AppliedOnIngest
		}
	}

	// Mark self-write to prevent watcher from triggering a redundant reload
	if h.configWatcher != nil {
		h.configWatcher.MarkSelfWrite()
	}

	// Persist to disk
	if err := config.SaveSettings(config.ConfigFilePath(), h.settings); err != nil {
		zap.L().Error("Failed to save scope config", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:   "failed to save config",
			Code:    fiber.StatusInternalServerError,
			Details: err.Error(),
		})
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
