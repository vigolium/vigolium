package server

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/internal/config"
	"go.uber.org/zap"
)

// HandleGetConfig handles GET /api/config — returns flattened config entries.
// Query params:
//   - filter: substring match on key (optional)
//   - show_sensitive: "true" to show unredacted sensitive values (admin only;
//     ignored for other roles and on --view-only servers)
func (h *Handlers) HandleGetConfig(c fiber.Ctx) error {
	if h.settings == nil {
		return respondErrorMsg(c, fiber.StatusInternalServerError, "settings not available")
	}

	filter := c.Query("filter")
	// Unmasking is admin-only. This route is viewer-readable and stays
	// registered under --view-only, and the flattened config includes the
	// server's own admin API key, so honouring the flag for every role would
	// let a read-only token escalate. A nil user means auth is disabled
	// (--no-auth), where there are no roles to enforce, except that a
	// --view-only server never unmasks: it is the read-only face of an
	// instance, often run without auth precisely so others can look at it.
	showSensitive := c.Query("show_sensitive") == "true"
	if user := getAuthUser(c); user != nil && user.Role != RoleAdmin {
		showSensitive = false
	}
	if h.config.ViewOnly {
		showSensitive = false
	}

	entries := config.FlattenSettings(h.settings)

	// Sort by key
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Key < entries[j].Key
	})

	// Filter and build response
	var result []ConfigEntryResponse
	for _, e := range entries {
		if filter != "" && !strings.Contains(e.Key, filter) {
			continue
		}

		value := e.Value
		if e.Sensitive && !showSensitive && value != "" {
			value = "********"
		}

		result = append(result, ConfigEntryResponse{
			Key:       e.Key,
			Value:     value,
			Sensitive: e.Sensitive,
		})
	}

	if result == nil {
		result = []ConfigEntryResponse{}
	}

	return respondBespokeList(c, ConfigListResponse{
		Entries: result,
		Total:   len(result),
	}, PaginatedResponse{Data: result, Total: int64(len(result))}, nil)
}

// HandleUpdateConfig handles POST /api/config — updates multiple config values.
// Accepts JSON body: {"dot.key1": "value1", "dot.key2": "value2"}
func (h *Handlers) HandleUpdateConfig(c fiber.Ctx) error {
	if h.settings == nil {
		return respondErrorMsg(c, fiber.StatusInternalServerError, "settings not available")
	}

	var req ConfigUpdateRequest
	if err := c.Bind().JSON(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
	}

	if len(req) == 0 {
		return respondErrorMsg(c, fiber.StatusBadRequest, "request body must contain at least one key-value pair")
	}

	var updated []ConfigEntryResponse
	var errors []string

	for key, value := range req {
		if err := config.SetField(h.settings, key, value); err != nil {
			errors = append(errors, key+": "+err.Error())
			continue
		}
		updated = append(updated, ConfigEntryResponse{
			Key:   key,
			Value: value,
		})
	}

	// Sort updated entries for deterministic output
	sort.Slice(updated, func(i, j int) bool {
		return updated[i].Key < updated[j].Key
	})

	// Persist to disk
	if len(updated) > 0 {
		if h.configWatcher != nil {
			h.configWatcher.MarkSelfWrite()
		}
		if err := config.SaveSettings(h.effectiveConfigPath(), h.settings); err != nil {
			zap.L().Error("Failed to save config", zap.Error(err))
			return respondErrorMsg(c, fiber.StatusInternalServerError, "failed to save config", err.Error())
		}
	}

	msg := "Config updated successfully"
	status := fiber.StatusOK
	if len(errors) > 0 && len(updated) > 0 {
		msg = "Config partially updated"
	} else if len(errors) > 0 {
		msg = "Config update failed"
		status = fiber.StatusBadRequest
	}

	return c.Status(status).JSON(ConfigUpdateResponse{
		Message: msg,
		Updated: updated,
		Errors:  errors,
	})
}
