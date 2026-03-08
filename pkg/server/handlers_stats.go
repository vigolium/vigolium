package server

import (
	"context"
	"slices"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
)

// HandleStats handles GET /api/stats — returns aggregated scan statistics.
func (h *Handlers) HandleStats(c fiber.Ctx) error {
	projectUUID := getProjectUUID(c)
	resp := StatsResponse{
		ProjectUUID: projectUUID,
		Findings: FindingStats{
			BySeverity: make(map[string]int64),
		},
	}

	// Module counts
	activeModules := modules.GetActiveModules()
	passiveModules := modules.GetPassiveModules()
	resp.Modules.Active.Total = len(activeModules)
	resp.Modules.Passive.Total = len(passiveModules)

	// Determine enabled counts from settings
	if h.settings != nil {
		resp.Modules.Active.Enabled = countEnabledModules(
			h.settings.DynamicAssessment.EnabledModules.ActiveModules,
			len(activeModules),
		)
		resp.Modules.Passive.Enabled = countEnabledModules(
			h.settings.DynamicAssessment.EnabledModules.PassiveModules,
			len(passiveModules),
		)
	} else {
		// No settings = all enabled
		resp.Modules.Active.Enabled = len(activeModules)
		resp.Modules.Passive.Enabled = len(passiveModules)
	}

	// Database counts (scoped to project)
	if h.db != nil {
		ctx := context.Background()

		recordQ := h.db.NewSelect().Model((*database.HTTPRecord)(nil))
		if projectUUID != "" {
			recordQ = recordQ.Where("project_uuid = ?", projectUUID)
		}
		recordCount, err := recordQ.Count(ctx)
		if err == nil {
			resp.HTTPRecords.Total = int64(recordCount)
		}

		findingQ := h.db.NewSelect().Model((*database.Finding)(nil))
		if projectUUID != "" {
			findingQ = findingQ.Where("project_uuid = ?", projectUUID)
		}
		findingCount, err := findingQ.Count(ctx)
		if err == nil {
			resp.Findings.Total = int64(findingCount)
		}

		bySeverity, err := database.CountFindingsBySeverity(ctx, h.db, projectUUID)
		if err == nil {
			resp.Findings.BySeverity = bySeverity
		}
	}

	return c.JSON(resp)
}

// countEnabledModules returns the number of enabled modules.
// If the config list contains "all", all modules are enabled.
func countEnabledModules(configured []string, total int) int {
	if slices.Contains(configured, "all") {
		return total
	}
	return len(configured)
}
