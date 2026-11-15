package server

import (
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
		em := &h.settings.DynamicAssessment.EnabledModules
		for _, m := range activeModules {
			if em.ActiveEnabled(m.ID()) {
				resp.Modules.Active.Enabled++
			}
		}
		for _, m := range passiveModules {
			if em.PassiveEnabled(m.ID()) {
				resp.Modules.Passive.Enabled++
			}
		}
	} else {
		// No settings = all enabled
		resp.Modules.Active.Enabled = len(activeModules)
		resp.Modules.Passive.Enabled = len(passiveModules)
	}

	// Database counts (scoped to project) — request-bound read, cancels with the client.
	if h.db != nil {
		ctx := c.Context()

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
