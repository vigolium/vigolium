package server

import (
	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/diagnostics"
)

// HandleDiagnostics handles GET /api/diagnostics — returns a system readiness report.
func (h *Handlers) HandleDiagnostics(c fiber.Ctx) error {
	deps := diagnostics.Deps{
		DB:       h.db,
		Queue:    h.queue,
		Settings: h.settings,
	}
	return c.JSON(diagnostics.Run(deps))
}
