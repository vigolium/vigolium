package server

import (
	_ "embed"

	"github.com/gofiber/fiber/v3"
)

//go:embed swagger_spec.json
var swaggerSpec []byte

// HandleSwaggerSpec serves the OpenAPI specification JSON.
func (h *Handlers) HandleSwaggerSpec(c fiber.Ctx) error {
	c.Set("Content-Type", "application/json")
	return c.Send(swaggerSpec)
}
