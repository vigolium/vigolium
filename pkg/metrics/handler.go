package metrics

import (
	"bytes"

	"github.com/gofiber/fiber/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

const promContentType = "text/plain; version=0.0.4; charset=utf-8"

// NewFiberHandler returns a Fiber handler that serves Prometheus metrics.
// Fiber v3 uses fasthttp, so we cannot use promhttp.Handler() directly.
func NewFiberHandler(registry *prometheus.Registry) fiber.Handler {
	return func(c fiber.Ctx) error {
		mfs, err := registry.Gather()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
		}

		var buf bytes.Buffer
		enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
		for _, mf := range mfs {
			if err := enc.Encode(mf); err != nil {
				return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
			}
		}

		c.Set("Content-Type", promContentType)
		return c.Send(buf.Bytes())
	}
}
