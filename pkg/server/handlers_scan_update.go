package server

import (
	"database/sql"
	"errors"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/vigolium/vigolium/pkg/database"
)

// HandleUpdateScan handles POST /api/scans/:uuid/update — partially updates an
// existing native scan record. Fields omitted from the body are left unchanged.
// Immutable fields (uuid, project_uuid, created_at) are ignored if present in
// the request body — the UUID is taken from the path, and project ownership is
// validated against X-Project-UUID before the write.
func (h *Handlers) HandleUpdateScan(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	scanUUID := c.Params("uuid")
	if scanUUID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "missing uuid parameter",
			Code:  fiber.StatusBadRequest,
		})
	}

	projectUUID := getProjectUUID(c)
	existing, err := h.repo.GetScanByUUID(c.Context(), scanUUID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
				Error: ErrScanNotFound.Error(),
				Code:  fiber.StatusNotFound,
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to retrieve scan: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}
	// Hide cross-project existence: return 404 rather than 403.
	if existing.ProjectUUID != projectUUID {
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: ErrScanNotFound.Error(),
			Code:  fiber.StatusNotFound,
		})
	}

	var patch database.Scan
	if err := c.Bind().JSON(&patch); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid request body: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	// Strip immutable creation metadata, then bind the PK from the path.
	patch.ProjectUUID = ""
	patch.CreatedAt = time.Time{}
	patch.UUID = scanUUID
	// Stamp UpdatedAt so the row reflects the write — OmitZero would otherwise
	// skip it (the JSON body usually doesn't include updated_at).
	patch.UpdatedAt = time.Now().UTC()

	if err := h.repo.UpdateScanPartial(c.Context(), &patch); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to update scan: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	updated, err := h.repo.GetScanByUUID(c.Context(), scanUUID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to retrieve updated scan: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}
	return c.JSON(updated)
}

// HandleUpdateAgenticScan handles POST /api/agent/scans/:uuid/update —
// partially updates an existing agentic scan record. Fields omitted from the
// body are left unchanged. Immutable fields (id, uuid, project_uuid,
// created_at) are ignored if present in the request body.
func (h *Handlers) HandleUpdateAgenticScan(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	scanUUID := c.Params("uuid")
	if scanUUID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "missing uuid parameter",
			Code:  fiber.StatusBadRequest,
		})
	}

	projectUUID := getProjectUUID(c)
	existing, err := h.repo.GetAgenticScan(c.Context(), scanUUID)
	if err != nil {
		// GetAgenticScan wraps sql.ErrNoRows; treat any error as not-found
		// rather than 500 since the repo doesn't surface a richer signal.
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: ErrAgentNotFound.Error(),
			Code:  fiber.StatusNotFound,
		})
	}
	if existing.ProjectUUID != projectUUID {
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: ErrAgentNotFound.Error(),
			Code:  fiber.StatusNotFound,
		})
	}

	var patch database.AgenticScan
	if err := c.Bind().JSON(&patch); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid request body: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	// Strip immutable creation metadata. ID is an autoincrement PK with a
	// distinct UUID lookup key — keeping ID zero ensures OmitZero skips it.
	patch.ID = 0
	patch.ProjectUUID = ""
	patch.CreatedAt = time.Time{}
	patch.UUID = scanUUID

	if err := h.repo.UpdateAgenticScan(c.Context(), &patch); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to update agentic scan: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	updated, err := h.repo.GetAgenticScan(c.Context(), scanUUID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to retrieve updated agentic scan: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}
	return c.JSON(updated)
}
