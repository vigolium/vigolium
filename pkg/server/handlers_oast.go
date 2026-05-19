package server

import (
	"database/sql"
	"errors"
	"strconv"

	"github.com/gofiber/fiber/v3"
)

// HandleListOASTInteractions handles GET /api/oast-interactions
func (h *Handlers) HandleListOASTInteractions(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	scanUUID := c.Query("scan_uuid")
	protocol := c.Query("protocol")
	moduleID := c.Query("module_id")
	search := c.Query("search")

	limit := 50
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	if limit > 500 {
		limit = 500
	}

	offset := 0
	if o := c.Query("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}

	projectUUID := getProjectUUID(c)
	interactions, total, err := h.repo.ListOASTInteractions(c.Context(), projectUUID, scanUUID, protocol, moduleID, search, limit, offset)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "query failed: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(PaginatedResponse{
		ProjectUUID: projectUUID,
		Data:        interactions,
		Total:       total,
		Limit:       limit,
		Offset:      offset,
		HasMore:     int64(offset+limit) < total,
	})
}

// HandleGetOASTInteraction handles GET /api/oast-interactions/:id
func (h *Handlers) HandleGetOASTInteraction(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	idStr := c.Params("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid OAST interaction ID: must be a number",
			Code:  fiber.StatusBadRequest,
		})
	}

	interaction, err := h.repo.GetOASTInteractionByID(c.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
				Error: ErrOASTInteractionNotFound.Error(),
				Code:  fiber.StatusNotFound,
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to retrieve OAST interaction: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(interaction)
}

// HandleDeleteOASTInteraction handles DELETE /api/oast-interactions/:id
func (h *Handlers) HandleDeleteOASTInteraction(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	idStr := c.Params("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid OAST interaction ID: must be a number",
			Code:  fiber.StatusBadRequest,
		})
	}

	// Verify it exists first
	if _, err := h.repo.GetOASTInteractionByID(c.Context(), id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
				Error: ErrOASTInteractionNotFound.Error(),
				Code:  fiber.StatusNotFound,
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to retrieve OAST interaction: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	if err := h.repo.DeleteOASTInteraction(c.Context(), id); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to delete OAST interaction: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(fiber.Map{"message": "OAST interaction deleted", "id": id})
}
