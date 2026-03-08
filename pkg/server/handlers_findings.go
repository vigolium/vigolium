package server

import (
	"database/sql"
	"errors"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
)

// HandleListFindings handles GET /api/findings
func (h *Handlers) HandleListFindings(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	projectUUID := getProjectUUID(c)
	filters := database.QueryFilters{
		ProjectUUID: projectUUID,
	}

	// Domain (join http_records)
	if domain := c.Query("domain"); domain != "" {
		filters.HostPattern = domain
	}

	// Severity (comma-separated)
	if sev := c.Query("severity"); sev != "" {
		for _, s := range strings.Split(sev, ",") {
			s = strings.TrimSpace(strings.ToLower(s))
			if s != "" {
				filters.Severity = append(filters.Severity, s)
			}
		}
	}

	// Scan ID
	if scanID := c.Query("scan_id"); scanID != "" {
		filters.ScanUUID = scanID
	}

	// Module name
	if mn := c.Query("module_name"); mn != "" {
		filters.ModuleName = mn
	}

	// Module type
	if mt := c.Query("module_type"); mt != "" {
		filters.ModuleType = mt
	}

	// Finding source
	if fs := c.Query("finding_source"); fs != "" {
		filters.FindingSource = fs
	}

	// Search
	if s := c.Query("search"); s != "" {
		filters.SearchTerm = s
	}

	// Sorting
	if sort := c.Query("sort"); sort != "" {
		filters.SortBy = sort
	}
	if order := c.Query("order"); strings.EqualFold(order, "asc") {
		filters.SortAsc = true
	}

	// Pagination
	limit := 50
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	if limit > 500 {
		limit = 500
	}
	filters.Limit = limit

	if o := c.Query("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			filters.Offset = v
		}
	}

	fqb := database.NewFindingsQueryBuilder(h.db, filters)
	ctx := c.Context()

	findings, err := fqb.Execute(ctx)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "query failed: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	total, _ := fqb.Count(ctx)

	return c.JSON(PaginatedResponse{
		ProjectUUID: projectUUID,
		Data:        findings,
		Total:       total,
		Limit:       filters.Limit,
		Offset:      filters.Offset,
		HasMore:     int64(filters.Offset+filters.Limit) < total,
	})
}

// HandleDeleteFinding handles DELETE /api/findings/:id — deletes a single finding by numeric ID.
func (h *Handlers) HandleDeleteFinding(c fiber.Ctx) error {
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
			Error: "invalid finding ID: must be a number",
			Code:  fiber.StatusBadRequest,
		})
	}

	// Verify the finding exists
	if _, err := h.repo.GetFindingByID(c.Context(), id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
				Error: ErrFindingNotFound.Error(),
				Code:  fiber.StatusNotFound,
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to retrieve finding: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	if err := h.repo.DeleteFinding(c.Context(), id); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to delete finding: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(fiber.Map{
		"message": "finding deleted",
		"id":      id,
	})
}

// HandleGetFinding handles GET /api/findings/:id — returns a single finding by numeric ID.
func (h *Handlers) HandleGetFinding(c fiber.Ctx) error {
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
			Error: "invalid finding ID: must be a number",
			Code:  fiber.StatusBadRequest,
		})
	}

	finding, err := h.repo.GetFindingByID(c.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
				Error: ErrFindingNotFound.Error(),
				Code:  fiber.StatusNotFound,
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to retrieve finding: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(finding)
}
