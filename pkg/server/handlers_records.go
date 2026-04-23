package server

import (
	"database/sql"
	"errors"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
)

// HandleListRecords handles GET /api/http-records
func (h *Handlers) HandleListRecords(c fiber.Ctx) error {
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

	// Domain / host
	if domain := c.Query("domain"); domain != "" {
		filters.HostPattern = domain
	}

	// Status codes (comma-separated)
	if sc := c.Query("status_code"); sc != "" {
		for _, s := range strings.Split(sc, ",") {
			code, err := strconv.Atoi(strings.TrimSpace(s))
			if err == nil {
				filters.StatusCodes = append(filters.StatusCodes, code)
			}
		}
	}

	// Content type
	if ct := c.Query("content_type"); ct != "" {
		filters.ContentType = ct
	}

	// Methods (comma-separated)
	if m := c.Query("method"); m != "" {
		for _, method := range strings.Split(m, ",") {
			method = strings.TrimSpace(strings.ToUpper(method))
			if method != "" {
				filters.Methods = append(filters.Methods, method)
			}
		}
	}

	// Path
	if p := c.Query("path"); p != "" {
		filters.PathPattern = p
	}

	// Search
	if s := c.Query("search"); s != "" {
		filters.SearchTerm = s
	}

	// Source
	if src := c.Query("source"); src != "" {
		filters.Source = src
	}

	// Risk score
	if minRisk := c.Query("min_risk"); minRisk != "" {
		if v, err := strconv.Atoi(minRisk); err == nil {
			filters.MinRiskScore = v
		}
	}

	// Remark (single or comma-separated for AND filtering)
	if remark := c.Query("remark"); remark != "" {
		if strings.Contains(remark, ",") {
			for _, r := range strings.Split(remark, ",") {
				r = strings.TrimSpace(r)
				if r != "" {
					filters.Remarks = append(filters.Remarks, r)
				}
			}
		} else {
			filters.Remark = remark
		}
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

	qb := database.NewQueryBuilder(h.db, filters)

	// Exclude blob fields for lightweight list responses. Raw columns are the
	// single source of truth; omitting them here also nils the JSON-derived
	// request_body/response_body/request_headers/response_headers fields
	// (MarshalJSON parses raw → nil in, nil out).
	query := qb.BuildRecordsQuery().
		ExcludeColumn("raw_request").
		ExcludeColumn("raw_response")

	var records []*database.HTTPRecord
	ctx := c.Context()
	if err := query.Scan(ctx, &records); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "query failed: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	total, _ := qb.Count(ctx)

	return c.JSON(PaginatedResponse{
		ProjectUUID: projectUUID,
		Data:        records,
		Total:       total,
		Limit:       filters.Limit,
		Offset:      filters.Offset,
		HasMore:     int64(filters.Offset+filters.Limit) < total,
	})
}

// HandleDeleteRecord handles DELETE /api/http-records/:uuid — deletes a single HTTP record by UUID.
func (h *Handlers) HandleDeleteRecord(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	uuid := c.Params("uuid")
	if uuid == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "missing uuid parameter",
			Code:  fiber.StatusBadRequest,
		})
	}

	// Verify the record exists
	if _, err := h.repo.GetRecordByUUID(c.Context(), uuid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
				Error: ErrRecordNotFound.Error(),
				Code:  fiber.StatusNotFound,
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to retrieve record: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	if err := h.repo.DeleteRecord(c.Context(), uuid); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to delete record: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(fiber.Map{
		"message": "HTTP record deleted",
		"uuid":    uuid,
	})
}

// HandleGetRecord handles GET /api/http-records/:uuid — returns a single HTTP record with full blob fields.
func (h *Handlers) HandleGetRecord(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	uuid := c.Params("uuid")
	if uuid == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "missing uuid parameter",
			Code:  fiber.StatusBadRequest,
		})
	}

	record, err := h.repo.GetRecordByUUID(c.Context(), uuid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
				Error: ErrRecordNotFound.Error(),
				Code:  fiber.StatusNotFound,
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to retrieve record: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(record)
}
