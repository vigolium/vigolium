package server

import (
	"database/sql"
	"errors"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/burpbridge"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
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

	bridgeEnabled := h.config.BurpBridgeURL != "" && burpbridge.Eligible(filters)
	fetchFilters := filters
	if bridgeEnabled {
		fetchFilters.Offset = 0
		fetchFilters.Limit = filters.Offset + filters.Limit
	}
	// Excluding raw_* keeps the list payload small. HTTPRecord.MarshalJSON
	// derives request_body/response_body/request_headers/response_headers from
	// raw_request/raw_response, so dropping those columns implicitly drops the
	// derived fields too. Detail endpoints select raw_* and get the full view.
	qb := database.NewQueryBuilder(h.db, fetchFilters).OmitBodies()

	query := qb.BuildRecordsQuery()

	var records []*database.HTTPRecord
	ctx := c.Context()
	if err := query.Scan(ctx, &records); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "query failed: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	total, _ := qb.Count(ctx)
	if bridgeEnabled {
		client, clientErr := burpbridge.New(h.config.BurpBridgeURL)
		var live burpbridge.Result
		if clientErr == nil {
			live, clientErr = client.Query(ctx, burpbridge.QueryFromFilters(fetchFilters, false))
		}
		if clientErr != nil {
			c.Set("X-Vigolium-Burp-Bridge", "unavailable")
			zap.L().Warn("Burp bridge traffic unavailable; returning database records only", zap.Error(clientErr))
		} else {
			c.Set("X-Vigolium-Burp-Bridge", "connected")
		}
		records, total = burpbridge.MergePage(
			records,
			live.Records,
			total,
			live.Total,
			filters.Offset,
			filters.Limit,
			filters.SortBy,
			filters.SortAsc,
		)
	}

	return c.JSON(PaginatedResponse{
		ProjectUUID: projectUUID,
		Data:        records,
		Total:       total,
		Limit:       filters.Limit,
		Offset:      filters.Offset,
		HasMore:     int64(filters.Offset+len(records)) < total,
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

	// Verify the record exists and belongs to the request's project. Only the
	// project is needed, so don't load the record's body to delete it.
	recProject, err := h.repo.RecordProjectUUID(c.Context(), uuid)
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
	if !inRequestProject(c, recProject) {
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: ErrRecordNotFound.Error(),
			Code:  fiber.StatusNotFound,
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
	if burpbridge.IsBridgeUUID(uuid) {
		if h.config.BurpBridgeURL == "" {
			return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{Error: ErrRecordNotFound.Error()})
		}
		client, err := burpbridge.New(h.config.BurpBridgeURL)
		if err != nil {
			return c.Status(fiber.StatusBadGateway).JSON(ErrorResponse{Error: err.Error()})
		}
		record, err := client.Inspect(c.Context(), uuid, getProjectUUID(c))
		if err != nil {
			return c.Status(fiber.StatusBadGateway).JSON(ErrorResponse{Error: err.Error()})
		}
		return c.JSON(record)
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
	if !inRequestProject(c, record.ProjectUUID) {
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: ErrRecordNotFound.Error(),
			Code:  fiber.StatusNotFound,
		})
	}

	return c.JSON(record)
}
