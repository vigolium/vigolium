package server

import (
	"database/sql"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
)

// --- Schema introspection ---

// HandleListDBTables returns all database tables with row counts.
// GET /api/db/tables
func (h *Handlers) HandleListDBTables(c fiber.Ctx) error {
	tables, err := database.ListTablesWithCounts(c.Context(), h.db)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to list tables: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}
	return c.JSON(fiber.Map{
		"tables": tables,
		"total":  len(tables),
	})
}

// HandleListDBTableColumns returns column metadata for a specific table.
// GET /api/db/tables/:table/columns
func (h *Handlers) HandleListDBTableColumns(c fiber.Ctx) error {
	tableName := c.Params("table")
	if err := database.ValidateTableName(c.Context(), h.db, tableName); err != nil {
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  fiber.StatusNotFound,
		})
	}

	columns, err := database.ListColumns(c.Context(), h.db, tableName)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to list columns: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	pk, _ := database.DetectPrimaryKey(c.Context(), h.db, tableName)

	return c.JSON(fiber.Map{
		"table":       tableName,
		"columns":     columns,
		"primary_key": pk.Columns,
		"total":       len(columns),
	})
}

// --- Generic CRUD ---

// HandleListDBRecords returns paginated, filtered records from any table.
// GET /api/db/tables/:table/records
func (h *Handlers) HandleListDBRecords(c fiber.Ctx) error {
	tableName := c.Params("table")

	opts, err := parseGenericQueryOptions(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	// Auto-inject project_uuid filter for project-scoped tables
	if isProjectScopedTable(tableName) {
		projectUUID := getProjectUUID(c)
		allProjects := c.Query("all_projects", "false")
		if allProjects != "true" && projectUUID != "" {
			opts.Filters = append(opts.Filters, database.GenericFilter{
				Column:   "project_uuid",
				Operator: "eq",
				Value:    projectUUID,
			})
		}
	}

	records, columns, total, err := database.QueryGenericTableFiltered(c.Context(), h.db, tableName, opts)
	if err != nil {
		status := fiber.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			status = fiber.StatusNotFound
		}
		return c.Status(status).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  status,
		})
	}

	return c.JSON(fiber.Map{
		"table":   tableName,
		"total":   total,
		"limit":   opts.Limit,
		"offset":  opts.Offset,
		"columns": columns,
		"records": records,
	})
}

// HandleGetDBRecord returns a single record by primary key.
// GET /api/db/tables/:table/records/:id
func (h *Handlers) HandleGetDBRecord(c fiber.Ctx) error {
	tableName := c.Params("table")
	pkValue := c.Params("id")

	record, err := database.GetGenericRecord(c.Context(), h.db, tableName, pkValue)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
				Error: "record not found",
				Code:  fiber.StatusNotFound,
			})
		}
		status := fiber.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "not supported") {
			status = fiber.StatusBadRequest
		}
		return c.Status(status).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  status,
		})
	}

	return c.JSON(fiber.Map{
		"table":  tableName,
		"record": record,
	})
}

// HandleCreateDBRecord inserts a new record into a table.
// POST /api/db/tables/:table/records
func (h *Handlers) HandleCreateDBRecord(c fiber.Ctx) error {
	tableName := c.Params("table")

	var fields map[string]interface{}
	if err := c.Bind().JSON(&fields); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid JSON body: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	// Auto-inject project_uuid for project-scoped tables
	if isProjectScopedTable(tableName) {
		if _, ok := fields["project_uuid"]; !ok {
			fields["project_uuid"] = getProjectUUID(c)
		}
	}

	if err := database.InsertGenericRecord(c.Context(), h.db, tableName, fields); err != nil {
		status := fiber.StatusInternalServerError
		if strings.Contains(err.Error(), "invalid column") || strings.Contains(err.Error(), "no valid fields") {
			status = fiber.StatusBadRequest
		}
		return c.Status(status).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  status,
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"table":   tableName,
		"message": "record created",
	})
}

// HandleUpdateDBRecord updates fields on an existing record.
// PUT /api/db/tables/:table/records/:id
func (h *Handlers) HandleUpdateDBRecord(c fiber.Ctx) error {
	tableName := c.Params("table")
	pkValue := c.Params("id")

	var fields map[string]interface{}
	if err := c.Bind().JSON(&fields); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid JSON body: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	if err := database.UpdateGenericRecord(c.Context(), h.db, tableName, pkValue, fields); err != nil {
		if err == sql.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
				Error: "record not found",
				Code:  fiber.StatusNotFound,
			})
		}
		status := fiber.StatusInternalServerError
		if strings.Contains(err.Error(), "invalid column") || strings.Contains(err.Error(), "cannot update primary key") || strings.Contains(err.Error(), "no valid fields") {
			status = fiber.StatusBadRequest
		}
		return c.Status(status).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  status,
		})
	}

	return c.JSON(fiber.Map{
		"table":   tableName,
		"id":      pkValue,
		"message": "record updated",
	})
}

// HandleDeleteDBRecord deletes a record by primary key.
// DELETE /api/db/tables/:table/records/:id
func (h *Handlers) HandleDeleteDBRecord(c fiber.Ctx) error {
	tableName := c.Params("table")
	pkValue := c.Params("id")

	if err := database.DeleteGenericRecord(c.Context(), h.db, tableName, pkValue); err != nil {
		if err == sql.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
				Error: "record not found",
				Code:  fiber.StatusNotFound,
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(fiber.Map{
		"table":   tableName,
		"id":      pkValue,
		"message": "record deleted",
	})
}

// --- Helpers ---

// parseGenericQueryOptions extracts GenericQueryOptions from query parameters.
func parseGenericQueryOptions(c fiber.Ctx) (database.GenericQueryOptions, error) {
	opts := database.GenericQueryOptions{
		Limit:  100,
		Offset: 0,
	}

	if v := c.Query("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return opts, err
		}
		opts.Limit = n
	}

	if v := c.Query("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return opts, err
		}
		opts.Offset = n
	}

	if v := c.Query("sort"); v != "" {
		opts.SortBy = v
	}

	if v := c.Query("order"); v != "" {
		opts.SortAsc = strings.EqualFold(v, "asc")
	}

	if v := c.Query("columns"); v != "" {
		opts.Columns = strings.Split(v, ",")
		for i := range opts.Columns {
			opts.Columns[i] = strings.TrimSpace(opts.Columns[i])
		}
	}

	if v := c.Query("search"); v != "" {
		opts.SearchTerm = v
	}

	if v := c.Query("truncate"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return opts, err
		}
		opts.Truncate = n
	}

	// Parse filter.* query params
	// Supported forms: filter.column=value, filter.column__op=value
	queries := c.Queries()
	for key, val := range queries {
		if !strings.HasPrefix(key, "filter.") {
			continue
		}
		rest := strings.TrimPrefix(key, "filter.")

		var column, operator string
		if idx := strings.LastIndex(rest, "__"); idx > 0 {
			column = rest[:idx]
			operator = rest[idx+2:]
		} else {
			column = rest
			operator = "eq"
		}

		opts.Filters = append(opts.Filters, database.GenericFilter{
			Column:   column,
			Operator: operator,
			Value:    val,
		})
	}

	return opts, nil
}

// isProjectScopedTable returns true if the table has a project_uuid column.
func isProjectScopedTable(tableName string) bool {
	scoped := map[string]bool{
		"scans":              true,
		"http_records":       true,
		"findings":           true,
		"source_repos":       true,
		"session_hostnames":  true,
		"oast_interactions":  true,
		"scan_logs":          true,
		"agent_runs":         true,
		"scopes":             true,
		"finding_records":    false,
	}
	return scoped[tableName]
}
