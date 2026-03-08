package server

import (
	"strconv"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
)

// HandleListSourceRepos handles GET /api/source-repos
func (h *Handlers) HandleListSourceRepos(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	ctx := c.Context()
	projectUUID := getProjectUUID(c)

	// Filter by hostname
	if hostname := c.Query("hostname"); hostname != "" {
		repos, err := h.repo.GetSourceReposByHostname(ctx, projectUUID, hostname)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Error: "query failed: " + err.Error(),
				Code:  fiber.StatusInternalServerError,
			})
		}
		return c.JSON(PaginatedResponse{
			ProjectUUID: projectUUID,
			Data:        repos,
			Total:       int64(len(repos)),
			Limit:       len(repos),
		})
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

	offset := 0
	if o := c.Query("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}

	repos, total, err := h.repo.ListSourceRepos(ctx, projectUUID, limit, offset)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "query failed: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(PaginatedResponse{
		ProjectUUID: projectUUID,
		Data:        repos,
		Total:       total,
		Limit:       limit,
		Offset:      offset,
		HasMore:     int64(offset+limit) < total,
	})
}

// HandleCreateSourceRepo handles POST /api/source-repos
func (h *Handlers) HandleCreateSourceRepo(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	var req SourceRepoRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid request body: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	if req.Hostname == "" || req.RootPath == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "hostname and root_path are required",
			Code:  fiber.StatusBadRequest,
		})
	}

	name := req.Name
	if name == "" {
		name = req.Hostname
	}

	repoType := req.RepoType
	if repoType == "" {
		repoType = "folder"
	}

	sr := &database.SourceRepo{
		ProjectUUID: getProjectUUID(c),
		Hostname:    req.Hostname,
		Name:        name,
		RootPath:    req.RootPath,
		RepoType:    repoType,
		Language:    req.Language,
		Framework:   req.Framework,
		ScanUUID:    req.ScanUUID,
		Endpoints:   req.Endpoints,
		RouteParams: req.RouteParams,
		Sinks:       req.Sinks,
		Tags:        req.Tags,
		Metadata:    req.Metadata,
	}

	if err := h.repo.CreateSourceRepo(c.Context(), sr); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to create source repo: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.Status(fiber.StatusCreated).JSON(sr)
}

// HandleGetSourceRepo handles GET /api/source-repos/:id
func (h *Handlers) HandleGetSourceRepo(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid ID",
			Code:  fiber.StatusBadRequest,
		})
	}

	sr, err := h.repo.GetSourceRepoByID(c.Context(), id)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: "source repo not found",
			Code:  fiber.StatusNotFound,
		})
	}

	return c.JSON(sr)
}

// HandleUpdateSourceRepo handles PUT /api/source-repos/:id
func (h *Handlers) HandleUpdateSourceRepo(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid ID",
			Code:  fiber.StatusBadRequest,
		})
	}

	sr, err := h.repo.GetSourceRepoByID(c.Context(), id)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: "source repo not found",
			Code:  fiber.StatusNotFound,
		})
	}

	var req SourceRepoRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid request body: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	// Apply updates
	if req.Hostname != "" {
		sr.Hostname = req.Hostname
	}
	if req.Name != "" {
		sr.Name = req.Name
	}
	if req.RootPath != "" {
		sr.RootPath = req.RootPath
	}
	if req.RepoType != "" {
		sr.RepoType = req.RepoType
	}
	if req.Language != "" {
		sr.Language = req.Language
	}
	if req.Framework != "" {
		sr.Framework = req.Framework
	}
	if req.ScanUUID != "" {
		sr.ScanUUID = req.ScanUUID
	}
	if req.Endpoints != nil {
		sr.Endpoints = req.Endpoints
	}
	if req.RouteParams != nil {
		sr.RouteParams = req.RouteParams
	}
	if req.Sinks != nil {
		sr.Sinks = req.Sinks
	}
	if req.Tags != nil {
		sr.Tags = req.Tags
	}
	if req.Metadata != nil {
		sr.Metadata = req.Metadata
	}

	if err := h.repo.UpdateSourceRepo(c.Context(), sr); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to update source repo: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(sr)
}

// HandleDeleteSourceRepo handles DELETE /api/source-repos/:id
func (h *Handlers) HandleDeleteSourceRepo(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid ID",
			Code:  fiber.StatusBadRequest,
		})
	}

	if err := h.repo.DeleteSourceRepo(c.Context(), id); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to delete source repo: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(fiber.Map{"message": "source repo deleted", "id": id})
}
