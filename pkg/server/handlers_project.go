package server

import (
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/database"
)

// HandleListProjects handles GET /api/projects
func (h *Handlers) HandleListProjects(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	ownerUUID := c.Query("owner")
	projects, err := h.repo.ListProjects(c.Context(), ownerUUID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "query failed: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	// Bulk-fetch stats for all projects
	allStats, err := h.repo.GetAllProjectsStats(c.Context())
	if err != nil {
		// Non-fatal: return projects without stats
		allStats = make(map[string]*database.ProjectStatsRow)
	}

	result := make([]ProjectWithStats, 0, len(projects))
	for _, p := range projects {
		ps := buildProjectStats(allStats[p.UUID])
		result = append(result, ProjectWithStats{Project: p, Stats: ps})
	}

	return c.JSON(result)
}

// HandleCreateProject handles POST /api/projects
func (h *Handlers) HandleCreateProject(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	var req ProjectRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid request body: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	if req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "name is required",
			Code:  fiber.StatusBadRequest,
		})
	}

	now := time.Now()
	project := &database.Project{
		UUID:        uuid.NewString(),
		Name:        req.Name,
		Description: req.Description,
		OwnerUUID:   req.OwnerUUID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := h.repo.CreateProject(c.Context(), project); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to create project: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.Status(fiber.StatusCreated).JSON(project)
}

// HandleGetProject handles GET /api/projects/:uuid
func (h *Handlers) HandleGetProject(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	projectUUID := c.Params("uuid")
	project, err := h.repo.GetProjectByUUID(c.Context(), projectUUID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: "project not found",
			Code:  fiber.StatusNotFound,
		})
	}

	statsRow, err := h.repo.GetProjectStats(c.Context(), projectUUID)
	if err != nil {
		statsRow = nil // non-fatal
	}

	return c.JSON(ProjectWithStats{
		Project: project,
		Stats:   buildProjectStats(statsRow),
	})
}

// HandleUpdateProject handles PUT /api/projects/:uuid
func (h *Handlers) HandleUpdateProject(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	projectUUID := c.Params("uuid")
	project, err := h.repo.GetProjectByUUID(c.Context(), projectUUID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: "project not found",
			Code:  fiber.StatusNotFound,
		})
	}

	var req ProjectRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid request body: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	if req.Name != "" {
		project.Name = req.Name
	}
	if req.Description != "" {
		project.Description = req.Description
	}
	if req.OwnerUUID != "" {
		project.OwnerUUID = req.OwnerUUID
	}
	project.UpdatedAt = time.Now()

	if err := h.repo.UpdateProject(c.Context(), project); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to update project: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(project)
}

// buildProjectStats converts a database ProjectStatsRow into the API response type.
func buildProjectStats(row *database.ProjectStatsRow) ProjectStats {
	if row == nil {
		return ProjectStats{}
	}
	return ProjectStats{
		HTTPRecords: ProjectHTTPRecordStats{
			Total:     row.HTTPRecords,
			Success:   row.HTTP2xx,
			Redirect:  row.HTTP3xx,
			ClientErr: row.HTTP4xx,
			ServerErr: row.HTTP5xx,
		},
		Findings: ProjectFindingStats{
			Total:    row.Findings,
			Critical: row.Critical,
			High:     row.High,
			Medium:   row.Medium,
			Low:      row.Low,
			Info:     row.Info,
		},
		Scans:            row.Scans,
		AgentRuns:        row.AgentRuns,
		SourceRepos:      row.SourceRepos,
		OASTInteractions: row.OASTInteractions,
	}
}

// HandleDeleteProject handles DELETE /api/projects/:uuid
func (h *Handlers) HandleDeleteProject(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	projectUUID := c.Params("uuid")

	if projectUUID == database.DefaultProjectUUID {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "cannot delete the default project",
			Code:  fiber.StatusBadRequest,
		})
	}

	// Reassign all data from this project to the default project before deletion
	if err := h.repo.ReassignProjectData(c.Context(), projectUUID, database.DefaultProjectUUID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to reassign project data: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	if err := h.repo.DeleteProject(c.Context(), projectUUID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to delete project: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(fiber.Map{"message": "project deleted", "uuid": projectUUID})
}
