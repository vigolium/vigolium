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

	return c.JSON(projects)
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

	return c.JSON(project)
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
