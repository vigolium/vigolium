package server

import "github.com/gofiber/fiber/v3"

// HandleUserInfo handles GET /api/user/info.
// Returns the authenticated user's identity and role.
func (h *Handlers) HandleUserInfo(c fiber.Ctx) error {
	user, _ := c.Locals(authUserLocalsKey).(*ResolvedUser)
	if user == nil {
		if h.config.NoAuth {
			return c.JSON(LoginUser{
				Name: "unauthenticated server",
				Role: RoleAdmin,
			})
		}
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: ErrInvalidAuthToken.Error(),
			Code:  fiber.StatusUnauthorized,
		})
	}
	return c.JSON(LoginUser{
		UUID:  user.UUID,
		Name:  user.Name,
		Email: user.Email,
		Role:  user.Role,
	})
}

// HandleLogin handles POST /api/auth/login.
// Validates username + access_code and returns user info with a Bearer token.
func (h *Handlers) HandleLogin(c fiber.Ctx) error {
	var req LoginRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid request body",
			Code:  fiber.StatusBadRequest,
		})
	}

	if req.Username == "" || req.AccessCode == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "username and access_code are required",
			Code:  fiber.StatusBadRequest,
		})
	}

	store := h.config.UserStore
	user := store.LookupByNameAndCode(req.Username, req.AccessCode)
	if user == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: ErrInvalidCredentials.Error(),
			Code:  fiber.StatusUnauthorized,
		})
	}

	return c.JSON(LoginResponse{
		Token: req.AccessCode,
		User: LoginUser{
			UUID:  user.UUID,
			Name:  user.Name,
			Email: user.Email,
			Role:  user.Role,
		},
	})
}
