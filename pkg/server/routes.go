package server

import (
	"io/fs"
	"strings"

	"github.com/gofiber/contrib/v3/swaggerui"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
	fiberlogger "github.com/gofiber/fiber/v3/middleware/logger"
	fiberrecover "github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/requestid"
	"github.com/gofiber/fiber/v3/middleware/static"

	"github.com/vigolium/vigolium/public"
)

// registerRoutes sets up all middleware and routes on the Fiber app.
func registerRoutes(app *fiber.App, handlers *Handlers, cfg ServerConfig) {
	// Global middleware
	app.Use(requestid.New())
	app.Use(fiberlogger.New())
	app.Use(fiberrecover.New())
	app.Use(SecurityHeadersMiddleware())
	app.Use(DefaultBodyLimitMiddleware("/api/repos/upload"))

	if cfg.Debug {
		app.Use(DebugRequestMiddleware())
	}

	// CORS
	if cfg.CORSAllowedOrigins != "" {
		corsCfg := cors.Config{
			AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowHeaders: []string{"Content-Type", "Authorization", "X-Project-UUID"},
		}
		switch cfg.CORSAllowedOrigins {
		case "reflect-origin":
			corsCfg.AllowOriginsFunc = func(_ string) bool { return true }
			corsCfg.AllowCredentials = true
		case "*":
			corsCfg.AllowOrigins = []string{"*"}
		default:
			origins := strings.Split(cfg.CORSAllowedOrigins, ",")
			for i := range origins {
				origins[i] = strings.TrimSpace(origins[i])
			}
			corsCfg.AllowOrigins = origins
			corsCfg.AllowCredentials = true
		}
		app.Use(cors.New(corsCfg))
	}

	// Swagger UI (before auth so docs are publicly accessible)
	app.Get("/swagger/doc.json", handlers.HandleSwaggerSpec)
	app.Use("/swagger", swaggerui.New(swaggerui.Config{
		BasePath:    "/",
		FileContent: swaggerSpec,
		Path:        "swagger",
		Title:       "Vigolium API",
	}))

	// Favicon (served from public/ root, not ui/ subdirectory)
	app.Get("/favicon.ico", func(c fiber.Ctx) error {
		data, err := public.StaticFS.ReadFile("favicon.ico")
		if err != nil {
			return c.SendStatus(fiber.StatusNotFound)
		}
		c.Set("Content-Type", "image/x-icon")
		c.Set("Cache-Control", "public, max-age=86400")
		return c.Send(data)
	})

	// Prometheus metrics (before auth so monitoring can scrape without tokens)
	app.Get("/metrics", handlers.HandleMetrics)

	// Dashboard UI (before auth so static assets are publicly accessible).
	// Fiber's static middleware calls c.Next() for paths with no matching file,
	// so /api/*, /health, /metrics, /swagger all pass through to their handlers.
	uiFS, _ := fs.Sub(public.StaticFS, "ui")
	app.Use("/", static.New("", static.Config{
		FS:         uiFS,
		IndexNames: []string{"index.html"},
	}))

	// Bearer auth
	if !cfg.NoAuth && len(cfg.APIKeys) > 0 {
		app.Use(BearerAuth(cfg.APIKeys))
	}

	// Project UUID extraction from X-Project-UUID header
	app.Use(ProjectUUIDMiddleware())

	// Routes
	app.Get("/health", handlers.HandleHealth)
	app.Get("/server-info", handlers.HandleServerInfo)

	// API group
	api := app.Group("/api")
	api.Get("/info", handlers.HandleAppInfo)
	api.Get("/modules", handlers.HandleListModules)
	api.Get("/http-records", handlers.HandleListRecords)
	api.Get("/http-records/:uuid", handlers.HandleGetRecord)
	api.Get("/findings", handlers.HandleListFindings)
	api.Get("/findings/:id", handlers.HandleGetFinding)
	api.Post("/ingest-http", handlers.HandleIngestHTTP)
	api.Get("/stats", handlers.HandleStats)
	api.Get("/scope", handlers.HandleGetScope)
	api.Post("/scope", handlers.HandleUpdateScope)
	api.Get("/config", handlers.HandleGetConfig)
	api.Post("/config", handlers.HandleUpdateConfig)

	// Scan management
	api.Post("/scans/run", handlers.HandleRunScan)
	api.Get("/scan/status", handlers.HandleScanStatus)
	api.Delete("/scan", handlers.HandleCancelScan)

	// Scan history
	api.Get("/scans", handlers.HandleListScans)
	api.Get("/scans/:uuid", handlers.HandleGetScan)
	api.Delete("/scans/:uuid", handlers.HandleDeleteScan)
	api.Post("/scans/:uuid/stop", handlers.HandleStopScan)
	api.Post("/scans/:uuid/pause", handlers.HandlePauseScan)
	api.Post("/scans/:uuid/resume", handlers.HandleResumeScan)
	api.Get("/scans/:uuid/logs", handlers.HandleGetScanLogs)

	// Record-based scans
	api.Post("/scan-records", handlers.HandleScanRecords)
	api.Post("/scan-all-records", handlers.HandleScanAllRecords)

	// Delete operations
	api.Delete("/http-records/:uuid", handlers.HandleDeleteRecord)
	api.Delete("/findings/:id", handlers.HandleDeleteFinding)

	// Single-target scans
	api.Post("/scan-url", handlers.HandleScanURL)
	api.Post("/scan-request", handlers.HandleScanRequest)

	// Repo management (SAST upload/cleanup)
	api.Post("/repos/upload", handlers.HandleRepoUpload)
	api.Delete("/repos/:id", handlers.HandleRepoDelete)

	// Source repos
	api.Get("/source-repos", handlers.HandleListSourceRepos)
	api.Post("/source-repos", handlers.HandleCreateSourceRepo)
	api.Get("/source-repos/:id", handlers.HandleGetSourceRepo)
	api.Put("/source-repos/:id", handlers.HandleUpdateSourceRepo)
	api.Delete("/source-repos/:id", handlers.HandleDeleteSourceRepo)

	// OAST interactions
	api.Get("/oast-interactions", handlers.HandleListOASTInteractions)
	api.Get("/oast-interactions/:id", handlers.HandleGetOASTInteraction)
	api.Delete("/oast-interactions/:id", handlers.HandleDeleteOASTInteraction)

	// Extensions
	api.Get("/extensions/docs", handlers.HandleListExtensionAPI)
	api.Get("/extensions", handlers.HandleListExtensions)
	api.Get("/extensions/:name", handlers.HandleGetExtension)
	api.Put("/extensions/:name", handlers.HandleEditExtension)

	// Projects
	api.Get("/projects", handlers.HandleListProjects)
	api.Post("/projects", handlers.HandleCreateProject)
	api.Get("/projects/:uuid", handlers.HandleGetProject)
	api.Put("/projects/:uuid", handlers.HandleUpdateProject)
	api.Delete("/projects/:uuid", handlers.HandleDeleteProject)

	// Agent
	api.Post("/agent/run/query", handlers.HandleAgentQuery)
	api.Post("/agent/run/autopilot", handlers.HandleAgentAutopilot)
	api.Post("/agent/run/pipeline", handlers.HandleAgentPipeline)
	api.Post("/agent/run/swarm", handlers.HandleAgentSwarm)
	api.Post("/agent/chat/completions", handlers.HandleChatCompletions)
	api.Get("/agent/status/list", handlers.HandleAgentRunList) // must be before :id
	api.Get("/agent/status/:id", handlers.HandleAgentRunStatus)

}
