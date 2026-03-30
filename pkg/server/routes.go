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

	// Login endpoint (before auth — publicly accessible)
	app.Post("/api/auth/login", handlers.HandleLogin)

	// Dashboard UI (before auth so static assets are publicly accessible).
	// Fiber's static middleware calls c.Next() for paths with no matching file,
	// so /api/*, /health, /metrics, /swagger all pass through to their handlers.
	uiFS, _ := fs.Sub(public.StaticFS, "ui")
	app.Use("/", static.New("", static.Config{
		FS:         uiFS,
		IndexNames: []string{"index.html"},
	}))

	// Bearer auth with user store
	if !cfg.NoAuth && (len(cfg.APIKeys) > 0 || cfg.UserStore != nil) {
		app.Use(BearerAuth(cfg.APIKeys, cfg.UserStore))
	}

	// Project UUID extraction from X-Project-UUID header
	app.Use(ProjectUUIDMiddleware())

	// Routes (public — no role guard needed, auth already skips these)
	app.Get("/health", handlers.HandleHealth)
	app.Get("/server-info", handlers.HandleServerInfo)

	// API group
	api := app.Group("/api")

	// --- Viewer routes (admin + operator + viewer) ---
	// Read-only access to records, findings, stats, and scan history
	viewer := api.Group("", RoleGuard(RoleAdmin, RoleOperator, RoleViewer))
	viewer.Get("/info", handlers.HandleAppInfo)
	viewer.Get("/user/info", handlers.HandleUserInfo)
	viewer.Get("/modules", handlers.HandleListModules)
	viewer.Get("/http-records", handlers.HandleListRecords)
	viewer.Get("/http-records/:uuid", handlers.HandleGetRecord)
	viewer.Get("/findings", handlers.HandleListFindings)
	viewer.Get("/findings/:id", handlers.HandleGetFinding)
	viewer.Get("/stats", handlers.HandleStats)
	viewer.Get("/scans/queue", handlers.HandleScanQueue)
	viewer.Get("/scans", handlers.HandleListScans)
	viewer.Get("/scans/:uuid", handlers.HandleGetScan)
	viewer.Get("/scan/status", handlers.HandleScanStatus)
	viewer.Get("/scans/:uuid/logs", handlers.HandleGetScanLogs)
	viewer.Get("/scope", handlers.HandleGetScope)
	viewer.Get("/config", handlers.HandleGetConfig)
	viewer.Get("/source-repos", handlers.HandleListSourceRepos)
	viewer.Get("/source-repos/:id", handlers.HandleGetSourceRepo)
	viewer.Get("/oast-interactions", handlers.HandleListOASTInteractions)
	viewer.Get("/oast-interactions/:id", handlers.HandleGetOASTInteraction)
	viewer.Get("/extensions/docs", handlers.HandleListExtensionAPI)
	viewer.Get("/extensions", handlers.HandleListExtensions)
	viewer.Get("/extensions/:name", handlers.HandleGetExtension)
	viewer.Get("/projects", handlers.HandleListProjects)
	viewer.Get("/projects/:uuid", handlers.HandleGetProject)
	viewer.Get("/agent/status/list", handlers.HandleAgentRunList) // must be before :id
	viewer.Get("/agent/status/:id", handlers.HandleAgentRunStatus)
	viewer.Get("/agent/sessions", handlers.HandleAgentSessionList)
	viewer.Get("/agent/sessions/:id", handlers.HandleAgentSessionDetail)
	viewer.Get("/diagnostics", handlers.HandleDiagnostics)

	// --- Generic database API (read-only for viewer) ---
	viewer.Get("/db/tables", handlers.HandleListDBTables)
	viewer.Get("/db/tables/:table/columns", handlers.HandleListDBTableColumns)
	viewer.Get("/db/tables/:table/records", handlers.HandleListDBRecords)
	viewer.Get("/db/tables/:table/records/:id", handlers.HandleGetDBRecord)

	// In view-only mode, skip all write/mutation routes (operator + admin).
	if cfg.ViewOnly {
		return
	}

	// --- Operator routes (admin + operator) ---
	// Scan execution, ingestion, and agent operations
	operator := api.Group("", RoleGuard(RoleAdmin, RoleOperator))
	operator.Post("/scans/run", handlers.HandleRunScan)
	operator.Post("/scan-records", handlers.HandleScanRecords)
	operator.Post("/scan-all-records", handlers.HandleScanAllRecords)
	operator.Post("/scan-url", handlers.HandleScanURL)
	operator.Post("/scan-request", handlers.HandleScanRequest)
	operator.Post("/scans/:uuid/stop", handlers.HandleStopScan)
	operator.Post("/scans/:uuid/pause", handlers.HandlePauseScan)
	operator.Post("/scans/:uuid/resume", handlers.HandleResumeScan)
	operator.Post("/ingest-http", handlers.HandleIngestHTTP)
	if !cfg.NoAgent {
		operator.Post("/agent/run/query", handlers.HandleAgentQuery)
		operator.Post("/agent/run/autopilot", handlers.HandleAgentAutopilot)
operator.Post("/agent/run/swarm", handlers.HandleAgentSwarm)
		operator.Post("/agent/chat/completions", handlers.HandleChatCompletions)
	}

	// --- Admin routes (admin only) ---
	// Destructive operations, config changes, project/resource management
	admin := api.Group("", RoleGuard(RoleAdmin))
	admin.Delete("/scan", handlers.HandleCancelScan)
	admin.Delete("/scans/:uuid", handlers.HandleDeleteScan)
	admin.Delete("/http-records/:uuid", handlers.HandleDeleteRecord)
	admin.Delete("/findings/:id", handlers.HandleDeleteFinding)
	admin.Delete("/oast-interactions/:id", handlers.HandleDeleteOASTInteraction)
	admin.Delete("/repos/:id", handlers.HandleRepoDelete)
	admin.Delete("/source-repos/:id", handlers.HandleDeleteSourceRepo)
	admin.Delete("/projects/:uuid", handlers.HandleDeleteProject)
	admin.Post("/scope", handlers.HandleUpdateScope)
	admin.Post("/config", handlers.HandleUpdateConfig)
	admin.Post("/repos/upload", handlers.HandleRepoUpload)
	admin.Post("/source-repos", handlers.HandleCreateSourceRepo)
	admin.Put("/source-repos/:id", handlers.HandleUpdateSourceRepo)
	admin.Put("/extensions/:name", handlers.HandleEditExtension)
	admin.Post("/projects", handlers.HandleCreateProject)
	admin.Put("/projects/:uuid", handlers.HandleUpdateProject)

	// --- Generic database API (writes for admin only) ---
	admin.Post("/db/tables/:table/records", handlers.HandleCreateDBRecord)
	admin.Put("/db/tables/:table/records/:id", handlers.HandleUpdateDBRecord)
	admin.Delete("/db/tables/:table/records/:id", handlers.HandleDeleteDBRecord)

}
