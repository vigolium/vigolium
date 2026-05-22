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
	app.Use(DefaultBodyLimitMiddleware())

	if cfg.Debug {
		app.Use(DebugRequestMiddleware())
	}

	// CORS
	if cfg.CORSAllowedOrigins != "" {
		corsCfg := cors.Config{
			AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowHeaders: []string{"Content-Type", "Authorization", "X-Project-UUID", "X-User-Email"},
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
	if !cfg.NoSwagger {
		app.Get("/swagger/doc.json", handlers.HandleSwaggerSpec)
		app.Use("/swagger", swaggerui.New(swaggerui.Config{
			BasePath:    "/",
			FileContent: swaggerSpec,
			Path:        "swagger",
			Title:       "Vigolium API",
		}))
	}

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

	// Project UUID extraction from X-Project-UUID header.
	// Passing the repo enables lazy auto-creation of unknown UUIDs so client-side
	// state (UI localStorage, CLI configs) keeps working after a scanner DB reset.
	app.Use(ProjectUUIDMiddleware(handlers.repo))

	// Routes (public — no role guard needed, auth already skips these)
	app.Get("/health", handlers.HandleHealth)
	app.Get("/server-info", handlers.HandleServerInfo)

	// API group
	api := app.Group("/api")

	// In demo-only mode, expose only the narrow read-only allowlist below and
	// block every other API route with a 403 "disabled in demo mode" response.
	// The allowlisted endpoints mirror the five docs pages under
	// docs/api-references/ (findings, extensions, http-records, modules, stats).
	if cfg.DemoOnly {
		demo := api.Group("", RoleGuard(RoleAdmin, RoleOperator, RoleViewer))
		demo.Get("/modules", handlers.HandleListModules)
		demo.Get("/stats", handlers.HandleStats)
		demo.Get("/http-records", handlers.HandleListRecords)
		demo.Get("/http-records/:uuid", handlers.HandleGetRecord)
		demo.Get("/findings", handlers.findings.HandleListFindings)
		demo.Get("/findings/:id", handlers.findings.HandleGetFinding)
		demo.Get("/extensions/docs", handlers.HandleListExtensionAPI) // must precede :name
		demo.Get("/extensions", handlers.HandleListExtensions)
		demo.Get("/extensions/:name", handlers.HandleGetExtension)
		api.All("/*", func(c fiber.Ctx) error {
			return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
				Error: "this API endpoint is disabled in demo mode",
				Code:  fiber.StatusForbidden,
			})
		})
		return
	}

	// --- Viewer routes (admin + operator + viewer) ---
	// Read-only access to records, findings, stats, and scan history
	viewer := api.Group("", RoleGuard(RoleAdmin, RoleOperator, RoleViewer))
	viewer.Get("/info", handlers.HandleAppInfo)
	viewer.Get("/user/info", handlers.HandleUserInfo)
	viewer.Get("/modules", handlers.HandleListModules)
	viewer.Get("/http-records", handlers.HandleListRecords)
	viewer.Get("/http-records/:uuid", handlers.HandleGetRecord)
	viewer.Get("/findings", handlers.findings.HandleListFindings)
	viewer.Get("/findings/:id", handlers.findings.HandleGetFinding)
	viewer.Get("/stats", handlers.HandleStats)
	viewer.Get("/scans", handlers.HandleListScans)
	viewer.Get("/scans/:uuid", handlers.HandleGetScan)
	viewer.Get("/scan/status", handlers.HandleScanStatus)
	viewer.Get("/scans/:uuid/logs", handlers.HandleGetScanLogs)
	viewer.Get("/scope", handlers.HandleGetScope)
	viewer.Get("/config", handlers.HandleGetConfig)
	viewer.Get("/oast-interactions", handlers.HandleListOASTInteractions)
	viewer.Get("/oast-interactions/:id", handlers.HandleGetOASTInteraction)
	viewer.Get("/extensions/docs", handlers.HandleListExtensionAPI)
	viewer.Get("/extensions", handlers.HandleListExtensions)
	viewer.Get("/extensions/:name", handlers.HandleGetExtension)
	viewer.Get("/projects", handlers.HandleListProjects)
	viewer.Get("/projects/:uuid", handlers.HandleGetProject)
	viewer.Get("/projects/:uuid/stats", handlers.HandleGetProjectStats)
	viewer.Get("/agent/status/list", handlers.HandleAgenticScanList) // must be before :id
	viewer.Get("/agent/status/:id", handlers.HandleAgenticScanStatus)
	viewer.Get("/agent/sessions", handlers.HandleAgentSessionList)
	viewer.Get("/agent/sessions/:id", handlers.HandleAgentSessionDetail)
	viewer.Get("/agent/sessions/:id/logs", handlers.HandleAgentSessionLogs)
	viewer.Get("/agent/sessions/:id/artifacts", handlers.HandleAgentSessionArtifacts)
	viewer.Get("/agent/sessions/:id/artifacts/*", handlers.HandleAgentSessionArtifact)
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
	operator.Post("/import", handlers.HandleImport)
	operator.Post("/scans/:uuid/update", handlers.HandleUpdateScan)
	operator.Post("/agent/scans/:uuid/update", handlers.HandleUpdateAgenticScan)
	operator.Patch("/findings/:id/status", handlers.findings.HandleUpdateFindingStatus)
	if !cfg.NoAgent {
		operator.Post("/agent/run/query", handlers.HandleAgentQuery)
		operator.Post("/agent/run/autopilot", handlers.HandleAgentAutopilot)
		operator.Post("/agent/run/swarm", handlers.HandleAgentSwarm)
		operator.Post("/agent/run/audit", handlers.HandleAgentAudit)
		operator.Post("/agent/chat/completions", handlers.HandleChatCompletions)
	}

	// --- Admin routes (admin only) ---
	// Destructive operations, config changes, project/resource management
	admin := api.Group("", RoleGuard(RoleAdmin))
	admin.Delete("/scans/:uuid", handlers.HandleDeleteScan)
	admin.Delete("/http-records/:uuid", handlers.HandleDeleteRecord)
	admin.Delete("/findings/:id", handlers.findings.HandleDeleteFinding)
	admin.Delete("/oast-interactions/:id", handlers.HandleDeleteOASTInteraction)
	admin.Delete("/projects/:uuid", handlers.HandleDeleteProject)
	admin.Post("/scope", handlers.HandleUpdateScope)
	admin.Post("/config", handlers.HandleUpdateConfig)
	admin.Put("/extensions/:name", handlers.HandleEditExtension)
	admin.Post("/projects", handlers.HandleCreateProject)
	admin.Put("/projects/:uuid", handlers.HandleUpdateProject)

	// --- Cloud storage endpoints ---
	// Scoped by project UUID via middleware. Requires storage config to be enabled.
	viewer.Get("/storage/source/:key", handlers.HandleStorageDownloadSource)
	viewer.Get("/storage/results/:scan_uuid", handlers.HandleStorageDownloadResults)
	operator.Post("/storage/upload-source", handlers.HandleStorageUploadSource)
	operator.Post("/storage/presign", handlers.HandleStoragePresign)

	// --- Generic database API (writes for admin only) ---
	admin.Post("/db/tables/:table/records", handlers.HandleCreateDBRecord)
	admin.Put("/db/tables/:table/records/:id", handlers.HandleUpdateDBRecord)
	admin.Delete("/db/tables/:table/records/:id", handlers.HandleDeleteDBRecord)

}
