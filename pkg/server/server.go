package server

import (
	"context"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	vhttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/metrics"
	"github.com/vigolium/vigolium/pkg/queue"
	"github.com/vigolium/vigolium/pkg/server/mitm"
	"go.uber.org/zap"
)

// DefaultIngestProxyCADir is the default directory for the ingest-proxy MITM
// CA (used when ServerConfig.IngestProxyCADir is empty). It is the single
// source of truth shared with the CLI's --export-ca path so a CA exported
// out-of-band matches the one the running proxy uses.
const DefaultIngestProxyCADir = "~/.vigolium/ca"

// Server is the HTTP API server.
type Server struct {
	serviceApp      *fiber.App
	proxyServer     *http.Server // nil if proxy disabled
	proxyCACertPath string       // MITM CA cert path when HTTPS interception is on
	handlers        *Handlers
	recordWriter    *database.RecordWriter
	configWatcher   *config.ConfigWatcher
	config          ServerConfig
	queue           queue.Queue
	db              *database.DB
	repo            *database.Repository
}

// NewServer creates a new HTTP API server.
//
// svc is the shared *services.Services the caller built for httpRequester.
// It carries the dedup manager, host rate limiter, and scan Options used by
// the core executor — passing it through lets API-triggered scans reuse the
// same rate-limiter instance the ingestion path uses, rather than running
// unbounded. Safe to pass nil (handlers will fall back to the previous
// minimal-wiring behavior).
func NewServer(cfg ServerConfig, q queue.Queue, db *database.DB, repo *database.Repository, settings *config.Settings, httpRequester *vhttp.Requester, svc *services.Services) *Server {
	if cfg.ServiceAddr == "" {
		cfg.ServiceAddr = ":9002"
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 10 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 60 * time.Second
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 120 * time.Second
	}
	if cfg.ShutdownTimeout == 0 {
		cfg.ShutdownTimeout = 30 * time.Second
	}

	// Create write-coalescing RecordWriter when a database is available.
	// This serializes all ingestion writes through a single goroutine,
	// eliminating SQLite SQLITE_BUSY errors under concurrent load.
	var recordWriter *database.RecordWriter
	if repo != nil {
		recordWriter = database.NewRecordWriter(repo, database.RecordWriterConfig{})
	}

	handlers := NewHandlers(q, db, repo, recordWriter, cfg, settings, httpRequester, svc)

	// Set up Prometheus metrics (when enabled)
	if cfg.EnableMetrics {
		registry := prometheus.NewRegistry()
		registry.MustRegister(collectors.NewGoCollector())
		registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		registry.MustRegister(metrics.NewCollector(metrics.CollectorConfig{
			Queue:     q,
			DB:        db,
			ScanState: handlers,
			StartTime: handlers.startTime,
			Version:   cfg.Version,
			Commit:    cfg.Commit,
		}))
		handlers.metricsHandler = metrics.NewFiberHandler(registry)
	}

	app := fiber.New(fiber.Config{
		ServerHeader: "Vigolium v" + cfg.Version + " (AGPL-3.0; source https://github.com/vigolium/vigolium)",
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	})

	registerRoutes(app, handlers, cfg)

	s := &Server{
		serviceApp:   app,
		handlers:     handlers,
		recordWriter: recordWriter,
		config:       cfg,
		queue:        q,
		db:           db,
		repo:         repo,
	}

	// Create config watcher for hot reload. Watch the same file the server
	// loaded settings from (honors --config); fall back to the default path.
	if settings != nil {
		watchPath := cfg.ConfigPath
		if watchPath == "" {
			watchPath = config.ConfigFilePath()
		}
		cw, err := config.NewConfigWatcher(watchPath, settings)
		if err != nil {
			zap.L().Warn("Failed to create config watcher, hot reload disabled",
				zap.Error(err))
		} else {
			s.configWatcher = cw
			handlers.configWatcher = cw

			// Invalidate the cached scope matcher when scope config hot-reloads.
			// Agent changes need no rewiring here — the cached agent engine
			// re-reads settings.Agent.Olium on the next run. User-facing reload
			// feedback is emitted by the CLI via OnConfigReload.
			cw.OnReload(func(changed []string) {
				for _, section := range changed {
					if section == "scope" {
						handlers.resetScopeMatcher()
						return
					}
				}
			})
		}
	}

	// Create proxy server if configured (disabled in view-only mode)
	if cfg.IngestProxyAddr != "" && !cfg.ViewOnly {
		var mitmCA *mitm.CA
		if cfg.IngestProxyMITM {
			caDir := cfg.IngestProxyCADir
			if caDir == "" {
				caDir = config.ExpandPath(DefaultIngestProxyCADir)
			}
			ca, err := mitm.LoadOrCreateCA(caDir)
			if err != nil {
				zap.L().Error("Failed to initialize ingest-proxy MITM CA; HTTPS interception disabled",
					zap.Error(err))
			} else {
				mitmCA = ca
				s.proxyCACertPath = ca.CertPath()
				zap.L().Info("Ingest-proxy HTTPS interception enabled",
					zap.String("ca_cert", ca.CertPath()))
			}
		}
		s.proxyServer = newIngestProxy(cfg.IngestProxyAddr, db, repo, recordWriter, settings,
			handlers.getScopeMatcher, mitmCA, cfg.IngestProxyInsecure)
	}

	return s
}

// ProxyCACertPath returns the on-disk path of the ingest-proxy MITM CA
// certificate, or "" when HTTPS interception is not enabled. Used by the CLI to
// surface the trust anchor at startup.
func (s *Server) ProxyCACertPath() string { return s.proxyCACertPath }

// OnConfigReload registers fn to run after the config watcher hot-reloads one
// or more sections at runtime; fn receives the changed section names. No-op
// when the watcher failed to start. Register before Start(). Used by the CLI
// to print operator-facing reload feedback.
func (s *Server) OnConfigReload(fn func(changed []string)) {
	if s.configWatcher != nil {
		s.configWatcher.OnReload(fn)
	}
}

// Start starts the API server (and proxy if configured).
// Blocks until the server is stopped.
func (s *Server) Start() error {
	// Start config watcher for hot reload
	if s.configWatcher != nil {
		s.configWatcher.Start()
	}

	// Start proxy in background if configured
	if s.proxyServer != nil {
		go func() {
			zap.L().Info("Ingest proxy starting",
				zap.String("addr", s.proxyServer.Addr))
			if err := s.proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				zap.L().Error("Ingest proxy error", zap.Error(err))
			}
		}()
	}

	zap.L().Info("API server starting",
		zap.String("addr", s.config.ServiceAddr))

	return s.serviceApp.Listen(s.config.ServiceAddr, fiber.ListenConfig{
		DisableStartupMessage: true,
	})
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), s.config.ShutdownTimeout)
		defer cancel()
	}

	zap.L().Info("API server shutting down")

	// Stop config watcher
	if s.configWatcher != nil {
		if err := s.configWatcher.Close(); err != nil {
			zap.L().Error("Config watcher close error", zap.Error(err))
		}
	}

	// Shutdown proxy first
	if s.proxyServer != nil {
		if err := s.proxyServer.Shutdown(ctx); err != nil {
			zap.L().Error("Proxy shutdown error", zap.Error(err))
		}
	}

	// Close handler resources (agent engine pool, cleanup goroutine). This
	// cancels the handlers' run context first, so in-flight agent runs
	// (autopilot/swarm/audit) stop and release their SSE connections before we
	// wait on the HTTP server below — otherwise a live stream keeps a
	// connection non-idle and graceful shutdown blocks on it.
	if s.handlers != nil {
		s.handlers.Close()
	}

	// Flush remaining buffered records before closing
	if s.recordWriter != nil {
		s.recordWriter.Close()
	}

	// Honor the caller's deadline: ShutdownWithContext force-closes any
	// connections still open when ctx expires, instead of waiting forever for
	// them to go idle (which plain Shutdown() does — it ignores ctx entirely).
	return s.serviceApp.ShutdownWithContext(ctx)
}

// Queue returns the underlying queue.
func (s *Server) Queue() queue.Queue {
	return s.queue
}

// Config returns the server configuration.
func (s *Server) Config() ServerConfig {
	return s.config
}
