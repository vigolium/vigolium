package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/fsexport"
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

// serverHeader builds the `Server:` response header. The version stamped into
// the binary already carries its own "v" prefix (pkg/cli.Version is "v0.4.1",
// and .goreleaser.yaml stamps "v{{.Version}}"), so a hardcoded "v" in front of
// it rendered as "Vigolium vv0.4.1". The prefix is normalized rather than just
// dropped so a build stamped without one still reads as a version.
func serverHeader(version string) string {
	v := strings.TrimSpace(version)
	switch {
	case v == "":
		v = "dev"
	case !strings.HasPrefix(v, "v"):
		v = "v" + v
	}
	return "Vigolium " + v + " (source https://github.com/vigolium/vigolium)"
}

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
	fsMirror        *fsexport.Mirror // live --mirror-fs filesystem mirror (nil when disabled)

	// serviceLn and proxyLn are the bound listeners (Bind); started records
	// whether Start handed them to the servers, so Shutdown knows who closes
	// them.
	serviceLn, proxyLn net.Listener
	started            bool
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
	// WriteTimeout intentionally has NO non-zero default: this server hosts SSE
	// agent/audit streams that legitimately run for minutes, and fasthttp arms the
	// write deadline once for the whole (streamed) response, so any finite cap
	// severs a long stream mid-flight. 0 leaves it unlimited; ReadTimeout +
	// IdleTimeout + handler/job deadlines bound non-streaming work. Operators who
	// don't use long streams can still set an explicit WriteTimeout.
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 120 * time.Second
	}
	if cfg.MaxUploadBytes <= 0 {
		cfg.MaxUploadBytes = defaultMaxUploadBytes
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
		ServerHeader: serverHeader(cfg.Version),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
		// Raise the framework body ceiling above DefaultBodyLimitMiddleware's 4 MB
		// cap so the exempt large-upload routes actually work. Without this Fiber's
		// own 4 MB default rejects the upload before the route exemption can run.
		// Non-upload routes are still held to 4 MB by the middleware.
		BodyLimit: cfg.MaxUploadBytes,
		// Stream the request body instead of pre-buffering the whole thing into
		// memory before any handler runs. With this off, fasthttp reads up to the
		// full BodyLimit (512 MB) into memory for EVERY request before the 4 MB
		// middleware can reject it, so a burst of ordinary oversized POSTs to normal
		// JSON routes is a memory-amplification vector. Streaming lets
		// DefaultBodyLimitMiddleware reject an oversized declared Content-Length
		// before allocation; the large-upload routes read their stream on demand.
		StreamRequestBody: true,
		// Router errors (unknown route, wrong method, recovered panic) and errors
		// a handler returns render as the negotiated JSON error, not text/plain.
		ErrorHandler: apiErrorHandler,
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

	// --mirror-fs: mirror every saved record + finding to a live filesystem tree
	// in addition to the database. Wired via the repository's save callbacks, so
	// it covers all ingestion paths (handlers, ingest-proxy, scan-on-receive)
	// uniformly. Best-effort: a setup failure logs and leaves the DB untouched.
	if cfg.MirrorFSPath != "" && repo != nil {
		// omitResponse=false: always mirror a response when the record has one
		// (records without a response simply skip the .resp.* files).
		mirror, err := fsexport.NewMirror(config.ExpandPath(cfg.MirrorFSPath), false)
		if err != nil {
			zap.L().Warn("Failed to start --mirror-fs filesystem mirror; continuing without it",
				zap.String("path", cfg.MirrorFSPath), zap.Error(err))
		} else {
			s.fsMirror = mirror
			handlers.mirrorDropped = mirror.Dropped
			repo.OnRecordSaved = mirror.OnRecord
			repo.OnFindingSaved = mirror.OnFinding
			zap.L().Info("Filesystem mirror enabled", zap.String("path", cfg.MirrorFSPath))
		}
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
			handlers.ingestScopeFor, mitmCA, cfg.IngestProxyInsecure, cfg.IngestProxyAuth)
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

// Bind opens the API listener and, when configured, the ingest proxy's,
// without serving. A caller that announces the server binds first, so a port
// already in use is an error before anything says "running". Idempotent.
func (s *Server) Bind() error {
	if s.serviceLn != nil {
		return nil
	}
	ln, err := net.Listen("tcp", s.config.ServiceAddr)
	if err != nil {
		return fmt.Errorf("bind API server to %s: %w", s.config.ServiceAddr, err)
	}
	if s.proxyServer != nil {
		pln, err := net.Listen("tcp", s.proxyServer.Addr)
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("bind ingest proxy to %s: %w", s.proxyServer.Addr, err)
		}
		s.proxyLn = pln
	}
	s.serviceLn = ln
	return nil
}

// ServiceAddr returns the address the API listener is bound to, or the
// configured address before Bind.
func (s *Server) ServiceAddr() string {
	if s.serviceLn != nil {
		return s.serviceLn.Addr().String()
	}
	return s.config.ServiceAddr
}

// Start starts the API server (and proxy if configured), binding first when
// Bind was not called. Blocks until the server is stopped.
func (s *Server) Start() error {
	if err := s.Bind(); err != nil {
		return err
	}
	s.started = true

	// Start config watcher for hot reload
	if s.configWatcher != nil {
		s.configWatcher.Start()
	}

	// Start proxy in background if configured
	if s.proxyServer != nil {
		go func() {
			zap.L().Info("Ingest proxy starting",
				zap.String("addr", s.proxyServer.Addr))
			if err := s.proxyServer.Serve(s.proxyLn); err != nil && err != http.ErrServerClosed {
				zap.L().Error("Ingest proxy error", zap.Error(err))
			}
		}()
	}

	zap.L().Info("API server starting",
		zap.String("addr", s.config.ServiceAddr))

	return s.serviceApp.Listener(s.serviceLn, fiber.ListenConfig{
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

	// Bound but never started: nothing else owns the listeners.
	if !s.started {
		if s.serviceLn != nil {
			_ = s.serviceLn.Close()
		}
		if s.proxyLn != nil {
			_ = s.proxyLn.Close()
		}
	}

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

	// Drain and flush the filesystem mirror AFTER the record writer flush, so the
	// final batch of saved records reaches their callbacks (and thus the mirror)
	// before we wait for the mirror's writer goroutine to finish.
	if s.fsMirror != nil {
		s.fsMirror.Close()
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
