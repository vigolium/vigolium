package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/notify/webhook"
	"github.com/vigolium/vigolium/pkg/queue"
	"github.com/vigolium/vigolium/pkg/server"
	"github.com/vigolium/vigolium/pkg/server/mitm"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/public"
	"go.uber.org/zap"
)

// serverOptions holds server-specific configuration.
type serverOptions struct {
	// Server
	Host            string
	ServicePort     int
	IngestProxyPort int
	APIKeys         []string
	NoAuth          bool

	// Ingest-proxy TLS interception (MITM)
	ProxyMITM     bool   // Intercept HTTPS via a generated CA (records + scans TLS traffic)
	ProxyInsecure bool   // Skip upstream TLS verification when intercepting HTTPS
	ExportCA      string // Write the MITM CA cert to this path and exit

	// Queue
	MemBufferSize int

	// Output
	Output string

	// Catchup scan
	CatchupThreads int
	DisableCatchup bool

	// Agent warm session
	DisableWarmSession bool

	// Disable agent endpoints entirely
	NoAgent bool

	// View-only mode
	ViewOnly bool

	// Demo-only mode — expose only the narrow read-only allowlist
	DemoOnly bool

	// Disable Swagger UI
	NoSwagger bool
}

var serverOpts = &serverOptions{
	Host:        "0.0.0.0",
	ServicePort: 9002,
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start API server",
	Long: `Start the Vigolium REST API server (Fiber-based). Exposes scan endpoints, traffic ingestion, agent runs, and a Swagger UI.

Common modes:
  • Default: full API, requires the auto-generated key from config (see config ls server.api_key)
  • --view-only: read-only — no scan, ingest, or agent endpoints
  • --scan-on-receive: continuously scan ingested traffic as it arrives
  • --ingest-proxy-port: enable a transparent HTTP ingest proxy on a separate port
  • -A: disable auth (local development only)`,
	RunE: runServerCmd,
}

func init() {
	rootCmd.AddCommand(serverCmd)
	flags := serverCmd.Flags()

	// HTTP request settings (used by background scan workers)
	flags.DurationVar(&globalTimeout, "timeout", 15*time.Second, "HTTP request timeout for background scan workers (e.g. 30s, 1m)")

	// Server group
	flags.StringVar(&serverOpts.Host, "host", "0.0.0.0", "Bind address for the API server")
	flags.IntVar(&serverOpts.ServicePort, "service-port", 9002, "Port for the REST API server")
	flags.IntVar(&serverOpts.IngestProxyPort, "ingest-proxy-port", 0, "Transparent HTTP proxy port for recording traffic (0 = disabled)")
	flags.BoolVar(&serverOpts.ProxyMITM, "proxy-mitm", false,
		"Intercept HTTPS through --ingest-proxy-port using a generated CA so TLS traffic is recorded (and scanned with -S). Trust the CA printed at startup")
	flags.BoolVar(&serverOpts.ProxyInsecure, "proxy-insecure", false,
		"When intercepting HTTPS (--proxy-mitm), skip verification of the upstream server's TLS certificate")
	flags.StringVar(&serverOpts.ExportCA, "export-ca", "",
		"Write the ingest-proxy MITM CA certificate to this path and exit (generates the CA if needed)")
	flags.StringSliceVar(&serverOpts.APIKeys, "alternative-ingest-key", nil, "Additional API key for ingestion endpoints (repeatable)")
	flags.BoolVarP(&serverOpts.NoAuth, "no-auth", "A", false, "Run server without API key authentication")

	// Queue group
	flags.IntVar(&serverOpts.MemBufferSize, "mem-buffer", 10000, "In-memory queue capacity before spilling to disk")

	// Output group
	flags.StringVarP(&serverOpts.Output, "output", "o", "", "Write findings to specified output file")

	// Scan-on-receive group (runServerCmd reads these globals)
	flags.BoolVarP(&globalScanOnReceive, "scan-on-receive", "S", false,
		"Continuously scan new HTTP records as they arrive in the database")
	flags.BoolVar(&globalFullNativeScanOnReceive, "full-native-scan-on-receive", false,
		"Run the full native scan pipeline (discovery + spidering + dynamic-assessment) continuously on received records, instead of dynamic-assessment only")

	// Catchup scan group
	flags.IntVar(&serverOpts.CatchupThreads, "catchup-threads", 4,
		"Workers for background scanning of unscanned records")
	flags.BoolVar(&serverOpts.DisableCatchup, "disable-catchup", false,
		"Disable automatic background scanning of unscanned records")

	// Agent warm session
	flags.BoolVar(&serverOpts.DisableWarmSession, "disable-warm-session", false,
		"Disable agent subprocess warm session pooling")

	// Disable agent
	flags.BoolVar(&serverOpts.NoAgent, "no-agent", false,
		"Disable all agent endpoints and warm session pooling")

	// View-only mode
	flags.BoolVar(&serverOpts.ViewOnly, "view-only", false,
		"Run server in read-only mode (disables scanning, ingestion, agent, and all write endpoints)")

	// Demo-only mode
	flags.BoolVar(&serverOpts.DemoOnly, "demo-only", false,
		"Expose only the demo allowlist: GET /api/findings[/:id], /api/http-records[/:uuid], /api/modules, /api/stats, /api/extensions[/:name|/docs]")

	// Disable Swagger
	flags.BoolVar(&serverOpts.NoSwagger, "no-swagger", false,
		"Disable Swagger UI and API spec endpoint")
}

// newServerRunnerOptions builds the types.Options used by `vigolium server`
// for its scan-on-receive runner. Extracted so the shape can be unit-tested.
// Both Modules and PassiveModules MUST be "all" — omitting PassiveModules
// silently drops all 91 passive modules in server mode (regression guarded
// by pkg/cli/server_options_test.go).
func newServerRunnerOptions(so *serverOptions, concurrency, maxPerHost, maxHostError int, proxy string, verbose bool) *types.Options {
	return &types.Options{
		Concurrency:    concurrency,
		MaxPerHost:     maxPerHost,
		MaxHostError:   maxHostError,
		Timeout:        10 * time.Second,
		Retries:        1,
		Output:         so.Output,
		Verbose:        verbose,
		Silent:         true,
		ProxyURL:       proxy,
		Modules:        []string{"all"},
		PassiveModules: []string{"all"},
	}
}

// proxyCADir is the directory holding the ingest-proxy MITM CA. It resolves the
// same default the server uses (server.DefaultIngestProxyCADir) so --export-ca
// and the running proxy always agree on the CA location.
func proxyCADir() string { return config.ExpandPath(server.DefaultIngestProxyCADir) }

// exportProxyCA loads-or-creates the MITM CA and writes its certificate to dst,
// printing trust instructions. Backs the --export-ca flag.
func exportProxyCA(dst string) error {
	ca, err := mitm.LoadOrCreateCA(proxyCADir())
	if err != nil {
		return fmt.Errorf("initialize MITM CA: %w", err)
	}
	dst = config.ExpandPath(dst)
	if err := ca.ExportCert(dst); err != nil {
		return fmt.Errorf("export CA certificate: %w", err)
	}
	if !globalSilent {
		fmt.Printf("%s Ingest-proxy CA certificate written to %s\n",
			terminal.InfoSymbol(), terminal.Cyan(dst))
		fmt.Printf("  Trust it to capture HTTPS, e.g.:\n    curl --proxy http://127.0.0.1:9090 --cacert %s https://target/\n", dst)
	}
	return nil
}

// armForceQuit installs a last-resort escape hatch for a graceful shutdown that
// hangs. Once signal.Notify captures SIGINT, Go no longer terminates the
// process on Ctrl+C — so if the shutdown sequence blocks (e.g. on a stuck
// connection), further Ctrl+C presses are swallowed and only SIGKILL would end
// it. Call this right after the first shutdown signal is received: it spawns a
// goroutine that force-exits on either a second interrupt (Ctrl+C again) or a
// hard deadline that backstops the server's own shutdown timeout. sigChan must
// be the same channel signal.Notify is delivering to. The goroutine leaks
// harmlessly if shutdown completes first — the process exits and reclaims it.
func armForceQuit(sigChan <-chan os.Signal, deadline time.Duration) {
	go func() {
		select {
		case <-sigChan:
			fmt.Fprintln(os.Stderr, "\nForce quit — second interrupt received, exiting now.")
			os.Exit(1)
		case <-time.After(deadline):
			fmt.Fprintf(os.Stderr, "\nGraceful shutdown exceeded %s, forcing exit.\n", deadline)
			os.Exit(1)
		}
	}()
}

// printConfigReload renders a friendly console line when the config watcher
// hot-reloads sections at runtime, mirroring the startup banner style. Runs on
// the watcher goroutine and respects --silent. Agent reloads also echo the new
// olium provider/model so the operator can confirm the switch took effect.
func printConfigReload(settings *config.Settings, changed []string) {
	if globalSilent || len(changed) == 0 {
		return
	}
	sym := terminal.Cyan(terminal.SymbolBowtie)
	fmt.Printf("\n  %s Config reloaded: %s\n",
		sym,
		terminal.Cyan(strings.Join(changed, ", ")))
	if slices.Contains(changed, "agent") {
		fmt.Printf("  %s Agent olium (provider: %s, model: %s)\n",
			sym,
			terminal.Cyan(settings.Agent.Olium.DisplayProvider()),
			terminal.Cyan(settings.Agent.Olium.DisplayModel()))
	}
}

// printServerEndpoints renders the "where to reach me" lines shown at
// startup: one for the API base, one for the dashboard UI. Each label is
// plain (default terminal color) and padded to a common width so the URLs
// line up in a column, and the URL itself is orange so the address an
// operator wants to click stands out. When showAPIKeyHint is set, an orange
// "how to get the API key" command is printed directly below the dashboard
// line so an operator has the address and the credential together.
func printServerEndpoints(serviceAddr string, showAPIKeyHint bool) {
	port := serviceAddr[strings.LastIndex(serviceAddr, ":")+1:]
	row := func(label, value string) {
		fmt.Printf("  %s %-26s %s\n",
			terminal.InfoSymbol(),
			label,
			value)
	}
	row("Server running at", terminal.Orange(fmt.Sprintf("http://%s", serviceAddr)))
	row("Dashboard UI available at", terminal.Orange(fmt.Sprintf("http://localhost:%s/", port)))
	if showAPIKeyHint {
		row("Get the API key", terminal.Orange("vigolium config ls server.auth_api_key --force"))
	}
}

func runServerCmd(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	// --export-ca: generate (if needed) and write the MITM CA cert, then exit.
	if serverOpts.ExportCA != "" {
		return exportProxyCA(serverOpts.ExportCA)
	}

	// Load settings early so config values are available for API key resolution
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}

	// Override SQLite path if --db flag is set, matching scan/ingest/etc.
	// Without this the server ignores --db and opens the default database.
	if globalDB != "" {
		settings.Database.SQLite.Path = globalDB
	}

	// Warm sessions no longer exist — the olium engine is in-process, so
	// --disable-warm-session is a no-op retained for flag compatibility.
	_ = serverOpts.DisableWarmSession

	// Resolve API keys with priority: -A flag > --alternative-ingest-key flag > env var > config file
	var apiKeys []string
	// Whether to surface the "how to get the API key" hint at startup. Only
	// when auth is on and the operator didn't pass the key via -A (so it came
	// from env/config and they may not have it handy). Printed below the
	// dashboard line by printServerEndpoints.
	var showAPIKeyHint bool
	if serverOpts.NoAuth {
		if !globalSilent {
			fmt.Println()
			fmt.Printf("  %s %s\n", terminal.BoldRed(terminal.SymbolFailed), terminal.BoldRed("Server running WITHOUT authentication"))
			fmt.Println()
		}
	} else {
		apiKeys = serverOpts.APIKeys
		if len(apiKeys) == 0 {
			if envKey := os.Getenv("VIGOLIUM_API_KEY"); envKey != "" {
				apiKeys = []string{envKey}
			}
		}
		if len(apiKeys) == 0 && settings.Server.AuthAPIKey != "" {
			apiKeys = []string{settings.Server.AuthAPIKey}
		}
		if len(apiKeys) == 0 {
			zap.L().Fatal("No API keys configured. Set auth_api_key in config, use VIGOLIUM_API_KEY env, or pass --alternative-ingest-key")
		}
		showAPIKeyHint = len(serverOpts.APIKeys) == 0
	}

	// Initialize database for storing scan results
	var repo *database.Repository
	db, err := database.NewDB(&settings.Database)
	if err != nil {
		zap.L().Warn("Failed to create database, results won't be persisted", zap.Error(err))
	} else {
		defer func() { _ = db.Close() }()
		if err := db.CreateSchema(context.Background()); err != nil {
			zap.L().Warn("Failed to create database schema", zap.Error(err))
		} else {
			_ = db.SeedDefaults(context.Background())
			repo = database.NewRepository(db)
			if !globalSilent {
				fmt.Printf("  %s Database initialized %s\n", terminal.InfoSymbol(), terminal.Cyan(db.Driver()))
			}
		}
	}

	// Load file-based users for role-based access control.
	// Bootstrap from embedded default template on first run.
	var userStore *server.UserStore
	usersFilePath := config.ExpandPath(settings.Server.UsersFile)
	usersFileCreated := false
	if created, err := server.BootstrapUsersFile(usersFilePath, public.WorkbenchUsersJSON); err != nil {
		zap.L().Warn("Failed to bootstrap users file", zap.Error(err))
	} else {
		usersFileCreated = created
	}
	if fileUsers, err := server.LoadUsersFile(usersFilePath); err != nil {
		zap.L().Fatal("Failed to load users file", zap.String("path", usersFilePath), zap.Error(err))
	} else if fileUsers != nil {
		userStore = server.NewUserStore(fileUsers)
		// Upsert file users into DB (name/email only — access_code and role stay in memory)
		if repo != nil {
			for _, fu := range fileUsers {
				u := &database.User{
					UUID:  userStore.Lookup(fu.AccessCode).UUID,
					Name:  fu.Name,
					Email: fu.Email,
				}
				if err := repo.UpsertUser(context.Background(), u); err != nil {
					zap.L().Warn("Failed to upsert file user", zap.String("name", fu.Name), zap.Error(err))
				}
			}
		}
		if !globalSilent {
			suffix := ""
			if usersFileCreated {
				suffix = terminal.Gray(" (created default file)")
			}
			fmt.Printf("  %s Loaded %d users from %s%s\n",
				terminal.InfoSymbol(), len(fileUsers), terminal.Cyan(config.ContractPath(usersFilePath)), suffix)
		}
	}

	// Create hybrid task queue (in-memory buffer + disk spillover)
	queueDir := filepath.Join(os.TempDir(), "vigolium-server-queue")
	taskQueue, err := queue.NewQueue(queue.Config{
		Type:          queue.QueueTypeHybrid,
		DiskDir:       queueDir,
		MaxPerSegment: 10000,
		MemBufferSize: serverOpts.MemBufferSize,
	})
	if err != nil {
		zap.L().Fatal("Failed to create queue", zap.Error(err))
	}

	// Build addresses
	serviceAddr := fmt.Sprintf("%s:%d", serverOpts.Host, serverOpts.ServicePort)
	var ingestProxyAddr string
	if serverOpts.IngestProxyPort > 0 {
		ingestProxyAddr = fmt.Sprintf("%s:%d", serverOpts.Host, serverOpts.IngestProxyPort)
	}

	// Initialize HTTP requester for fetching responses during ingestion
	requesterOpts := types.DefaultOptions()
	requesterOpts.Concurrency = globalConcurrency
	requesterOpts.Timeout = globalTimeout
	requesterOpts.ProxyURL = globalProxy
	requesterOpts.Verbose = globalVerbose
	requesterOpts.Debug = globalDebug
	requesterOpts.MaxPerHost = globalMaxPerHost

	if err := network.Init(requesterOpts); err != nil {
		zap.L().Warn("Failed to initialize network for ingestion requester", zap.Error(err))
	}

	dedupMgr := dedup.NewManager()
	defer dedupMgr.Close()

	svc := &services.Services{
		Options:      requesterOpts,
		DedupManager: dedupMgr,
	}

	hostLimiter := hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{
		MaxPerHost:    requesterOpts.MaxPerHost,
		MaxEntries:    1000,
		EvictAfter:    30 * time.Second,
		EvictInterval: 10 * time.Second,
	})
	defer func() { _ = hostLimiter.Close() }()
	svc.HostLimiter = hostLimiter

	var httpRequester *http.Requester
	if !globalDisableFetchResponse {
		var reqErr error
		httpRequester, reqErr = http.NewRequester(requesterOpts, svc)
		if reqErr != nil {
			zap.L().Warn("Failed to create HTTP requester for ingestion, responses won't be fetched", zap.Error(reqErr))
		}
	}

	// Create API server
	apiServer := server.NewServer(server.ServerConfig{
		ServiceAddr:          serviceAddr,
		IngestProxyAddr:      ingestProxyAddr,
		IngestProxyMITM:      serverOpts.ProxyMITM,
		IngestProxyInsecure:  serverOpts.ProxyInsecure,
		APIKeys:              apiKeys,
		UserStore:            userStore,
		NoAuth:               serverOpts.NoAuth,
		ScanOnReceive:        globalScanOnReceive,
		DisableFetchResponse: globalDisableFetchResponse,
		Concurrency:          globalConcurrency,
		ReadTimeout:          10 * time.Second,
		WriteTimeout:         60 * time.Second,
		IdleTimeout:          120 * time.Second,
		ShutdownTimeout:      30 * time.Second,
		CORSAllowedOrigins:   settings.Server.CORSAllowedOrigins,
		EnableMetrics:        settings.Server.EnableMetrics,
		NoSwagger:            serverOpts.NoSwagger || settings.Server.DisableSwagger,
		NoAgent:              serverOpts.NoAgent,
		ViewOnly:             serverOpts.ViewOnly,
		DemoOnly:             serverOpts.DemoOnly,
		License:              settings.Server.License,
		AgentHeavyMax:        settings.Server.AgentHeavyMax,
		AgentLightMax:        settings.Server.AgentLightMax,
		AgentQueueTimeout:    parseAgentQueueTimeout(settings.Server.AgentQueueTimeout),
		Debug:                globalDebug,
		Version:              Version,
		Author:               Author,
		Commit:               Commit,
		BuildTime:            BuildTime,
		ConfigPath:           clicommon.EffectiveConfigPath(globalConfig),
	}, taskQueue, db, repo, settings, httpRequester, svc)

	// Echo a friendly console line whenever the watcher hot-reloads config
	// (e.g. after `vigolium config set agent.olium.provider ...`).
	apiServer.OnConfigReload(func(changed []string) {
		printConfigReload(settings, changed)
	})

	// In view-only or demo-only mode, print banner early and skip runner/catchup entirely
	if serverOpts.ViewOnly || serverOpts.DemoOnly {
		if !globalSilent {
			fmt.Println()
			bannerText := "View-only mode — all write endpoints disabled"
			if serverOpts.DemoOnly {
				bannerText = "Demo-only mode — exposing read-only allowlist (findings, http-records, modules, stats, extensions)"
			}
			fmt.Printf("  %s %s\n", terminal.InfoSymbol(), terminal.BoldYellow(bannerText))
			printServerEndpoints(serviceAddr, showAPIKeyHint)
			fmt.Printf("  %s Docs %s\n",
				terminal.InfoSymbol(),
				terminal.Cyan("https://docs.vigolium.com"))
			fmt.Println()
		}

		// Buffered so Start's goroutine never blocks if the main goroutine
		// already received an OS signal first.
		serverDone := make(chan error, 1)
		go func() {
			if err := apiServer.Start(); err != nil {
				zap.L().Error("API server error", zap.Error(err))
				serverDone <- err
			}
		}()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		select {
		case <-sigChan:
			zap.L().Info("Shutdown signal received")
			// A second Ctrl+C (or a hard deadline) force-exits if the graceful
			// path below hangs — SIGINT is captured now, so the OS won't.
			armForceQuit(sigChan, 35*time.Second)
		case <-serverDone:
			zap.L().Info("API server exited, shutting down")
		}

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		if err := apiServer.Shutdown(shutdownCtx); err != nil {
			zap.L().Error("API server shutdown error", zap.Error(err))
		}
		if err := taskQueue.Close(); err != nil {
			zap.L().Error("Queue close error", zap.Error(err))
		}
		zap.L().Info("Server shutdown complete")
		return nil
	}

	// --full-native-scan-on-receive implies --scan-on-receive
	if globalFullNativeScanOnReceive {
		globalScanOnReceive = true
	}

	// Create runner options (concurrency comes from global -c/--concurrency flag)
	// Phase banners are always suppressed in server mode — the server startup
	// banner provides the relevant info and the phase summaries are noise.
	runnerOpts := newServerRunnerOptions(serverOpts, globalConcurrency, globalMaxPerHost, globalMaxHostError, globalProxy, globalVerbose)

	// scan-on-receive: skip to dynamic-assessment only (records already in DB).
	// full-native-scan-on-receive: run the full native scan pipeline per batch.
	if globalFullNativeScanOnReceive {
		runnerOpts.ScanOnReceive = true
		runnerOpts.FullNativeScanOnReceive = true
	} else if globalScanOnReceive {
		runnerOpts.ScanOnReceive = true
		runnerOpts.SkipIngestion = true
	}

	// Create input source(s)
	queueSource := queue.NewQueueInputSource(taskQueue)

	var inputSource source.InputSource
	var serverScanCursorAt time.Time
	var serverScanCursorUUID string
	if globalScanOnReceive && db != nil && repo != nil {
		// Create a persistent scan record for the server session
		scanUUID := uuid.New().String()
		serverScan := &database.Scan{
			UUID:        fmt.Sprintf("scan-%s", scanUUID),
			ProjectUUID: database.DefaultProjectUUID,
			Name:        fmt.Sprintf("server-scan-on-receive-%s", scanUUID[:8]),
			Status:      "running",
			Target:      strings.Join(globalTargets, ","),
			Modules:     strings.Join(runnerOpts.Modules, ","),
			Threads:     globalConcurrency,
			ScanSource:  "scan-on-receive",
			ScanMode:    "incremental",
			StartedAt:   time.Now(),
		}
		if err := repo.CreateScanWithCursor(context.Background(), serverScan); err != nil {
			zap.L().Warn("Failed to create server scan record", zap.Error(err))
		}
		// Capture cursor position for catchup scan to detect backlog behind it
		serverScanCursorAt = serverScan.CursorAt
		serverScanCursorUUID = serverScan.CursorUUID

		// Reuse the server scan UUID so the runner tracks cursor on the same record
		runnerOpts.ScanUUID = serverScan.UUID

		// Both modes create their own DB sources internally:
		// DA-only creates a continuous poller; full-pipeline creates one-shot
		// sources per iteration. No DB input source needed at the runner level.
		inputSource = queueSource
		zap.L().Info("Scan-on-receive enabled: watching database for new records",
			zap.String("scan_uuid", serverScan.UUID),
			zap.Bool("full_pipeline", globalFullNativeScanOnReceive))
	} else {
		inputSource = queueSource
	}

	// Create runner with combined source
	// Only spin up the long-lived scan runner when the server actually needs
	// one — the scan-on-receive poller or the full-native-on-receive pipeline.
	// Without one of those, the runner's RunNativeScan creates a phantom
	// "cli-scan" DB row (internal/runner/runner.go:897) that never completes,
	// and tees stderr into a session log for a scan that will never produce
	// work. /api/scan-request, /api/scan-url, /api/scan/* all run their
	// executors inline in goroutines and don't need the shared runner.
	var scanRunner *runner.Runner
	if globalScanOnReceive || globalFullNativeScanOnReceive {
		var err error
		scanRunner, err = runner.NewWithInputSource(runnerOpts, inputSource)
		if err != nil {
			zap.L().Fatal("Failed to create runner", zap.Error(err))
		}
		scanRunner.SetSettings(settings)
		if repo != nil {
			scanRunner.SetRepository(repo)
		}
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Print startup info before starting
	if !globalSilent {
		sep := terminal.Gray("│")
		printServerEndpoints(serviceAddr, showAPIKeyHint)
		if ingestProxyAddr != "" {
			fmt.Printf("  %s Ingest proxy %s\n",
				terminal.InfoSymbol(),
				terminal.Cyan(fmt.Sprintf("http://%s", ingestProxyAddr)))
			if caPath := apiServer.ProxyCACertPath(); caPath != "" {
				fmt.Printf("  %s HTTPS intercept %s  %s trust %s\n",
					terminal.InfoSymbol(),
					terminal.Cyan("on"),
					sep,
					terminal.Cyan(fmt.Sprintf("curl --cacert %s", caPath)))
			}
		} else if serverOpts.ProxyMITM {
			fmt.Printf("  %s %s --proxy-mitm has no effect without --ingest-proxy-port\n",
				terminal.WarningSymbol(), terminal.Yellow("warning:"))
		}
		if globalScanOnReceive && !serverOpts.DisableCatchup {
			fmt.Printf("  %s Scan workers %s  %s Catchup workers %s\n",
				terminal.InfoSymbol(),
				terminal.Cyan(fmt.Sprintf("%d", globalConcurrency)),
				sep,
				terminal.Cyan(fmt.Sprintf("%d (starts in 5s)", serverOpts.CatchupThreads)))
		} else {
			fmt.Printf("  %s Scan workers %s\n",
				terminal.InfoSymbol(),
				terminal.Cyan(fmt.Sprintf("%d", globalConcurrency)))
		}
		if globalScanOnReceive {
			moduleCount := modules.DefaultRegistry.ActiveModuleCount() + modules.DefaultRegistry.PassiveModuleCount()
			label := "enabled (polls unscanned ingested requests)"
			if globalFullNativeScanOnReceive {
				label = "full-native (discovery + spidering + dynamic-assessment per batch)"
			}
			fmt.Printf("  %s Scan-on-receive: %s  %s %s modules\n",
				terminal.InfoSymbol(),
				terminal.Cyan(label),
				terminal.Gray("│"),
				terminal.Cyan(fmt.Sprintf("%d", moduleCount)))
		} else {
			fmt.Printf("  %s Scan-on-receive %s\n",
				terminal.InfoSymbol(),
				terminal.BoldYellow("disabled"))
		}
		if serverOpts.NoAgent {
			fmt.Printf("  %s %s\n", terminal.InfoSymbol(), terminal.BoldYellow("Agent disabled — all agent endpoints skipped"))
		} else {
			fmt.Printf("  %s Agent olium (provider: %s, model: %s)\n",
				terminal.InfoSymbol(),
				terminal.Cyan(settings.Agent.Olium.DisplayProvider()),
				terminal.Cyan(settings.Agent.Olium.DisplayModel()))
		}
		fmt.Printf("  %s Docs %s\n",
			terminal.InfoSymbol(),
			terminal.Cyan("https://docs.vigolium.com"))
		fmt.Println()
	}

	// Start API server. A non-nil return from Listen means the HTTP server
	// died (port in use, internal panic, etc.). Log it and cancel the root
	// context so the main goroutine drops into the graceful-shutdown path
	// below instead of yanking the process down with os.Exit.
	go func() {
		if err := apiServer.Start(); err != nil {
			zap.L().Error("API server error", zap.Error(err))
			cancel()
		}
	}()

	// Start workers only when a runner was created (scan-on-receive or
	// full-native-on-receive). Plain API-only mode has no runner to start.
	if scanRunner != nil {
		go func() {
			if err := scanRunner.RunNativeScan(); err != nil {
				zap.L().Error("Runner error", zap.Error(err))
			}
		}()
	}

	// Launch background catchup scan for unscanned backlog records
	var catchupMu sync.Mutex
	var catchupRunner *runner.Runner
	if globalScanOnReceive && db != nil && repo != nil && !serverOpts.DisableCatchup {
		go func() {
			// 5-second cancellable delay — allows user to see startup and Ctrl+C if needed
			select {
			case <-time.After(5 * time.Second):
			case <-ctx.Done():
				return
			}

			cr := startCatchupScan(ctx, db, repo, settings,
				serverScanCursorAt, serverScanCursorUUID,
				serverOpts.CatchupThreads, runnerOpts)

			catchupMu.Lock()
			catchupRunner = cr
			catchupMu.Unlock()
		}()
	}

	// Wait for shutdown signal — either an OS signal or the API server
	// goroutine cancelling the root context after a Listen error.
	select {
	case <-sigChan:
		zap.L().Info("Shutdown signal received, initiating graceful shutdown...")
		// A second Ctrl+C (or a hard deadline) force-exits if the graceful
		// path below hangs — SIGINT is captured now, so the OS won't.
		armForceQuit(sigChan, 35*time.Second)
	case <-ctx.Done():
		zap.L().Info("Context cancelled, initiating graceful shutdown...")
		// No OS signal yet (Listen error path), but the operator may still
		// Ctrl+C during a slow shutdown — arm the same escape hatch.
		armForceQuit(sigChan, 35*time.Second)
	}

	// Cancel context (idempotent; safe if already cancelled above)
	cancel()

	// Close catchup runner if running
	catchupMu.Lock()
	cr := catchupRunner
	catchupMu.Unlock()
	if cr != nil {
		zap.L().Info("Stopping catchup scan...")
		cr.Close()
	}

	// Close runner first (stops workers from dequeuing). Only present when
	// scan-on-receive or full-native-on-receive was enabled.
	if scanRunner != nil {
		scanRunner.Close()
	}

	// Shutdown API server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		zap.L().Error("API server shutdown error", zap.Error(err))
	}

	// Close queue last
	if err := taskQueue.Close(); err != nil {
		zap.L().Error("Queue close error", zap.Error(err))
	}

	zap.L().Info("Server shutdown complete")
	return nil
}

// startCatchupScan checks for unscanned backlog records behind the server scan's
// cursor and launches a separate runner to scan them at reduced concurrency.
// Returns the runner (for shutdown) or nil if no backlog exists.
func startCatchupScan(
	ctx context.Context,
	db *database.DB,
	repo *database.Repository,
	settings *config.Settings,
	cursorAt time.Time,
	cursorUUID string,
	catchupThreads int,
	baseOpts *types.Options,
) *runner.Runner {
	// Check if there are records behind the server scan's cursor
	backlog, err := repo.CountRecordsAfterCursor(ctx, time.Time{}, "")
	if err != nil {
		zap.L().Warn("Failed to check backlog records", zap.Error(err))
		return nil
	}

	// Count records that the live scan will handle (after cursor)
	liveCount, err := repo.CountRecordsAfterCursor(ctx, cursorAt, cursorUUID)
	if err != nil {
		zap.L().Warn("Failed to count live records", zap.Error(err))
		return nil
	}

	// Backlog = total records minus what the live scan will process
	backlogCount := backlog - liveCount
	if backlogCount <= 0 {
		zap.L().Info("No backlog records to catch up on")
		return nil
	}

	zap.L().Info("Checking for unscanned backlog records...",
		zap.Int64("backlog_count", backlogCount))

	// Create a separate scan record for the catchup
	catchupScan := &database.Scan{
		UUID:        fmt.Sprintf("server-catchup-%d", time.Now().UnixNano()),
		ProjectUUID: database.DefaultProjectUUID,
		Name:        "server-catchup",
		Status:      "running",
		Target:      strings.Join(globalTargets, ","),
		Modules:     strings.Join(baseOpts.Modules, ","),
		ScanSource:  "server-catchup",
		ScanMode:    "incremental",
		StartedAt:   time.Now(),
	}
	if err := repo.CreateScanWithCursor(ctx, catchupScan); err != nil {
		zap.L().Warn("Failed to create catchup scan record", zap.Error(err))
		return nil
	}

	// Re-check how many records the catchup scan needs to process (after cursor copy)
	remaining, err := repo.CountRecordsAfterCursor(ctx, catchupScan.CursorAt, catchupScan.CursorUUID)
	if err != nil {
		zap.L().Warn("Failed to count catchup records", zap.Error(err))
		return nil
	}
	if remaining <= 0 {
		zap.L().Info("No backlog records to catch up on (already scanned)")
		_ = repo.CompleteScan(ctx, catchupScan.UUID, "")
		return nil
	}

	// Create one-shot input source — returns io.EOF when cursor catches up
	catchupSource := database.NewOneShotDBInputSource(db, repo, catchupScan.UUID)

	// Build runner options with reduced concurrency
	catchupOpts := &types.Options{
		Concurrency:    catchupThreads,
		MaxPerHost:     baseOpts.MaxPerHost,
		MaxHostError:   baseOpts.MaxHostError,
		Timeout:        baseOpts.Timeout,
		Retries:        baseOpts.Retries,
		Verbose:        baseOpts.Verbose,
		Silent:         baseOpts.Silent,
		ProxyURL:       baseOpts.ProxyURL,
		Modules:        baseOpts.Modules,
		PassiveModules: baseOpts.PassiveModules,
	}

	catchupRunner, err := runner.NewWithInputSource(catchupOpts, catchupSource)
	if err != nil {
		zap.L().Warn("Failed to create catchup runner", zap.Error(err))
		_ = repo.CompleteScan(ctx, catchupScan.UUID, err.Error())
		return nil
	}

	catchupRunner.SetSettings(settings)
	catchupRunner.SetRepository(repo)

	scanUUID := catchupScan.UUID
	zap.L().Info("Catchup scan started",
		zap.String("scan_uuid", scanUUID),
		zap.Int("workers", catchupThreads),
		zap.Int64("backlog_records", remaining))

	go func() {
		var errMsg string
		if err := catchupRunner.RunNativeScan(); err != nil {
			zap.L().Error("Catchup scan error", zap.Error(err))
			errMsg = err.Error()
		}
		if completeErr := repo.CompleteScan(context.Background(), scanUUID, errMsg); completeErr != nil {
			zap.L().Error("Failed to complete catchup scan record", zap.Error(completeErr))
		}
		webhook.FireNativeScan(settings, repo, scanUUID)
		if errMsg == "" {
			zap.L().Info("Catchup scan completed", zap.String("scan_uuid", scanUUID))
		}
	}()

	return catchupRunner
}

// parseAgentQueueTimeout parses a Go duration string for the agent queue timeout.
// Returns 0 (triggering the runtime default of 30s) on empty or invalid input.
func parseAgentQueueTimeout(s string) time.Duration {
	if s == "" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d
}
