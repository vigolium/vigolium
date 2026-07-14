package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/burpbridge"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
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
	BurpBridgeURL   string
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

	// MirrorFS, when set, mirrors ingested traffic + findings to this directory
	// as a live filesystem tree (in addition to the database).
	MirrorFS string

	// PassiveOnly, with -S/--scan-on-receive, restricts scanning to passive
	// modules only (no active scan traffic; includes secret detection).
	PassiveOnly bool

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
  • --burp-bridge-url: merge live Burp Proxy history into the normal HTTP records API
  • --scan-on-receive: continuously scan ingested traffic as it arrives
  • --ingest-proxy-port: enable a transparent HTTP ingest proxy on a separate port
  • -A: disable auth (local development only)`,
	Args: cobra.NoArgs,
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
	flags.StringVar(
		&serverOpts.BurpBridgeURL,
		"burp-bridge-url",
		burpbridge.URLFromEnvironment(),
		"Merge live Burp traffic from this loopback bridge URL into /api/http-records")
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
	flags.StringVar(&serverOpts.MirrorFS, "mirror-fs", "",
		"Mirror ingested traffic + findings to a live flat filesystem tree under this dir (<dir>/traffic, <dir>/findings), in addition to the database — readable by an external agent with ls/grep/jq")

	// Scan-on-receive group (runServerCmd reads these globals)
	flags.BoolVarP(&globalScanOnReceive, "scan-on-receive", "S", false,
		"Continuously scan new HTTP records as they arrive in the database")
	flags.BoolVar(&globalFullNativeScanOnReceive, "full-native-scan-on-receive", false,
		"Run the full native scan pipeline (discovery + spidering + dynamic-assessment) continuously on received records, instead of dynamic-assessment only")
	flags.BoolVar(&serverOpts.PassiveOnly, "passive-only", false,
		"With -S/--scan-on-receive, run passive modules only (no active scan traffic; includes secret detection)")

	// Catchup scan group (deprecated: catch-up is disabled — the live
	// scan-on-receive scanner already covers post-cursor records; these flags are
	// accepted for compatibility but no longer have any effect).
	flags.IntVar(&serverOpts.CatchupThreads, "catchup-threads", 4,
		"Deprecated: no-op (catch-up scanning is disabled)")
	flags.BoolVar(&serverOpts.DisableCatchup, "disable-catchup", false,
		"Deprecated: no-op (catch-up scanning is already disabled)")

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
// PassiveModules MUST be "all" — omitting it silently drops all passive
// modules in server mode (regression guarded by pkg/cli/server_options_test.go).
// Modules is "all" by default; with so.PassiveOnly it is left empty so the
// runner (internal/runner/runner_modules.go) resolves zero active modules,
// yielding a passive-only scan that still sends no active traffic.
func newServerRunnerOptions(so *serverOptions, concurrency, maxPerHost, maxHostError int, proxy string, verbose bool) *types.Options {
	activeModules := []string{"all"}
	if so.PassiveOnly {
		activeModules = nil
	}
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
		Modules:        activeModules,
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

// initServerDatabase opens the results database and creates its schema, returning
// the live handle and repository on success. It returns (nil, nil) in every
// degraded case: the connection couldn't be opened, or — crucially — the
// connection opened but schema creation failed (a locked, read-only, disk-full,
// or schema-incompatible database). That second case previously returned a
// non-nil db with a nil repo, which the repo-backed API handlers dereferenced
// into nil-pointer panics (HTTP 500 on /api/scans, /api/projects, etc.). Folding
// it into the same no-persistence path keeps the whole server consistently
// DB-less so those handlers return a clean 503. The caller owns closing a
// non-nil returned db.
func initServerDatabase(cfg *config.DatabaseConfig, silent bool) (*database.DB, *database.Repository) {
	db, err := database.NewDB(cfg)
	if err != nil {
		zap.L().Warn("Failed to create database, results won't be persisted", zap.Error(err))
		return nil, nil
	}
	if err := db.CreateSchema(context.Background()); err != nil {
		zap.L().Error("Failed to create database schema; running without persistence", zap.Error(err))
		if !silent {
			fmt.Printf("  %s Database schema init failed: %v (running without persistence)\n",
				terminal.WarningSymbol(), err)
		}
		_ = db.Close()
		return nil, nil
	}
	_ = db.SeedDefaults(context.Background())
	if !silent {
		fmt.Printf("  %s Database initialized %s\n", terminal.InfoSymbol(), terminal.Cyan(db.Driver()))
	}
	return db, database.NewRepository(db)
}

func runServerCmd(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	if serverOpts.BurpBridgeURL != "" {
		validated, err := burpbridge.ValidateURL(serverOpts.BurpBridgeURL)
		if err != nil {
			return fmt.Errorf("--burp-bridge-url: %w", err)
		}
		serverOpts.BurpBridgeURL = validated
	}

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

	// Initialize database for storing scan results. initServerDatabase collapses a
	// half-initialized DB (connection opened but schema creation failed) into the
	// same no-persistence mode as an open failure, so the server never runs with a
	// live db handle paired with a nil repository — a state every repo-backed API
	// handler would nil-pointer panic on (HTTP 500 instead of a clean 503).
	db, repo := initServerDatabase(&settings.Database, globalSilent)
	if db != nil {
		defer func() { _ = db.Close() }()
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

	// Task queue. Only scan-on-receive / full-native-on-receive actually run a
	// consumer for it; every other server mode leaves it without a producer or
	// consumer, so opening a LevelDB-backed hybrid queue there would only spawn
	// idle drainer/cleanup goroutines and take an on-disk lock that blocks a second
	// server instance on the same host. Use a zero-cost in-memory queue in that
	// case, and give the durable queue a PID-scoped directory otherwise so two
	// instances don't contend on the shared /tmp path.
	var taskQueue queue.Queue
	if globalScanOnReceive || globalFullNativeScanOnReceive {
		queueDir := filepath.Join(os.TempDir(), fmt.Sprintf("vigolium-server-queue-%d", os.Getpid()))
		taskQueue, err = queue.NewQueue(queue.Config{
			Type:          queue.QueueTypeHybrid,
			DiskDir:       queueDir,
			MaxPerSegment: 10000,
			MemBufferSize: serverOpts.MemBufferSize,
		})
	} else {
		taskQueue, err = queue.NewQueue(queue.Config{
			Type:          queue.QueueTypeMemory,
			MemBufferSize: serverOpts.MemBufferSize,
		})
	}
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
	requesterOpts.NoWafPacing = globalNoWafPacing

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
		BurpBridgeURL:        serverOpts.BurpBridgeURL,
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
		// WriteTimeout MUST be 0 (no deadline): agent/audit SSE streams and other
		// long-lived responses routinely run for many minutes, and a non-zero
		// WriteTimeout severs them mid-stream. This matches DefaultServerConfig's
		// contract; IdleTimeout + per-handler deadlines bound non-streaming work.
		WriteTimeout:       0,
		IdleTimeout:        120 * time.Second,
		ShutdownTimeout:    30 * time.Second,
		CORSAllowedOrigins: settings.Server.CORSAllowedOrigins,
		EnableMetrics:      settings.Server.EnableMetrics,
		NoSwagger:          serverOpts.NoSwagger || settings.Server.DisableSwagger,
		NoAgent:            serverOpts.NoAgent,
		ViewOnly:           serverOpts.ViewOnly,
		DemoOnly:           serverOpts.DemoOnly,
		License:            settings.Server.License,
		MirrorFSPath:       firstNonEmptyString(serverOpts.MirrorFS, settings.Server.MirrorFSPath),
		AgentHeavyMax:      settings.Server.AgentHeavyMax,
		AgentLightMax:      settings.Server.AgentLightMax,
		AgentQueueTimeout:  parseAgentQueueTimeout(settings.Server.AgentQueueTimeout),
		Debug:              globalDebug,
		Version:            Version,
		Author:             Author,
		Commit:             Commit,
		BuildTime:          BuildTime,
		ConfigPath:         clicommon.EffectiveConfigPath(globalConfig),
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

	// --passive-only zeroes active modules, but --full-native-scan-on-receive
	// still runs discovery + spidering, which actively crawl (send requests).
	// Warn but allow: passive modules run on the crawled + ingested traffic.
	if serverOpts.PassiveOnly && globalFullNativeScanOnReceive {
		zap.L().Warn("--passive-only zeroes active scan modules, but --full-native-scan-on-receive still crawls (discovery + spidering send requests); for zero active traffic use --scan-on-receive without --full-native-scan-on-receive")
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
		if serverOpts.BurpBridgeURL != "" {
			fmt.Printf("  %s Burp traffic source %s\n",
				terminal.InfoSymbol(),
				terminal.Cyan(serverOpts.BurpBridgeURL))
		}
		if globalScanOnReceive {
			// Catch-up is disabled (see startCatchupScan); only the live workers run.
			fmt.Printf("  %s Scan workers %s\n",
				terminal.InfoSymbol(),
				terminal.Cyan(fmt.Sprintf("%d", globalConcurrency)))
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

	// Catch-up scanning is disabled — the previous implementation re-scanned the
	// live scan-on-receive range instead of the historical backlog it detected, so
	// it only ever produced duplicate work. The live incremental scanner already
	// covers post-cursor records; scan a pre-existing database explicitly with
	// `vigolium scan`. The --catchup-threads/--disable-catchup flags are accepted
	// (deprecated) but ignored.

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
