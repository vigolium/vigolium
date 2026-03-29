package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/public"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/queue"
	"github.com/vigolium/vigolium/pkg/server"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/spf13/cobra"
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

	// Queue
	MemBufferSize int

	// Output
	Output string

	// Catchup scan
	CatchupThreads int
	DisableCatchup bool

	// Agent warm session
	DisableWarmSession bool

	// Agent ACP command override
	AgentACPCmd string

	// Disable agent endpoints entirely
	NoAgent bool

	// View-only mode
	ViewOnly bool
}

var serverOpts = &serverOptions{
	Host:        "0.0.0.0",
	ServicePort: 9002,
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start API server",
	RunE:  runServerCmd,
}

func init() {
	rootCmd.AddCommand(serverCmd)
	flags := serverCmd.Flags()

	// Server group
	flags.StringVar(&serverOpts.Host, "host", "0.0.0.0", "Bind address for the API server")
	flags.IntVar(&serverOpts.ServicePort, "service-port", 9002, "Port for the REST API server")
	flags.IntVar(&serverOpts.IngestProxyPort, "ingest-proxy-port", 0, "Transparent HTTP proxy port for recording traffic (0 = disabled)")
	flags.StringSliceVar(&serverOpts.APIKeys, "alternative-ingest-key", nil, "Additional API key for ingestion endpoints (repeatable)")
	flags.BoolVarP(&serverOpts.NoAuth, "no-auth", "A", false, "Run server without API key authentication")

	// Queue group
	flags.IntVar(&serverOpts.MemBufferSize, "mem-buffer", 10000, "In-memory queue capacity before spilling to disk")

	// Output group
	flags.StringVarP(&serverOpts.Output, "output", "o", "", "Write findings to specified output file")

	// Catchup scan group
	flags.IntVar(&serverOpts.CatchupThreads, "catchup-threads", 4,
		"Workers for background scanning of unscanned records")
	flags.BoolVar(&serverOpts.DisableCatchup, "disable-catchup", false,
		"Disable automatic background scanning of unscanned records")

	// Agent warm session
	flags.BoolVar(&serverOpts.DisableWarmSession, "disable-warm-session", false,
		"Disable agent subprocess warm session pooling")

	// Agent ACP command override
	flags.StringVar(&serverOpts.AgentACPCmd, "agent-acp-cmd", "",
		"Custom ACP agent command for all agent runs (e.g. 'traecli acp')")

	// Disable agent
	flags.BoolVar(&serverOpts.NoAgent, "no-agent", false,
		"Disable all agent endpoints and warm session pooling")

	// View-only mode
	flags.BoolVar(&serverOpts.ViewOnly, "view-only", false,
		"Run server in read-only mode (disables scanning, ingestion, agent, and all write endpoints)")
}

func runServerCmd(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	// Load settings early so config values are available for API key resolution
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}

	// When --no-agent is set, force-disable warm sessions and skip ACP command registration.
	if serverOpts.NoAgent {
		f := false
		settings.Agent.WarmSession.Enable = &f
	} else {
		// Auto-enable warm sessions in server mode unless explicitly disabled via flag.
		// The server runs in the background anyway, so warm sessions are a natural fit.
		if serverOpts.DisableWarmSession {
			f := false
			settings.Agent.WarmSession.Enable = &f
		} else if !settings.Agent.WarmSession.IsEnabled() {
			t := true
			settings.Agent.WarmSession.Enable = &t
		}
	}

	// Register ad-hoc ACP agent command and set it as default when --agent-acp-cmd is provided.
	// This makes all API agent requests use the custom command by default, including warm sessions.
	if serverOpts.AgentACPCmd != "" && !serverOpts.NoAgent {
		if def := agent.ParseACPCmd(serverOpts.AgentACPCmd); def != nil {
			def.Description = "Custom ACP agent from --agent-acp-cmd"
			if settings.Agent.Backends == nil {
				settings.Agent.Backends = make(map[string]config.AgentDef)
			}
			settings.Agent.Backends["custom-acp"] = *def
			settings.Agent.DefaultAgent = "custom-acp"
		}
	}

	// Resolve API keys with priority: -A flag > --alternative-ingest-key flag > env var > config file
	var apiKeys []string
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
		if !globalSilent && len(serverOpts.APIKeys) == 0 {
			fmt.Printf("  %s To view your API key: %s\n",
				terminal.InfoSymbol(),
				terminal.Cyan("vigolium config view server.auth_api_key --force"))
		}
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
	if created, err := server.BootstrapUsersFile(usersFilePath, public.DefaultUsersJSON); err != nil {
		zap.L().Warn("Failed to bootstrap users file", zap.Error(err))
	} else if created && !globalSilent {
		fmt.Printf("  %s Created default users file at %s\n",
			terminal.InfoSymbol(), terminal.Cyan(config.ContractPath(usersFilePath)))
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
			fmt.Printf("  %s Loaded %d users from %s\n",
				terminal.InfoSymbol(), len(fileUsers), terminal.Cyan(config.ContractPath(usersFilePath)))
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
		NoAgent:              serverOpts.NoAgent,
		ViewOnly:             serverOpts.ViewOnly,
		Debug:                globalDebug,
		Version:              Version,
		Author:               Author,
		Commit:               Commit,
		BuildTime:            BuildTime,
	}, taskQueue, db, repo, settings, httpRequester)

	// In view-only mode, print banner early and skip runner/catchup entirely
	if serverOpts.ViewOnly {
		if !globalSilent {
			fmt.Println()
			fmt.Printf("  %s %s\n", terminal.InfoSymbol(), terminal.BoldYellow("View-only mode — all write endpoints disabled"))
			port := serviceAddr[strings.LastIndex(serviceAddr, ":")+1:]
			fmt.Printf("  %s Starting vigolium server %s and %s\n",
				terminal.InfoSymbol(),
				terminal.Cyan(fmt.Sprintf("http://%s", serviceAddr)),
				terminal.Cyan(fmt.Sprintf("http://localhost:%s", port)))
			fmt.Printf("  %s UI Dashboard %s\n",
				terminal.InfoSymbol(),
				terminal.Cyan(fmt.Sprintf("http://localhost:%s/", port)))
			fmt.Printf("  %s Docs %s\n",
				terminal.InfoSymbol(),
				terminal.Cyan("https://docs.vigolium.com"))
			fmt.Println()
		}

		go func() {
			if err := apiServer.Start(); err != nil {
				zap.L().Fatal("API server error", zap.Error(err))
			}
		}()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		zap.L().Info("Shutdown signal received")

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

	// Create runner options (concurrency comes from global -c/--concurrency flag)
	// Phase banners are always suppressed in server mode — the server startup
	// banner provides the relevant info and the phase summaries are noise.
	runnerOpts := &types.Options{
		Concurrency:  globalConcurrency,
		MaxPerHost:   globalMaxPerHost,
		MaxHostError: globalMaxHostError,
		Timeout:      10 * time.Second,
		Retries:      1,
		Output:       serverOpts.Output,
		Verbose:      globalVerbose,
		Silent:       true,
		ProxyURL:     globalProxy,
		Modules:      []string{"all"},
	}

	// Create input source(s)
	queueSource := queue.NewQueueInputSource(taskQueue)

	var inputSource source.InputSource
	var serverScanCursorAt time.Time
	var serverScanCursorUUID string
	if globalScanOnReceive && db != nil && repo != nil {
		// Create a persistent scan record for the server session
		serverScan := &database.Scan{
			UUID:        fmt.Sprintf("server-scan-%d", time.Now().UnixNano()),
			ProjectUUID: database.DefaultProjectUUID,
			Name:        "server-scan-on-receive",
			Status:      "running",
			Modules:     strings.Join(runnerOpts.Modules, ","),
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
		dbSource := database.NewDBInputSource(db, repo, serverScan.UUID, 2*time.Second)
		inputSource = source.NewConcurrentMultiSource(queueSource, dbSource)
		zap.L().Info("Scan-on-receive enabled: watching database for new records",
			zap.String("scan_uuid", serverScan.UUID))
	} else {
		inputSource = queueSource
	}

	// Create runner with combined source
	scanRunner, err := runner.NewWithInputSource(runnerOpts, inputSource)
	if err != nil {
		zap.L().Fatal("Failed to create runner", zap.Error(err))
	}

	// Pass settings and repository to runner
	scanRunner.SetSettings(settings)
	if repo != nil {
		scanRunner.SetRepository(repo)
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Print startup info before starting
	if !globalSilent {
		port := serviceAddr[strings.LastIndex(serviceAddr, ":")+1:]
		fmt.Printf("  %s Starting vigolium server %s and %s\n",
			terminal.InfoSymbol(),
			terminal.Cyan(fmt.Sprintf("http://%s", serviceAddr)),
			terminal.Cyan(fmt.Sprintf("http://localhost:%s", port)))
		fmt.Printf("  %s UI Dashboard %s\n",
			terminal.InfoSymbol(),
			terminal.Cyan(fmt.Sprintf("http://localhost:%s/", port)))
		if ingestProxyAddr != "" {
			fmt.Printf("  %s Ingest proxy %s\n",
				terminal.InfoSymbol(),
				terminal.Cyan(fmt.Sprintf("http://%s", ingestProxyAddr)))
		}
		fmt.Printf("  %s Workers %s\n",
			terminal.InfoSymbol(),
			terminal.Cyan(fmt.Sprintf("%d", globalConcurrency)))
		if serverOpts.NoAgent {
			fmt.Printf("  %s %s\n", terminal.InfoSymbol(), terminal.BoldYellow("Agent disabled — all agent endpoints skipped"))
		} else if agentName := settings.Agent.DefaultAgent; agentName != "" {
			if agentDef, ok := settings.Agent.Backends[agentName]; ok {
				warmLabel := "off"
				if settings.Agent.WarmSession.IsEnabled() {
					warmLabel = "on"
				}
				fmt.Printf("  %s Agent %s (protocol: %s, warm: %s)\n",
					terminal.InfoSymbol(),
					terminal.Cyan(agentName),
					terminal.Cyan(agentDef.EffectiveProtocol()),
					terminal.Cyan(warmLabel))
			}
		}
		if globalScanOnReceive && !serverOpts.DisableCatchup {
			fmt.Printf("  %s Catchup scan %s (starts in 5s)\n",
				terminal.InfoSymbol(),
				terminal.Cyan(fmt.Sprintf("%d workers", serverOpts.CatchupThreads)))
		}
		fmt.Printf("  %s Docs %s\n",
			terminal.InfoSymbol(),
			terminal.Cyan("https://docs.vigolium.com"))
		fmt.Println()
	}

	// Start API server
	go func() {
		if err := apiServer.Start(); err != nil {
			zap.L().Fatal("API server error", zap.Error(err))
		}
	}()

	// Start workers
	go func() {
		if err := scanRunner.RunNativeScan(); err != nil {
			zap.L().Error("Runner error", zap.Error(err))
		}
	}()

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

	// Wait for shutdown signal
	<-sigChan
	zap.L().Info("Shutdown signal received, initiating graceful shutdown...")

	// Cancel context
	cancel()

	// Close catchup runner if running
	catchupMu.Lock()
	cr := catchupRunner
	catchupMu.Unlock()
	if cr != nil {
		zap.L().Info("Stopping catchup scan...")
		cr.Close()
	}

	// Close runner first (stops workers from dequeuing)
	scanRunner.Close()

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
		Concurrency:  catchupThreads,
		MaxPerHost:   baseOpts.MaxPerHost,
		MaxHostError: baseOpts.MaxHostError,
		Timeout:      baseOpts.Timeout,
		Retries:      baseOpts.Retries,
		Verbose:      baseOpts.Verbose,
		Silent:       baseOpts.Silent,
		ProxyURL:     baseOpts.ProxyURL,
		Modules:      baseOpts.Modules,
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
		if errMsg == "" {
			zap.L().Info("Catchup scan completed", zap.String("scan_uuid", scanUUID))
		}
	}()

	return catchupRunner
}
