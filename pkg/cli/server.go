package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

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
	"github.com/vigolium/vigolium/pkg/output"
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
	// IngestProxyHost is the ingest proxy's bind address, independent of
	// Host so exposing the API never exposes an open forward proxy with it.
	IngestProxyHost string
	// ProxyToken / ProxyAllow gate the ingest proxy (see server.ProxyAuth).
	ProxyToken string
	ProxyAllow []string
	APIKeys    []string
	NoAuth     bool

	// Ingest-proxy TLS interception (MITM)
	ProxyMITM     bool   // Intercept HTTPS via a generated CA (records + scans TLS traffic)
	ProxyInsecure bool   // Skip upstream TLS verification when intercepting HTTPS
	ExportCA      string // Write the MITM CA cert to this path and exit

	// Queue
	MemBufferSize int
	// DiscardQueued drops whatever a previous run left in the disk-spill
	// queue instead of resuming it.
	DiscardQueued bool

	// Output
	Output string

	// MirrorFS, when set, mirrors ingested traffic + findings to this directory
	// as a live filesystem tree (in addition to the database).
	MirrorFS string

	// PassiveOnly, with --scan-on-receive, restricts scanning to passive
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
	Host:        defaultServerHost,
	ServicePort: 9002,
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Serve the REST API, ingest live traffic, and scan it as it arrives",
	Long: `Start the Vigolium REST API server (Fiber-based). Exposes scan endpoints, traffic ingestion, agent runs, and a Swagger UI.

Common modes:
  • Default: full API, requires the auto-generated key from config (see config ls server.auth_api_key --force)
  • --view-only: read-only — no scan, ingest, or agent endpoints
  • --burp-bridge-url (alias --caido-bridge-url): merge live Burp/Caido proxy history into the normal HTTP records API
  • --scan-on-receive: continuously scan ingested traffic as it arrives
  • --ingest-proxy-port: enable a transparent HTTP ingest proxy on a separate port (binds --ingest-proxy-host, default 127.0.0.1)
  • -A: disable auth (local development only)

Both listeners bind 127.0.0.1 by default. --host 0.0.0.0 (or $VIGOLIUM_SERVER_HOST) exposes the API.
A routable --ingest-proxy-host needs --proxy-token and/or --proxy-allow, or the server refuses to start.
The MITM CA is managed with 'vigolium server ca print|path|install|uninstall'.`,
	Args: cobra.NoArgs,
	RunE: runServerCmd,
}

func init() {
	rootCmd.AddCommand(serverCmd)
	flags := serverCmd.Flags()

	// HTTP request settings (used by background scan workers)
	flags.DurationVar(&globalTimeout, "timeout", 15*time.Second, "HTTP request timeout for background scan workers (e.g. 30s, 1m)")

	// Server group
	flags.StringVar(&serverOpts.Host, "host", defaultServerHost,
		"Bind address for the API server ($"+serverHostEnv+" when unset; use 0.0.0.0 to expose it)")
	flags.IntVar(&serverOpts.ServicePort, "service-port", 9002, "Port for the REST API server")
	registerBridgeURLFlag(serverCmd, &serverOpts.BurpBridgeURL,
		"Merge live proxy traffic from this loopback Burp/Caido bridge URL into /api/http-records")
	flags.IntVar(&serverOpts.IngestProxyPort, "ingest-proxy-port", 0, "Transparent HTTP proxy port for recording traffic (0 = disabled)")
	flags.StringVar(&serverOpts.IngestProxyHost, "ingest-proxy-host", server.DefaultIngestProxyHost,
		"Bind address for the ingest proxy (config server.ingest_proxy_host). A non-loopback address needs --proxy-token or --proxy-allow")
	flags.StringVar(&serverOpts.ProxyToken, "proxy-token", "",
		"Require this secret on every ingest-proxy request as Proxy-Authorization (Basic with any username, or Bearer); config server.ingest_proxy_token")
	flags.StringArrayVar(&serverOpts.ProxyAllow, "proxy-allow", nil,
		"Accept ingest-proxy clients only from this CIDR or IP (repeatable; config server.ingest_proxy_allow)")
	flags.BoolVar(&serverOpts.ProxyMITM, "proxy-mitm", false,
		"Intercept HTTPS through --ingest-proxy-port using a generated CA so TLS traffic is recorded (and scanned with --scan-on-receive). Trust it with 'vigolium server ca install'")
	flags.BoolVar(&serverOpts.ProxyInsecure, "proxy-insecure", false,
		"When intercepting HTTPS (--proxy-mitm), skip verification of the upstream server's TLS certificate")
	flags.StringVar(&serverOpts.ExportCA, "export-ca", "",
		"Write the ingest-proxy MITM CA certificate to this path and exit (alias of 'server ca print --out')")
	_ = flags.MarkHidden("export-ca")
	flags.StringSliceVar(&serverOpts.APIKeys, "alternative-ingest-key", nil, "Additional API key for ingestion endpoints (repeatable)")
	flags.BoolVarP(&serverOpts.NoAuth, "no-auth", "A", false, "Run server without API key authentication")

	// Queue group
	flags.IntVar(&serverOpts.MemBufferSize, "mem-buffer", 10000, "In-memory queue capacity before spilling to disk")
	flags.BoolVar(&serverOpts.DiscardQueued, "discard-queued", false,
		"Drop tasks a previous run left in the disk-spill queue instead of resuming them (tasks older than 24h are always dropped)")

	// Output group
	flags.StringVarP(&serverOpts.Output, "output", "o", "", "Write findings to specified output file")
	flags.StringVar(&serverOpts.MirrorFS, "mirror-fs", "",
		"Mirror ingested traffic + findings to a live flat filesystem tree under this dir (<dir>/traffic, <dir>/findings), in addition to the database — readable by an external agent with ls/grep/jq")

	// Scan-on-receive group (runServerCmd reads these globals)
	registerScanOnReceiveFlags(flags,
		"Continuously scan new HTTP records as they arrive in the database")
	flags.BoolVar(&globalFullNativeScanOnReceive, "full-native-scan-on-receive", false,
		"Run the full native scan pipeline (discovery + spidering + dynamic-assessment) continuously on received records, instead of dynamic-assessment only")
	flags.BoolVar(&serverOpts.PassiveOnly, "passive-only", false,
		"With --scan-on-receive, run passive modules only (no active scan traffic; includes secret detection)")

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
// printing trust instructions. Backs the --export-ca flag. proxyPort is the
// --ingest-proxy-port given alongside it; the hint uses it so the printed curl
// line targets the proxy the operator actually runs.
func exportProxyCA(dst string, proxyPort int) error {
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
		fmt.Printf("  Trust it to capture HTTPS, e.g.:\n    %s\n", proxyCATrustHint(dst, proxyPort))
	}
	return nil
}

// proxyCATrustHint is the example curl line printed after --export-ca. With a
// known --ingest-proxy-port it names that port; without one there is no real
// port to name, so it says which flag sets it instead of inventing one.
func proxyCATrustHint(caPath string, proxyPort int) string {
	if proxyPort > 0 {
		return fmt.Sprintf("curl --proxy http://127.0.0.1:%d --cacert %s https://target/", proxyPort, caPath)
	}
	return fmt.Sprintf("curl --proxy http://127.0.0.1:<port> --cacert %s https://target/   (<port> = the server's --ingest-proxy-port)", caPath)
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
	if err := db.EnsureSchemaReady(context.Background()); err != nil {
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

	// --export-ca: generate (if needed) and write the MITM CA cert, then exit.
	if serverOpts.ExportCA != "" {
		return exportProxyCA(serverOpts.ExportCA, serverOpts.IngestProxyPort)
	}

	// Load settings early so config values are available for API key resolution
	// and for the server.enable_burp_bridge fallback resolved just below.
	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return err
	}

	// Burp bridge address: -B/--burp-bridge-url (which already defaults to
	// $VIGOLIUM_BURP_BRIDGE_URL) wins; otherwise fall back to the config file,
	// but only when server.enable_burp_bridge opts in. The bool is the gate —
	// server.burp_bridge_url carries a default address, so without it every
	// config would silently enable the bridge.
	if serverOpts.BurpBridgeURL == "" && settings.Server.EnableBurpBridge {
		serverOpts.BurpBridgeURL = firstNonEmptyString(settings.Server.BurpBridgeURL, burpbridge.DefaultURL)
	}
	if serverOpts.BurpBridgeURL != "" {
		validated, verr := burpbridge.ValidateURL(serverOpts.BurpBridgeURL)
		if verr != nil {
			return usageErrorf("--burp-bridge-url: %w", verr)
		}
		serverOpts.BurpBridgeURL = validated
	}

	serverOpts.Host = resolveServerHost(cmd, serverOpts.Host)
	proxyHost, proxyAuth, err := resolveIngestProxyAuth(cmd, serverOpts, &settings.Server)
	if err != nil {
		return err
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
			return asUsageError(errors.New("no API key configured: set server.auth_api_key (vigolium config set server.auth_api_key <key>), export VIGOLIUM_API_KEY, pass --alternative-ingest-key, or run with -A/--no-auth for local development"))
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

	// Prune native-scan status.json heartbeat files past their retention
	// (scanning_strategy.scan_logs.status_retention_days), off the start path.
	pruneSessionStatusInBackground(settings)

	// Reap scans whose process died without finalizing their row, now and
	// every few minutes, in every project.
	stopReaper := startAbandonedScanReaper(repo, settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir(), abandonedReapInterval)
	defer stopReaper()

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
	// idle drainer/cleanup goroutines and take an on-disk lock. Use a zero-cost
	// in-memory queue in that case. The durable queue lives in a stable directory
	// keyed by the database (~/.vigolium/server-queue/<hash>), locked for this
	// process, so a restart resumes what the last run left queued.
	var taskQueue queue.Queue
	var queueDir *queue.ServerQueueDir
	if globalScanOnReceive || globalFullNativeScanOnReceive {
		taskQueue, queueDir, err = openServerQueue(&settings.Database, serverOpts.MemBufferSize, serverOpts.DiscardQueued)
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
		ingestProxyAddr = joinHostPort(proxyHost, serverOpts.IngestProxyPort)
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
		IngestProxyAuth:      proxyAuth,
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
		ReportFormats:      serverReportFormats(),
		RenderReport:       renderServerReport,
		APIVersionDefault:  settings.Server.APIVersionDefault,
		AutoCreateProjects: settings.Server.AutoCreateProjects,
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
		serverDone := make(chan struct{}, 1)
		go func() {
			if err := apiServer.Start(); err != nil {
				zap.L().Error("API server error", zap.Error(err))
				serverDone <- struct{}{}
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
		closeServerQueue(taskQueue, queueDir)
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
		serverScan := newScanOnReceiveRow(database.DefaultProjectUUID, strings.Join(globalTargets, ","), strings.Join(runnerOpts.Modules, ","), globalConcurrency)
		if err := repo.CreateScanWithCursor(context.Background(), serverScan); err != nil {
			zap.L().Warn("Failed to create server scan record", zap.Error(err))
		}

		// Reuse the server scan UUID so the runner tracks cursor on the same record
		runnerOpts.ScanUUID = serverScan.UUID
		// ...and the same project. This matches the row above by value today,
		// but stating it keeps the two from drifting apart silently: the feed
		// reads the row's project while the executor writes this one.
		runnerOpts.ProjectUUID = serverScan.ProjectUUID

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
			fmt.Printf("  %s Ingest proxy %s  %s auth %s\n",
				terminal.InfoSymbol(),
				terminal.Cyan(ingestProxyDisplayURL(ingestProxyAddr, proxyAuth)),
				sep,
				terminal.Cyan(ingestProxyAuthLabel(proxyAuth)))
			if caPath := apiServer.ProxyCACertPath(); caPath != "" {
				fmt.Printf("  %s HTTPS intercept %s  %s trust %s\n",
					terminal.InfoSymbol(),
					terminal.Cyan("on"),
					sep,
					terminal.Cyan("vigolium server ca install"))
				fmt.Printf("    %s\n", terminal.Gray(fmt.Sprintf("curl --proxy %s --cacert %s https://target/",
					ingestProxyDisplayURL(ingestProxyAddr, proxyAuth), caPath)))
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

	// Collect late out-of-band callbacks for the sessions scans kept open.
	if repo != nil && settings.OAST.SessionPollInterval > 0 {
		go runOASTSessionPoller(ctx, repo, time.Duration(settings.OAST.SessionPollInterval)*time.Minute, pollOASTSessions)
	}

	// Start workers only when a runner was created (scan-on-receive or
	// full-native-on-receive). Plain API-only mode has no runner to start.
	if scanRunner != nil {
		go func() {
			if err := scanRunner.RunNativeScan(); err != nil {
				zap.L().Error("Runner error", zap.Error(err))
			}
		}()
	}

	// scan-on-receive watches every project, not just the default: one
	// receiver (runner + its own cursor row) per project, started once the
	// project holds ingested traffic. Full-native-on-receive stays on the
	// default project.
	var receivers *projectReceivers
	if scanRunner != nil && globalScanOnReceive && !globalFullNativeScanOnReceive && repo != nil {
		receivers = newProjectReceivers(func(projectUUID string) (receiver, error) {
			opts := *runnerOpts
			row := newScanOnReceiveRow(projectUUID, strings.Join(globalTargets, ","), strings.Join(runnerOpts.Modules, ","), globalConcurrency)
			if err := repo.CreateScanWithCursor(context.Background(), row); err != nil {
				return nil, err
			}
			opts.ScanUUID = row.UUID
			opts.ProjectUUID = projectUUID
			idle, err := queue.NewQueue(queue.Config{Type: queue.QueueTypeMemory, MemBufferSize: 1})
			if err != nil {
				return nil, err
			}
			r, err := runner.NewWithInputSource(&opts, queue.NewQueueInputSource(idle))
			if err != nil {
				return nil, err
			}
			r.SetSettings(settings)
			r.SetRepository(repo)
			go func() {
				if err := r.RunNativeScan(); err != nil {
					zap.L().Error("Runner error", zap.String("project", projectUUID), zap.Error(err))
				}
			}()
			return r, nil
		})
		receivers.add(database.DefaultProjectUUID, scanRunner)
		go receivers.watch(ctx, repo, projectReceiverInterval)
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
	if receivers != nil {
		receivers.closeAll() // includes scanRunner
	} else if scanRunner != nil {
		scanRunner.Close()
	}

	// Shutdown API server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		zap.L().Error("API server shutdown error", zap.Error(err))
	}

	// Close queue last
	closeServerQueue(taskQueue, queueDir)

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

// serverReportEntries are the post-scan report formats REST `output_formats`
// accepts beyond jsonl: the REST surface of the output format table.
var serverReportEntries = reportFormatEntries(output.SurfaceREST)

// serverReportFormats lists the names of serverReportEntries, the formats
// renderServerReport can produce.
func serverReportFormats() []string {
	formats := make([]string, 0, len(serverReportEntries))
	for _, rf := range serverReportEntries {
		formats = append(formats, rf.format)
	}
	return formats
}

// renderServerReport renders one report file for a finished REST scan through
// generateReportFromDB, the generator behind `scan --format html|report|…`,
// scoped to the scan. Injected into the server (pkg/server cannot import
// pkg/cli).
func renderServerReport(ctx context.Context, db *database.DB, format, outputPath, projectUUID, scanUUID string) error {
	for _, rf := range serverReportEntries {
		if rf.format != format {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(outputPath), 0o750); err != nil {
			return fmt.Errorf("create report dir: %w", err)
		}
		return generateReportFromDB(ctx, db, outputPath, false, projectUUID, scanUUID, rf, nil)
	}
	return fmt.Errorf("no report renderer for format %q", format)
}
