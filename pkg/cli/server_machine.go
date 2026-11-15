package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/atomicfile"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/procutil"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `server` in machine mode (-j or --events): stdout carries exactly one line,
// server.ready, once both listeners are bound; the banner, the access log and
// every other line go to stderr. A pidfile ~/.vigolium/server/<port>.json lets
// `server status` and `server stop` find the process.

var serverEvents string

func init() {
	f := serverCmd.Flags()
	f.StringVar(&serverEvents, "events", "", "Machine mode: print one server.ready JSON line on stdout once the listeners are bound and send every log line to stderr (value: ndjson). -j does the same")
	f.Lookup("events").NoOptDefVal = "ndjson"

	serverCmd.AddCommand(serverStatusCmd, serverStopCmd)
	serverStatusCmd.Flags().IntVar(&serverCtlPort, "port", 0, "Only the server on this port (default: every server with a pidfile)")
	serverStopCmd.Flags().IntVar(&serverCtlPort, "port", 0, "The server's port (required when more than one is running)")
	serverStopCmd.Flags().DurationVar(&serverStopTimeout, "timeout", 40*time.Second, "How long to wait for the server to exit")

	registerCommandSchema(contract.Command{Name: "server status", Item: serverStatusView{}, Extras: serverStatusExtras{},
		Description: "One row per server pidfile: the recorded pid and address, whether the process is alive and /health answers."})
	registerCommandSchema(contract.Command{Name: "server stop", Item: serverStatusView{},
		Description: "The server stopped (SIGTERM, sent only when /health answered with the recorded pid), and whether it exited in time."})
}

// serverStatusExtras are the top-level keys `server status -j` adds.
type serverStatusExtras struct {
	// Running is true when at least one listed server is alive.
	Running bool `json:"running"`
}

// serverMachineMode reports whether stdout is reserved for server.ready.
func serverMachineMode() bool { return globalJSON || serverEvents != "" }

// redirectServerStdout points os.Stdout at stderr for the server's lifetime
// in machine mode, so the banner and the HTTP access log (which binds
// os.Stdout when the server is built) cannot interleave with server.ready.
// It returns the real stdout and the restore step.
func redirectServerStdout() (io.Writer, func(), error) {
	real := os.Stdout
	if serverEvents != "" && serverEvents != "ndjson" {
		return real, func() {}, usageErrorf("--events %q: the server's only event format is ndjson", serverEvents)
	}
	if !serverMachineMode() {
		return real, func() {}, nil
	}
	os.Stdout = os.Stderr
	return real, func() { os.Stdout = real }, nil
}

// serverPidfile is ~/.vigolium/server/<port>.json.
type serverPidfile struct {
	PID       int    `json:"pid"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Addr      string `json:"addr"`
	DBPath    string `json:"db_path,omitempty"`
	Auth      string `json:"auth"`
	Version   string `json:"version,omitempty"`
	StartedAt string `json:"started_at"`
}

func serverPidDir() string { return config.ExpandPath("~/.vigolium/server") }

func serverPidPath(port int) string {
	return filepath.Join(serverPidDir(), strconv.Itoa(port)+".json")
}

// serverReadyEvent is the server.ready line.
type serverReadyEvent struct {
	Type          string `json:"type"`
	SchemaVersion int    `json:"schema_version"`
	Addr          string `json:"addr"`
	URL           string `json:"url"`
	PID           int    `json:"pid"`
	DBPath        string `json:"db_path,omitempty"`
	// Auth is "api_key" or "none" (-A).
	Auth string `json:"auth"`
	// HealthURL and ReadyURL are the unauthenticated liveness and readiness
	// probes.
	HealthURL       string `json:"health_url"`
	ReadyURL        string `json:"ready_url"`
	IngestProxyAddr string `json:"ingest_proxy_addr,omitempty"`
	Pidfile         string `json:"pidfile,omitempty"`
	TS              string `json:"ts"`
}

// announceServerReady writes the pidfile and, in machine mode, the
// server.ready line on the real stdout. Call it right after the listeners
// bound. The returned cleanup removes the pidfile.
func announceServerReady(stdout io.Writer, host string, port int, dbPath string, noAuth bool, proxyAddr string) func() {
	auth := "api_key"
	if noAuth {
		auth = "none"
	}
	url := "http://" + net.JoinHostPort(host, strconv.Itoa(port))
	pf := serverPidfile{PID: os.Getpid(), Host: host, Port: port, Addr: url, DBPath: dbPath, Auth: auth,
		Version: Version, StartedAt: time.Now().UTC().Format(time.RFC3339)}
	pidPath := serverPidPath(port)
	written := false
	if err := os.MkdirAll(serverPidDir(), 0o755); err == nil {
		if data, err := json.Marshal(pf); err == nil && atomicfile.WriteBytes(pidPath, data) == nil {
			written = true
		}
	}
	if serverMachineMode() {
		ev := serverReadyEvent{Type: "server.ready", SchemaVersion: AgentSchemaVersion, Addr: net.JoinHostPort(host, strconv.Itoa(port)),
			URL: url, PID: pf.PID, DBPath: dbPath, Auth: auth, HealthURL: url + "/health", ReadyURL: url + "/ready",
			IngestProxyAddr: proxyAddr, TS: agentTimestamp(time.Now())}
		if written {
			ev.Pidfile = pidPath
		}
		if data, err := json.Marshal(ev); err == nil {
			_, _ = fmt.Fprintln(stdout, string(data))
		}
	}
	return func() {
		if !written {
			return
		}
		// Only our own pidfile: a second server on the port after a crash
		// would have rewritten it.
		if cur, err := readServerPidfile(pidPath); err == nil && cur.PID == pf.PID {
			_ = os.Remove(pidPath)
		}
	}
}

func readServerPidfile(path string) (*serverPidfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pf serverPidfile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &pf, nil
}

var (
	serverCtlPort     int
	serverStopTimeout time.Duration
)

var serverStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show running servers: pidfile, process liveness and /health",
	Long: "List the servers that left a pidfile in ~/.vigolium/server/, with whether the recorded process is alive and " +
		"whether GET /health on the recorded address answers with that pid. Sends one request per server, to its " +
		"own unauthenticated /health. Exit 0 even when none is running (running: false).",
	Example: "  vigolium server status -j\n  vigolium server status --port 9002",
	Args:    cobra.NoArgs,
	RunE:    runServerStatus,
}

var serverStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop a running server (SIGTERM, only when /health confirms the pid)",
	Long: "Send SIGTERM to the server recorded in ~/.vigolium/server/<port>.json, but only when GET /health on its address " +
		"answers with the recorded pid: a stale pidfile whose pid now belongs to another process is never signalled. " +
		"Waits up to --timeout for the process to exit.",
	Example: "  vigolium server stop --port 9002 -j",
	Args:    cobra.NoArgs,
	RunE:    runServerStop,
}

// serverStatusView is one row of `server status` / `server stop`.
type serverStatusView struct {
	Port         int    `json:"port"`
	PID          int    `json:"pid"`
	Addr         string `json:"addr"`
	StartedAt    string `json:"started_at,omitempty"`
	ProcessAlive bool   `json:"process_alive"`
	Healthy      bool   `json:"healthy"`
	// HealthPIDMatches says /health answered with the recorded pid.
	HealthPIDMatches bool   `json:"health_pid_matches"`
	Running          bool   `json:"running"`
	Pidfile          string `json:"pidfile"`
	Stopped          *bool  `json:"stopped,omitempty"`
	Error            string `json:"error,omitempty"`
}

// probeServer reads one pidfile's state.
func probeServer(ctx context.Context, path string) serverStatusView {
	v := serverStatusView{Pidfile: path}
	pf, err := readServerPidfile(path)
	if err != nil {
		v.Error = err.Error()
		return v
	}
	v.Port, v.PID, v.Addr, v.StartedAt = pf.Port, pf.PID, pf.Addr, pf.StartedAt
	v.ProcessAlive = pf.PID > 0 && procutil.IsProcessAlive(pf.PID)
	hctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(hctx, http.MethodGet, strings.TrimSuffix(pf.Addr, "/")+"/health", nil)
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	if resp, err := client.Do(req); err == nil {
		var body struct {
			Status string `json:"status"`
			PID    int    `json:"pid"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&body)
		_ = resp.Body.Close()
		v.Healthy = resp.StatusCode == http.StatusOK
		v.HealthPIDMatches = v.Healthy && body.PID == pf.PID
	}
	v.Running = v.ProcessAlive && v.HealthPIDMatches
	return v
}

// serverPidfiles lists the pidfiles to look at (one port, or all).
func serverPidfiles() []string {
	if serverCtlPort > 0 {
		p := serverPidPath(serverCtlPort)
		if _, err := os.Stat(p); err != nil {
			return nil
		}
		return []string{p}
	}
	matches, _ := filepath.Glob(filepath.Join(serverPidDir(), "*.json"))
	sort.Strings(matches)
	return matches
}

func runServerStatus(cmd *cobra.Command, _ []string) error {
	views := []serverStatusView{}
	for _, p := range serverPidfiles() {
		views = append(views, probeServer(context.Background(), p))
	}
	if globalJSON {
		running := false
		for _, v := range views {
			running = running || v.Running
		}
		return emitRead(cmd, "", views, int64(len(views)), 0, len(views), withExtra("running", running))
	}
	if len(views) == 0 {
		fmt.Printf("%s No server pidfile in %s (no server started from this account is running)\n", terminal.InfoSymbol(), terminal.ShortenHome(serverPidDir()))
		return nil
	}
	for _, v := range views {
		state := terminal.Green("running")
		switch {
		case v.Error != "":
			state = terminal.Red("unreadable pidfile: " + v.Error)
		case !v.ProcessAlive:
			state = terminal.Yellow("stale pidfile (process gone)")
		case !v.HealthPIDMatches:
			state = terminal.Yellow("process alive, /health not answering with its pid")
		}
		fmt.Printf("%s port %d pid %d %s — %s\n", terminal.InfoSymbol(), v.Port, v.PID, v.Addr, state)
	}
	return nil
}

func runServerStop(cmd *cobra.Command, _ []string) error {
	files := serverPidfiles()
	switch {
	case len(files) == 0:
		return codedErrorf(apicontract.CodeNotFound, "no server pidfile found in %s%s", terminal.ShortenHome(serverPidDir()), portSuffix())
	case len(files) > 1:
		return usageErrorf("%d servers have pidfiles; pick one with --port", len(files))
	}
	v := probeServer(context.Background(), files[0])
	if v.Error != "" {
		return fmt.Errorf("read %s: %s", files[0], v.Error)
	}
	if !v.Running {
		reason := "its /health does not answer with the recorded pid"
		if !v.ProcessAlive {
			reason = "its process is gone (stale pidfile)"
			_ = os.Remove(files[0])
		}
		return clicommon.CLIError{
			Err:  fmt.Errorf("not signalling pid %d: %s", v.PID, reason),
			Code: apicontract.CodeNotFound,
			Hint: "check with: vigolium server status",
		}
	}
	proc, err := os.FindProcess(v.PID)
	if err == nil {
		err = proc.Signal(syscall.SIGTERM)
	}
	if err != nil {
		return fmt.Errorf("signal pid %d: %w", v.PID, err)
	}
	stopped := false
	deadline := time.Now().Add(serverStopTimeout)
	for time.Now().Before(deadline) {
		if !procutil.IsProcessAlive(v.PID) {
			stopped = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	v.Stopped = &stopped
	v.Running = !stopped
	var waitErr error
	if !stopped {
		waitErr = clicommon.CLIError{
			Err:  fmt.Errorf("server pid %d did not exit within --timeout %s", v.PID, serverStopTimeout),
			Code: apicontract.CodeWaitTimeout,
			Hint: fmt.Sprintf("a second SIGTERM forces it: kill -TERM %d", v.PID),
		}
	}
	if globalJSON {
		if err := emitMutation(cmd, "", mutationResult{Changed: true, Action: "stop", Items: []serverStatusView{v}}); err != nil {
			return err
		}
		return waitErr
	}
	if stopped {
		fmt.Printf("%s Stopped server on port %d (pid %d)\n", terminal.SuccessSymbol(), v.Port, v.PID)
	}
	return waitErr
}

func portSuffix() string {
	if serverCtlPort > 0 {
		return " for port " + strconv.Itoa(serverCtlPort)
	}
	return ""
}

// serverReadyDBPath names the SQLite file the server opened ("" otherwise).
func serverReadyDBPath(cfg *config.DatabaseConfig) string {
	if cfg == nil || (cfg.Driver != "" && cfg.Driver != "sqlite") {
		return ""
	}
	return config.ExpandPath(cfg.SQLite.Path)
}

// serverReadyProxyAddr is the ingest proxy's host:port, "" when it is off.
func serverReadyProxyAddr(host string, port int) string {
	if port <= 0 {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}
