package cli

import (
	"fmt"
	"os"
	"sync"
	"time"

	interactshclient "github.com/projectdiscovery/interactsh/pkg/client"
	interactshoptions "github.com/projectdiscovery/interactsh/pkg/options"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/terminal"
	"gopkg.in/yaml.v3"
)

const kitOASTDefaultSession = "oast-session.yaml"

// kitOASTTokenEnv is read when --token is empty, so a caller can hand the
// interactsh token over without putting it on a command line (where every
// local user can read it from the process table). The same variable feeds
// oast.token in the shipped config template.
const kitOASTTokenEnv = "VIGOLIUM_OAST_TOKEN"

// resolveKitOASTToken returns the --token value, or $VIGOLIUM_OAST_TOKEN when
// the flag is empty. An explicit flag always wins.
func resolveKitOASTToken(flag string) string {
	if flag != "" {
		return flag
	}
	return os.Getenv(kitOASTTokenEnv)
}

var (
	kitOASTSession    string
	kitOASTServer     string
	kitOASTToken      string
	kitOASTCount      int
	kitOASTWait       time.Duration
	kitOASTInterval   time.Duration
	kitOASTDeregister bool
)

var kitOASTCmd = &cobra.Command{
	Use:   "oast",
	Short: "Mint out-of-band (OOB/OAST) callback URLs and drain their interactions",
	Long: `Generate interactsh out-of-band callback URLs and later poll for the DNS/HTTP/SMTP
interactions they received — the primitive behind blind SSRF/XXE/RCE/log4shell
confirmation. State is kept in a session file so minting and polling can be
separate, fire-and-forget invocations (no long-running process).

  vigolium kit oast new                                     # mint a URL, save the session
  vigolium kit oast new -n 3 --session run.yaml             # mint 3 URLs into run.yaml
  # ...inject the URL(s) somewhere, wait...
  vigolium kit oast poll --session run.yaml --wait 30s -j   # drain interactions as JSON
  vigolium kit oast poll --session run.yaml --deregister    # final drain + tear down

The session file holds the interactsh private key + correlation id; keep it
until you are done polling. Uses the public oast.pro server by default; point
--server/--token at a self-hosted interactsh instance to keep callbacks private.`,
	RunE: func(cmd *cobra.Command, args []string) error { return cmd.Help() },
}

var kitOASTNewCmd = &cobra.Command{
	Use:   "new",
	Short: "Register an OAST session and mint one or more callback URLs",
	RunE:  runKitOASTNew,
}

var kitOASTPollCmd = &cobra.Command{
	Use:   "poll",
	Short: "Poll a saved OAST session for received interactions",
	RunE:  runKitOASTPoll,
}

func init() {
	// Long-only on purpose: -o means output everywhere else in the CLI
	// (export, fuzz, replay, scan, import, db export), so binding it to
	// the session file here would be the one place -o writes something
	// the operator did not ask to write.
	kitOASTCmd.PersistentFlags().StringVar(&kitOASTSession, "session", kitOASTDefaultSession, "Session file path (holds the interactsh keys/correlation id)")

	nf := kitOASTNewCmd.Flags()
	nf.StringVar(&kitOASTServer, "server", config.DefaultOASTServer, "interactsh server URL")
	nf.StringVar(&kitOASTToken, "token", "", "interactsh auth token (for a self-hosted server; falls back to $"+kitOASTTokenEnv+")")
	nf.IntVarP(&kitOASTCount, "count", "n", 1, "Number of callback URLs to mint")

	pf := kitOASTPollCmd.Flags()
	pf.DurationVar(&kitOASTWait, "wait", 15*time.Second, "How long to poll for interactions before exiting")
	pf.DurationVar(&kitOASTInterval, "interval", 5*time.Second, "Polling interval (auto-shrunk if larger than --wait)")
	pf.BoolVar(&kitOASTDeregister, "deregister", false, "After draining, deregister the session server-side and delete the session file")

	kitOASTCmd.AddCommand(kitOASTNewCmd, kitOASTPollCmd)
	kitCmd.AddCommand(kitOASTCmd)
}

type kitOASTNewResult struct {
	Server  string   `json:"server"`
	Session string   `json:"session"`
	Count   int      `json:"count"`
	URLs    []string `json:"urls"`
}

func runKitOASTNew(cmd *cobra.Command, args []string) error {
	if kitOASTCount < 1 {
		return usageErrorf("--count must be at least 1")
	}

	client, err := interactshclient.New(&interactshclient.Options{
		ServerURL: kitOASTServer,
		Token:     resolveKitOASTToken(kitOASTToken),
	})
	if err != nil {
		return fmt.Errorf("registering with interactsh server %q: %w", kitOASTServer, err)
	}

	urls := make([]string, 0, kitOASTCount)
	for i := 0; i < kitOASTCount; i++ {
		urls = append(urls, client.URL())
	}

	// Persist BEFORE anything can tear the session down. Deliberately do NOT
	// Close() the client: Close() sends a /deregister that destroys the session
	// server-side, which would make the saved session useless for polling.
	if err := client.SaveSessionTo(kitOASTSession); err != nil {
		return fmt.Errorf("saving session to %s: %w", kitOASTSession, err)
	}

	res := kitOASTNewResult{Server: kitOASTServer, Session: kitOASTSession, Count: len(urls), URLs: urls}
	if globalJSON {
		return emitStructRead(cmd, res, "urls")
	}
	for _, u := range urls {
		fmt.Println(u)
	}
	fmt.Fprintf(os.Stderr, "%s session saved to %s - poll it with: vigolium kit oast poll --session %s\n",
		terminal.InfoSymbol(), kitOASTSession, kitOASTSession)
	return nil
}

type kitOASTInteraction struct {
	Protocol      string    `json:"protocol"`
	UniqueID      string    `json:"unique_id"`
	FullID        string    `json:"full_id"`
	QType         string    `json:"q_type,omitempty"`
	RemoteAddress string    `json:"remote_address"`
	Timestamp     time.Time `json:"timestamp"`
	RawRequest    string    `json:"raw_request,omitempty"`
	RawResponse   string    `json:"raw_response,omitempty"`
	SMTPFrom      string    `json:"smtp_from,omitempty"`
}

type kitOASTPollResult struct {
	Server       string               `json:"server"`
	Session      string               `json:"session"`
	Count        int                  `json:"count"`
	Interactions []kitOASTInteraction `json:"interactions"`
}

func runKitOASTPoll(cmd *cobra.Command, args []string) error {
	session, err := loadOASTSession(kitOASTSession)
	if err != nil {
		return err
	}

	client, err := interactshclient.New(&interactshclient.Options{
		ServerURL:   session.ServerURL,
		Token:       session.Token,
		SessionInfo: session,
	})
	if err != nil {
		return fmt.Errorf("resuming session from %s: %w", kitOASTSession, err)
	}

	var (
		mu    sync.Mutex
		items []kitOASTInteraction
	)
	collect := func(in *server.Interaction) {
		if in == nil {
			return
		}
		mu.Lock()
		items = append(items, toKitOASTInteraction(in))
		mu.Unlock()
	}

	// StartPolling's ticker fires only AFTER one interval, so an interval larger
	// than the wait window would poll zero times. Shrink it to guarantee at least
	// a couple of polls within --wait.
	interval := kitOASTInterval
	if interval <= 0 || interval >= kitOASTWait {
		interval = kitOASTWait / 2
	}
	if interval < 500*time.Millisecond {
		interval = 500 * time.Millisecond
	}

	if err := client.StartPolling(interval, collect); err != nil {
		return fmt.Errorf("starting poll: %w", err)
	}
	time.Sleep(kitOASTWait)
	_ = client.StopPolling()

	mu.Lock()
	res := kitOASTPollResult{
		Server:       session.ServerURL,
		Session:      kitOASTSession,
		Count:        len(items),
		Interactions: items,
	}
	mu.Unlock()

	// Optional teardown: deregister the session server-side and delete the file.
	// Close() must run only after StopPolling (it rejects a still-polling client).
	if kitOASTDeregister {
		if cerr := client.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "%s deregister failed: %v\n", terminal.WarningSymbol(), cerr)
		} else if rerr := os.Remove(kitOASTSession); rerr != nil && !os.IsNotExist(rerr) {
			fmt.Fprintf(os.Stderr, "%s could not remove %s: %v\n", terminal.WarningSymbol(), kitOASTSession, rerr)
		}
	}

	if globalJSON {
		return emitStructRead(cmd, res, "interactions")
	}
	if res.Count == 0 {
		fmt.Fprintf(os.Stderr, "%s no interactions received (polled %s)\n", terminal.InfoSymbol(), kitOASTWait)
		return nil
	}
	for _, in := range res.Interactions {
		fmt.Printf("%s\t%s\t%s\t%s\n",
			terminal.Bold("["+in.Protocol+"]"), in.RemoteAddress, in.FullID, in.Timestamp.Format(time.RFC3339))
		if globalVerbose && in.RawRequest != "" {
			fmt.Println(in.RawRequest)
		}
	}
	fmt.Fprintf(os.Stderr, "\n%s %d interaction(s)\n", terminal.InfoSymbol(), res.Count)
	return nil
}

func toKitOASTInteraction(in *server.Interaction) kitOASTInteraction {
	return kitOASTInteraction{
		Protocol:      in.Protocol,
		UniqueID:      in.UniqueID,
		FullID:        in.FullId,
		QType:         in.QType,
		RemoteAddress: in.RemoteAddress,
		Timestamp:     in.Timestamp,
		RawRequest:    in.RawRequest,
		RawResponse:   in.RawResponse,
		SMTPFrom:      in.SMTPFrom,
	}
}

// loadOASTSession reads and parses an interactsh session file written by
// SaveSessionTo (YAML). A clear error when it's missing points the user back at
// `oast new`.
func loadOASTSession(path string) (*interactshoptions.SessionInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("session file %s not found - run `vigolium kit oast new --session %s` first", path, path)
		}
		return nil, err
	}
	var si interactshoptions.SessionInfo
	if err := yaml.Unmarshal(data, &si); err != nil {
		return nil, fmt.Errorf("parsing session file %s: %w", path, err)
	}
	if si.CorrelationID == "" || si.PrivateKey == "" {
		return nil, fmt.Errorf("session file %s is missing correlation id / private key — regenerate with `oast new`", path)
	}
	return &si, nil
}
