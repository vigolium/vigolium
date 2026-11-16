package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/httpstack"
	"github.com/vigolium/vigolium/pkg/parammine"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

var (
	kitParamMineTarget      string
	kitParamMineIgnoreScope bool
	kitParamMineMethod      string
	kitParamMineData        string
	kitParamMineHeaders     []string
	kitParamMineLocation    string
	kitParamMineWordlists   []string
	kitParamMineNoBuiltin   bool
	kitParamMineMaxRequests int
	kitParamMineTimeout     time.Duration
	kitParamMineRateLimit   int
)

var kitParamMineCmd = &cobra.Command{
	Use:   "param-mine [-t URL]",
	Short: "Discover hidden parameters an endpoint accepts (Arjun-style)",
	Long: `Discover parameters an endpoint reads although no request you have carries them
(debug=, callback=, admin=). Two baselines with a random parameter profile the
endpoint; candidate names are then sent in chunks sized to the transport, each
with its own random value, and a chunk whose answer differs (status, header set,
body length/content, or an echoed value) is bisected to single names. Every
candidate is re-sent twice with fresh values and kept only if the difference
reproduces.

  vigolium kit param-mine -t 'https://acme.test/search?q=x'
  vigolium kit param-mine -t https://acme.test/api/login -X POST -d 'user=a' -j
  vigolium kit param-mine -t https://acme.test/api -X POST \
      -H 'Content-Type: application/json' -d '{"id":1}'
  vigolium kit param-mine -t https://acme.test/ -w my-params.txt --max-requests 200

Names go on the query string for GET/HEAD/DELETE, into the form or JSON body
otherwise (--location overrides). The wordlist is -w files first, then the
built-in list (vigolium kit wordlist params). Mining an endpoint stops at
--max-requests, when the two baselines disagree (aborted: unstable), or after a
burst of 403/429/WAF answers (aborted: blocked). A full scan does the same per
endpoint in its param-mining phase (--intensity deep or --param-mining).`,
	Args: cobra.MaximumNArgs(1),
	RunE: runKitParamMine,
}

func init() {
	f := kitParamMineCmd.Flags()
	f.StringVarP(&kitParamMineTarget, "target", "t", "", "Endpoint URL to mine (or pass it as the argument)")
	registerSendScopeFlags(f, &kitParamMineIgnoreScope, "Mine an endpoint outside the configured host scope")
	f.StringVarP(&kitParamMineMethod, "method", "X", "GET", "HTTP method")
	f.StringVarP(&kitParamMineData, "data", "d", "", "Request body (form or JSON); names are added to it")
	f.StringArrayVarP(&kitParamMineHeaders, "header", "H", nil, "Request header 'Name: value' (repeatable)")
	f.StringVar(&kitParamMineLocation, "location", "auto", "Where names go: auto, query, form, json")
	f.StringArrayVarP(&kitParamMineWordlists, "wordlist", "w", nil, "File of parameter names, one per line, tried before the built-in list (repeatable)")
	f.BoolVar(&kitParamMineNoBuiltin, "no-builtin", false, "Use only the -w wordlists, not the built-in list")
	f.IntVar(&kitParamMineMaxRequests, "max-requests", parammine.DefaultMaxRequests, "Request budget, baselines and confirmations included")
	f.DurationVar(&kitParamMineTimeout, "timeout", 15*time.Second, "Per-request timeout")
	f.IntVar(&kitParamMineRateLimit, "rate-limit", defaultParamMineRateLimit, "Maximum requests per second (0 = unlimited)")
	kitCmd.AddCommand(kitParamMineCmd)
}

// kitParamMineItem is one confirmed hidden parameter in the -j result.
type kitParamMineItem struct {
	Name     string `json:"name"`
	Signal   string `json:"signal"`
	Location string `json:"location"`
	Detail   string `json:"detail,omitempty"`
	// URL and Status describe the confirming request: the original request
	// plus this one parameter.
	URL    string `json:"url"`
	Status int    `json:"status"`
}

func runKitParamMine(cmd *cobra.Command, args []string) error {
	target := kitParamMineTarget
	if len(args) == 1 {
		if target != "" && target != args[0] {
			return clicommon.UsageErrorf("give the URL once: -t %s or the argument %s, not both", target, args[0])
		}
		target = args[0]
	}
	if target == "" {
		return clicommon.UsageErrorf("a target URL is required (-t URL)")
	}
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return clicommon.UsageErrorf("target %q must be an http:// or https:// URL", target)
	}
	loc, err := parammine.ParseLocation(kitParamMineLocation)
	if err != nil {
		return clicommon.UsageErrorf("%v", err)
	}
	if kitParamMineMaxRequests < 3 {
		return clicommon.UsageErrorf("--max-requests must be at least 3 (two baselines and one chunk)")
	}
	headers, err := kitParamMineHeaderMap(kitParamMineHeaders)
	if err != nil {
		return err
	}
	base, err := httpmsg.GetRawRequestFromURLWithMethod(target, kitParamMineMethod, headers, []byte(kitParamMineData))
	if err != nil {
		return clicommon.UsageErrorf("invalid target %q: %v", target, err)
	}

	gate, err := newSendScopeGate(kitParamMineIgnoreScope)
	if err != nil {
		return err
	}
	if err := gate.check(target); err != nil {
		return err
	}

	words, err := kitParamMineWords()
	if err != nil {
		return err
	}
	if len(words) == 0 {
		return clicommon.UsageErrorf("the wordlist is empty")
	}

	stack, err := kitParamMineStack()
	if err != nil {
		return err
	}
	defer stack.Close()
	requester := stack.Requester

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if !globalJSON {
		fmt.Fprintf(os.Stderr, "%s mining %s %s with %d names (budget %d requests)...\n",
			terminal.InfoSymbol(), base.Request().Method(), target, len(words), kitParamMineMaxRequests)
	}
	res, err := parammine.Mine(ctx, base, words, parammine.RequesterSender(requester), parammine.Config{
		MaxRequests: kitParamMineMaxRequests,
		Location:    loc,
	})
	if err != nil {
		return err
	}

	items := make([]kitParamMineItem, 0, len(res.Hits))
	for _, h := range res.Hits {
		item := kitParamMineItem{Name: h.Name, Signal: string(h.Signal), Location: string(h.Location), Detail: h.Detail}
		if h.Exchange != nil {
			item.URL = h.Exchange.Target()
			if h.Exchange.HasResponse() {
				item.Status = h.Exchange.Response().StatusCode()
			}
		}
		items = append(items, item)
	}

	if globalJSON {
		if err := emitRead(cmd, "params", items, int64(len(items)), 0, len(items),
			withExtra("url", res.URL),
			withExtra("method", res.Method),
			withExtra("location", string(res.Location)),
			withExtra("names_tested", res.Tested),
			withExtra("requests", res.Requests),
			withExtra("aborted", res.Aborted)); err != nil {
			return err
		}
		return paramMineOutcome(res.Aborted)
	}
	for _, it := range items {
		fmt.Printf("%s\t%s\t%s\n", it.Name, it.Signal, it.Detail)
	}
	summary := fmt.Sprintf("%d hidden parameter(s); %d names tested in %d requests", len(items), res.Tested, res.Requests)
	if res.Aborted != "" {
		summary += " — stopped early: " + res.Aborted
	}
	fmt.Fprintf(os.Stderr, "\n%s %s\n", terminal.InfoSymbol(), summary)
	return paramMineOutcome(res.Aborted)
}

// paramMineOutcome turns a run that stopped on failed sends into its exit: a
// baseline that got no answer tested nothing (no_targets_reachable); a burst of
// transport errors cut the run short (partial). The other stops (budget,
// blocked, unstable) are answers about the target, reported in "aborted".
func paramMineOutcome(aborted string) error {
	switch aborted {
	case parammine.AbortBaseline:
		return sendOutcomeError("param-mine baseline request", 1, 1)
	case parammine.AbortErrors:
		return incompleteErrorf(apicontract.CodePartial, "param-mine stopped after consecutive transport errors; the names after that point were not tested")
	}
	return nil
}

// kitParamMineWords merges the -w files and the built-in list, first
// occurrence wins.
func kitParamMineWords() ([]string, error) {
	var sources [][]string
	for _, path := range kitParamMineWordlists {
		names, err := parammine.ReadWordlistFile(path)
		if err != nil {
			return nil, clicommon.UsageErrorf("cannot read wordlist %s: %v", path, err)
		}
		sources = append(sources, names)
	}
	if !kitParamMineNoBuiltin {
		builtin, err := parammine.Builtin()
		if err != nil {
			return nil, fmt.Errorf("built-in parameter wordlist: %w", err)
		}
		sources = append(sources, builtin)
	} else if len(sources) == 0 {
		return nil, clicommon.UsageErrorf("--no-builtin needs at least one -w wordlist")
	}
	return parammine.MergeWordlists(0, sources...), nil
}

func kitParamMineHeaderMap(raw []string) (map[string]string, error) {
	out := make(map[string]string, len(raw))
	for _, h := range raw {
		name, value, ok := strings.Cut(h, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, clicommon.UsageErrorf("invalid header %q (want 'Name: value')", h)
		}
		out[name] = strings.TrimSpace(value)
	}
	return out, nil
}

// kitParamMineStack builds a standalone requester: the global --proxy, this
// command's timeout and rate limit, and a per-host concurrency limiter.
func kitParamMineStack() (*httpstack.Stack, error) {
	opts := types.DefaultOptions()
	opts.Timeout = kitParamMineTimeout
	opts.ProxyURL = globalProxy
	opts.Verbose = globalVerbose
	opts.Debug = globalDebug
	opts.DumpTraffic = globalDumpTraffic
	opts.RateLimit = kitParamMineRateLimit
	return httpstack.New(httpstack.Config{Options: opts, RateLimit: float64(kitParamMineRateLimit)})
}
