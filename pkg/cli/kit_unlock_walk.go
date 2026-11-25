package cli

import (
	"context"
	"fmt"
	"net/url"
	"os"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	kitUnlockProfile     string
	kitUnlockOrigin      string
	kitUnlockAllowWrites bool
	kitUnlockIgnoreScope bool
)

var kitUnlockWalkCmd = &cobra.Command{
	Use:   "unlock-walk --profile <file|->",
	Short: "Walk a single-page app's routes on forged client state",
	Long: `Open a single-page app in a headless browser with forged client state, then
visit its routes, so views a client-side gate hides from an anonymous visitor
render and send their real API calls. The profile (JSON; its schema is the
unlock-profile document of 'vigolium schema all') holds the state:
localStorage and sessionStorage seeds, cookies, response stubs for the app's
own bootstrap and permission calls, rewrites of real answers, the routes to
visit and how many controls to click on each (maxClicksPerRoute, default %d).

  vigolium kit unlock-walk --profile unlock.json -j
  vigolium kit unlock-walk --profile unlock.json --origin https://app.acme.test -j
  cat unlock.json | vigolium kit unlock-walk --profile - -j

  {"origin": "https://app.acme.test",
   "localStorage": {"token": "x"},
   "stubs": [{"method": "GET", "path": "/api/me", "status": 200,
              "contentType": "application/json", "body": "{\"role\":\"admin\"}"}],
   "rewrites": [{"method": "GET", "path": "/api/menu", "status": 200,
                 "set": [{"pointer": "/data/isAdmin", "value": true}]}],
   "routes": ["/admin", "/admin/users"]}

The walk forges state; it never forges evidence:
  - storage seeds reach the page as data a fixed script reads, never as source;
  - a stub answers only requests on the profile's origin, in the browser; a
    stubbed response is never stored. A stub off the origin refuses the profile;
  - a rewrite lets a same-origin request reach the target, then changes its
    answer in the browser (a status, JSON members set by RFC 6901 pointer). A
    rewritten answer is never evidence: the exchange is never stored, never
    listed as a request, and is reported as rewrites_hit (upstream_status beside
    the status the page got, applied, error);
  - on each rendered route the walk clicks up to maxClicksPerRoute controls, one
    search, filter, first-row view and edit, and export first, then tabs and
    links, never one the destructive-label guard refuses (delete, logout,
    approve, …: clicks_skipped_destructive, skipped_controls). A click's
    requests pass the same gate (via "click"). Under --allow-writes the walk
    clicks nothing (clicks_refused: writes_allowed);
  - every request with a method other than GET, HEAD or OPTIONS is failed in the
    browser and reported by shape (aborted_writes); --allow-writes lets in-scope
    ones through;
  - every real in-scope exchange is stored as traffic (source unlock-walk, remark
    client-unlocked on a new row) and listed per route with its record_uuid.
Whether a reached endpoint is a finding is for a check on an anonymous request,
never for the walk.

The origin and every route are judged by the configured scope (exit 2,
out_of_scope; --require-scope / VIGOLIUM_REQUIRE_SCOPE fail closed on an empty
scope). Exchanges off the origin are stored only when the configured scope
names their host. An invalid profile exits 2 before a browser is launched.`,
	Args: cobra.NoArgs,
	RunE: runKitUnlockWalk,
}

func init() {
	kitUnlockWalkCmd.Long = fmt.Sprintf(kitUnlockWalkCmd.Long, spitolas.DefaultUnlockClicksPerRoute)
}

func init() {
	f := kitUnlockWalkCmd.Flags()
	f.StringVar(&kitUnlockProfile, "profile", "", "Unlock profile JSON file, or - for stdin (required)")
	f.StringVar(&kitUnlockOrigin, "origin", "", "Refuse the profile unless its origin is exactly this one (pins the origin on the command line)")
	f.BoolVar(&kitUnlockAllowWrites, "allow-writes", false, "Let in-scope requests with a state-changing method (POST, PUT, PATCH, DELETE, …) reach the target instead of failing them in the browser")
	registerSendScopeFlags(f, &kitUnlockIgnoreScope, "Walk an origin outside the configured host scope")
	kitCmd.AddCommand(kitUnlockWalkCmd)
}

// schemaDocUnlockProfile names the unlock profile document in `vigolium schema`.
const schemaDocUnlockProfile = "unlock-profile"

func init() {
	contract.RegisterDocument(contract.Document{Name: schemaDocUnlockProfile, Value: spitolas.UnlockProfile{},
		Description: fmt.Sprintf("The kit unlock-walk --profile input: origin, localStorage/sessionStorage seeds, cookies, response stubs (same-origin, 2xx/4xx/5xx, body up to %d KiB), rewrites of real same-origin answers (status 2xx/4xx/5xx and/or up to 20 RFC 6901 pointer sets, values up to %d KiB; never stored as evidence), routes (maxRoutes default %d, at most %d; settleMs default %d, at most %d) and maxClicksPerRoute (default %d, at most %d, 0 off).",
			spitolas.MaxUnlockStubBody>>10, spitolas.MaxUnlockRewriteValues>>10, spitolas.DefaultUnlockMaxRoutes, spitolas.MaxUnlockRoutes, spitolas.DefaultUnlockSettleMs, spitolas.MaxUnlockSettleMs,
			spitolas.DefaultUnlockClicksPerRoute, spitolas.MaxUnlockClicksPerRoute)})
}

// kitUnlockWalkReport is the -j document: the walk itself plus where its
// exchanges went.
type kitUnlockWalkReport struct {
	spitolas.UnlockWalkResult
	// Stored is true when real exchanges were written to the project store.
	Stored bool `json:"stored"`
	// StoreSkip says why nothing was stored (read_only, stateless,
	// database_unavailable, project_unresolved); absent when Stored.
	StoreSkip string `json:"store_skip,omitempty"`
}

// unlockWalkSink stores a walk's exchanges as unlock-walk records, a new row
// remarked client-unlocked.
type unlockWalkSink struct {
	saver  *handSendSaver
	origin string
}

func (s unlockWalkSink) SaveUnlockWalkRecord(ctx context.Context, rr *httpmsg.HttpRequestResponse) (string, error) {
	return s.saver.repo.SaveRecordWithLineage(ctx, rr, database.RecordSourceUnlockWalk, s.saver.projectUUID,
		s.saver.lineage(ctx, s.origin, database.RecordRemarkClientUnlocked))
}

func runKitUnlockWalk(cmd *cobra.Command, _ []string) error {
	if kitUnlockProfile == "" {
		return clicommon.UsageErrorf("--profile is required (a JSON unlock profile file, or - for stdin)")
	}
	data, label, err := kitReadInput(kitUnlockProfile)
	if err != nil {
		return clicommon.UsageErrorf("read the profile %s: %v", label, err)
	}
	profile, err := spitolas.ParseUnlockProfile(data)
	if err != nil {
		return clicommon.UsageErrorf("%v", err)
	}
	if err := checkUnlockOriginPin(profile.Origin, kitUnlockOrigin); err != nil {
		return err
	}

	gate, err := newSendScopeGate(kitUnlockIgnoreScope)
	if err != nil {
		return err
	}
	if err := gate.check(profile.Targets()...); err != nil {
		return err
	}

	saver := newHandSendSaver(database.RecordSourceUnlockWalk, true)
	cfg := spitolas.UnlockWalkConfig{
		Profile:     profile,
		InScope:     unlockOffOriginScope(gate),
		AllowWrites: kitUnlockAllowWrites,
		ProxyURL:    globalProxy,
	}
	if saver.active() {
		cfg.Sink = unlockWalkSink{saver: saver, origin: profile.Origin}
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	res, err := spitolas.UnlockWalk(ctx, cfg)
	if err != nil && res == nil {
		return err
	}

	report := kitUnlockWalkReport{UnlockWalkResult: *res, Stored: saver.active(), StoreSkip: saver.skip}
	if globalJSON {
		if jerr := emitObject(cmd, ".", report); jerr != nil {
			return jerr
		}
	} else {
		printUnlockWalk(report)
	}
	return err
}

// checkUnlockOriginPin refuses a profile whose origin is not the one --origin
// pinned (both in the profile's normal form).
func checkUnlockOriginPin(profileOrigin, pin string) error {
	if pin == "" {
		return nil
	}
	normal, err := spitolas.NormalizeUnlockOrigin(pin)
	if err != nil {
		return clicommon.UsageErrorf("--origin: %v", err)
	}
	if normal != profileOrigin {
		return clicommon.UsageErrorf("the profile's origin %s is not the --origin %s; nothing launched", profileOrigin, normal)
	}
	return nil
}

// unlockOffOriginScope admits a URL off the profile's origin for storage only
// when the configured scope names hosts and admits it. An unconfigured scope
// (which admits every host for sending) and --ignore-scope keep storage to the
// origin, so a third-party API the page calls is never recorded as the
// target's traffic.
func unlockOffOriginScope(gate sendScopeGate) func(*url.URL) bool {
	if gate.ignore || gate.matcher == nil || !gate.matcher.RestrictsHosts() {
		return nil
	}
	return func(u *url.URL) bool {
		t := urlSendTarget(u)
		return gate.matcher.InScopeTarget(t.host, t.path)
	}
}

// printUnlockWalk renders a walk for a human: one line per navigation on
// stdout, the totals on stderr.
func printUnlockWalk(r kitUnlockWalkReport) {
	line := func(nav spitolas.UnlockRouteResult) {
		state := terminal.Bold("rendered")
		if nav.Redirected {
			state = "redirected → " + nav.FinalURL
		}
		if nav.Error != "" {
			state = "error: " + nav.Error
		}
		fmt.Printf("%-40s %-8s %s  requests=%d aborted=%d stubs=%d rewrites=%d clicks=%d\n",
			clicommon.Truncate(nav.Route, 40), nav.Navigation, state, len(nav.Requests), len(nav.AbortedWrites), len(nav.StubsHit), len(nav.RewritesHit), len(nav.Clicks))
		for _, q := range nav.Requests {
			via := ""
			if q.Via != "" {
				via = " (" + q.Via + ")"
			}
			fmt.Printf("    %s %s %d %s%s\n", q.Method, q.URL, q.Status, q.RecordUUID, via)
		}
		for _, a := range nav.AbortedWrites {
			fmt.Printf("    aborted %s %s\n", a.Method, a.URL)
		}
		for _, h := range nav.RewritesHit {
			outcome := fmt.Sprintf("%d → %d", h.UpstreamStatus, h.Status)
			if !h.Applied {
				outcome = "not applied: " + h.Error
			}
			fmt.Printf("    rewritten %s %s %s (not evidence)\n", h.Method, h.URL, outcome)
		}
		for _, c := range nav.Clicks {
			fmt.Printf("    clicked %s %q requests=%d\n", c.Kind, c.Label, c.Requests)
		}
	}
	line(r.Landing)
	for _, nav := range r.Routes {
		line(nav)
	}
	t := r.Totals
	fmt.Fprintf(os.Stderr, "%s %d route(s): %d rendered, %d redirected; %d real request(s), %d record(s) stored, %d write(s) aborted, %d stub hit(s)\n",
		terminal.InfoSymbol(), t.Routes, t.Rendered, t.Redirected, t.RealRequests, t.RecordsStored, t.AbortedWrites, t.StubsHit)
	if t.RewritesHit > 0 {
		fmt.Fprintf(os.Stderr, "%s %d rewrite hit(s), %d applied; rewritten answers are not stored\n", terminal.InfoSymbol(), t.RewritesHit, t.RewritesApplied)
	}
	if len(r.RewritesNeverHit) > 0 {
		fmt.Fprintf(os.Stderr, "%s %d rewrite(s) never hit\n", terminal.WarningSymbol(), len(r.RewritesNeverHit))
	}
	if r.ClicksRefused != "" {
		fmt.Fprintf(os.Stderr, "%s no controls clicked: %s\n", terminal.WarningSymbol(), r.ClicksRefused)
	}
	if len(r.StubsNeverHit) > 0 {
		fmt.Fprintf(os.Stderr, "%s %d stub(s) never hit\n", terminal.WarningSymbol(), len(r.StubsNeverHit))
	}
	if len(r.RoutesSkipped) > 0 {
		fmt.Fprintf(os.Stderr, "%s %d route(s) past maxRoutes not visited\n", terminal.WarningSymbol(), len(r.RoutesSkipped))
	}
	if r.StoreSkip != "" {
		fmt.Fprintf(os.Stderr, "%s nothing stored: %s\n", terminal.WarningSymbol(), r.StoreSkip)
	}
}
