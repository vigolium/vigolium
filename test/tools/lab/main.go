// Command lab runs the expectation e2e kit's target fleet (test/e2e-expect/lab) as a
// standalone process, for pointing an installed vigolium at by hand:
//
//	go run ./test/tools/lab                 # random ports, prints the URLs
//	go run ./test/tools/lab -port-base 18000 -log
//	vigolium scan -T <(go run ./test/tools/lab -print-targets) ...
//
// On SIGINT/SIGTERM it prints what every server received (requests, peak
// concurrency, status mix) — the same ledger the tests assert on.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/test/e2e-expect/lab"
)

func main() {
	portBase := flag.Int("port-base", 0, "listen on consecutive ports from this one instead of random ports")
	logHits := flag.Bool("log", false, "print every request as it completes")
	printTargets := flag.Bool("print-targets", false, "print the plant/twin URLs one per line (for -T), then keep serving")
	jsonOut := flag.Bool("json", false, "print the fleet and the final ledger as JSON")
	flag.Parse()

	l := lab.New()
	l.PortBase = *portBase
	defer l.Close()

	sentinel := l.Serve("sentinel", lab.SafeEcho())
	offsite := sentinel.Origin("localhost")
	app := l.Serve("app", lab.VulnApp(lab.VulnAppOptions{OffsiteLinks: []string{offsite + "/partner?ref=lab"}}))
	l.Serve("minefield", lab.Minefield(lab.VulnAppOptions{}))
	l.Serve("throttled", lab.Throttled(lab.VulnApp(lab.VulnAppOptions{}), 15, time.Second))
	l.Serve("flaky", lab.Flaky(lab.VulnApp(lab.VulnAppOptions{}), 5))
	// The benign sweep's fixtures (waf_block, soft_404, slow_host, ...), each
	// on its own server under its fixture name.
	for _, f := range modtest.BenignFixtures() {
		l.Serve(f.Name, f.New())
	}
	l.Serve("hang", lab.Hang())
	l.Serve("loop", lab.RedirectLoop())
	l.ServeTLS("tls", lab.VulnApp(lab.VulnAppOptions{}))
	raws := []*lab.RawServer{
		l.ServeRaw("ssh", lab.SSHBanner),
		l.ServeRaw("garbage", lab.Garbage),
		l.ServeRaw("silent", lab.Silent),
	}
	dead := lab.DeadURL()

	type entry struct {
		Name string `json:"name"`
		URL  string `json:"url"`
		Note string `json:"note,omitempty"`
	}
	var fleet []entry
	for _, s := range l.Servers() {
		note := ""
		if s.Name == "sentinel" {
			note = "out of scope: linked from app as " + offsite + "; must receive 0 requests"
		}
		fleet = append(fleet, entry{s.Name, s.URL, note})
	}
	for _, r := range raws {
		fleet = append(fleet, entry{r.Name, r.URL, "raw TCP, not HTTP"})
	}
	fleet = append(fleet, entry{"dead", dead, "connection refused"})

	switch {
	case *printTargets:
		for _, p := range lab.Plants() {
			fmt.Println(p.URL(app.URL))
			fmt.Println(p.TwinURL(app.URL))
		}
	case *jsonOut:
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"servers": fleet, "plants": lab.Plants()})
	default:
		tw := tabwriter.NewWriter(os.Stderr, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "SERVER\tURL\tNOTE")
		for _, e := range fleet {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", e.Name, e.URL, e.Note)
		}
		_ = tw.Flush()
		fmt.Fprintln(os.Stderr, "\nplants on app (vulnerable → benign twin):")
		for _, p := range lab.Plants() {
			fmt.Fprintf(os.Stderr, "  %-18s %s  →  %s\n", p.Class, p.URL(app.URL), p.TwinURL(app.URL))
		}
		fmt.Fprintln(os.Stderr, "\nCtrl-C prints the ledger.")
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	seen := 0
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			report(l, *jsonOut)
			return
		case <-tick.C:
			if *logHits {
				hits := l.Ledger.HitsSince(seen)
				for _, h := range hits {
					q := ""
					if h.RawQuery != "" {
						q = "?" + h.RawQuery
					}
					fmt.Fprintf(os.Stderr, "%s %-10s %3d %s %s%s\n", h.End.Format("15:04:05.000"), h.Server, h.Status, h.Method, h.Path, clip(q, 120))
				}
				seen += len(hits)
			}
		}
	}
}

func report(l *lab.Lab, asJSON bool) {
	sums := l.Ledger.Summaries()
	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ledger": sums})
		return
	}
	tw := tabwriter.NewWriter(os.Stderr, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "\nSERVER\tREQUESTS\tCONNS\tPEAK\tSTATUS")
	for _, s := range sums {
		var parts []string
		for code, n := range s.Status {
			parts = append(parts, fmt.Sprintf("%d×%d", code, n))
		}
		_, _ = fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%s\n", s.Server, s.Requests, s.Conns, s.Peak, strings.Join(parts, " "))
	}
	_ = tw.Flush()
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
