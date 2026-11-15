package cli

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dnsresolve"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `vigolium dns` resolves names and stores the answers, so a later session reads
// them with `vigolium hosts` instead of re-running dig. Resolution only: zone
// transfers and subdomain brute force are not here.

var (
	dnsTypes       []string
	dnsResolvers   []string
	dnsIgnoreScope bool
	dnsNoStore     bool
	dnsConcurrency int
	dnsTimeout     time.Duration
)

var dnsCmd = &cobra.Command{
	Use:   "dns [name|url ...]",
	Short: "Resolve names (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA) and store the answers",
	Long: "Resolve each name — positional, -t, or one per line in -T — against the system resolver or " +
		"--resolver, and store the answers as host facts (read back with `vigolium hosts`; the A/AAAA/CNAME " +
		"also appear on `traffic -j` rows for that host). A URL is reduced to its hostname. Names outside the " +
		"configured host scope are refused unless --ignore-scope. Resolution only: no zone transfer, no brute force.",
	Example: "  vigolium dns example.com api.example.com -j\n" +
		"  vigolium dns -T hosts.txt --type a,cname --format tsv\n" +
		"  vigolium dns example.com --type mx,txt --resolver 1.1.1.1",
	RunE: runDNS,
}

func init() {
	rootCmd.AddCommand(dnsCmd)
	f := dnsCmd.Flags()
	f.StringArrayVarP(&globalTargets, "target", "t", nil, "Name or URL to resolve (repeatable)")
	f.StringArrayVarP(&globalTargetFiles, "target-file", "T", nil, "File of names or URLs, one per line (repeatable)")
	f.StringSliceVar(&dnsTypes, "type", nil, "Record types (comma-separated): "+strings.Join(dnsresolve.Types, ", ")+" (default all)")
	f.StringArrayVar(&dnsResolvers, "resolver", nil, "Resolver host[:port] to ask (repeatable; default the system resolver)")
	f.BoolVar(&dnsIgnoreScope, "ignore-scope", false, "Resolve names outside the configured host scope")
	f.BoolVar(&dnsNoStore, "no-store", false, "Print the answers without storing them")
	f.IntVarP(&dnsConcurrency, "concurrency", "c", defaultSendConcurrency, "Names resolved in parallel")
	f.DurationVar(&dnsTimeout, "timeout", 5*time.Second, "Per-query timeout")
	registerRowShapingFlags(f)
	registerTSVFlags(f)
}

// dnsShaping is dns' --fields vocabulary (one answer's keys); --compact drops
// the per-record list.
var dnsShaping = rowShaping{path: "dns"}

// dnsNames collects the names to resolve, hostnames only, deduplicated in order.
func dnsNames(args []string) ([]string, error) {
	raw := append(append([]string{}, args...), globalTargets...)
	lines, err := readTargetFilesLines(globalTargetFiles)
	if err != nil {
		return nil, err
	}
	raw = append(raw, lines...)
	var out []string
	seen := map[string]bool{}
	for _, r := range raw {
		name := hostOfNameOrURL(r)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out, nil
}

// hostOfNameOrURL reduces a URL or host[:port] to a lowercase hostname.
func hostOfNameOrURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "#") {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			s = u.Hostname()
		}
	} else if h, _, ok := strings.Cut(s, "/"); ok {
		s = h
	}
	if i := strings.LastIndex(s, ":"); i > 0 && !strings.Contains(s[:i], ":") {
		s = s[:i]
	}
	return strings.ToLower(strings.TrimSuffix(strings.Trim(s, "[]"), "."))
}

func runDNS(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()
	format, err := dnsShaping.prepare(cmd)
	if err != nil {
		return err
	}
	types, err := dnsresolve.ParseTypes(dnsTypes)
	if err != nil {
		return usageErrorf("--type: %v", err)
	}
	if dnsConcurrency < 1 {
		return usageErrorf("--concurrency must be >= 1, got %d", dnsConcurrency)
	}
	names, err := dnsNames(args)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return usageErrorf("no names to resolve: pass names, -t, or -T <file>")
	}
	gate, err := newSendScopeGate(dnsIgnoreScope)
	if err != nil {
		return err
	}
	if err := gate.check(names...); err != nil {
		return err
	}
	resolver, err := dnsresolve.New(dnsResolvers, dnsTimeout)
	if err != nil {
		return usageErrorf("%v", err)
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	answers := make([]dnsresolve.Answer, len(names))
	sem := make(chan struct{}, dnsConcurrency)
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, n string) {
			defer wg.Done()
			defer func() { <-sem }()
			answers[i] = resolver.Resolve(ctx, n, types)
		}(i, n)
	}
	wg.Wait()

	stored := 0
	if !dnsNoStore {
		if stored, err = storeDNSAnswers(ctx, answers); err != nil {
			return err
		}
	}

	switch {
	case globalJSON:
		items, err := dnsShaping.apply(answers)
		if err != nil {
			return err
		}
		return emitRead(cmd, "", items, int64(len(answers)), 0, len(answers),
			withExtra("stored", stored), withQuery("hosts", "--has", "dns", "--json"))
	case format == "tsv":
		return writeDNSTSV(answers)
	}
	for _, a := range answers {
		fmt.Printf("%s  %s\n", terminal.BoldCyan(a.Name), terminal.Gray(a.Rcode))
		for _, r := range a.Records {
			fmt.Printf("  %-6s %-6d %s\n", r.Type, r.TTL, r.Value)
		}
		for t, e := range a.Errors {
			fmt.Printf("  %s query failed: %s\n", strings.ToUpper(t), e)
		}
	}
	if !dnsNoStore && !globalSilent {
		fmt.Fprintf(os.Stderr, "%s stored %d answer(s); read them back with %s\n", terminal.InfoSymbol(), stored,
			terminal.Cyan("vigolium hosts --has dns"))
	}
	return nil
}

// writeDNSTSV prints one line per record (name, type, ttl, value), or per name
// with --fields.
func writeDNSTSV(answers []dnsresolve.Answer) error {
	if len(normalizeFieldList(jsonFields)) > 0 {
		return dnsShaping.emitTSV(answers)
	}
	columns := []string{"name", "type", "ttl", "value"}
	var rows []map[string]any
	for _, a := range answers {
		for _, r := range a.Records {
			rows = append(rows, map[string]any{"name": r.Name, "type": r.Type, "ttl": int64(r.TTL), "value": r.Value})
		}
	}
	return writeTSV(os.Stdout, columns, rows)
}

// storeDNSAnswers writes each name's answer to its port-0 host observation.
// A name whose every query failed stores nothing: there is no answer to keep.
func storeDNSAnswers(ctx context.Context, answers []dnsresolve.Answer) (int, error) {
	db, err := getDB()
	if err != nil {
		return 0, fmt.Errorf("failed to connect to database: %w", err)
	}
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return 0, err
	}
	obs := make([]database.HostObservationInput, 0, len(answers))
	for _, a := range answers {
		if len(a.Errors) > 0 && len(a.Records) == 0 && a.Rcode == "" {
			continue
		}
		in := database.HostObservationInput{Hostname: a.Name, Port: 0, Complete: len(a.Errors) == 0,
			MX: a.MX, NS: a.NS, TXT: a.TXT, SOA: a.SOA, CAA: a.CAA}
		in.A, in.AAAA, in.CNAME = a.A, a.AAAA, a.CNAME
		obs = append(obs, in)
	}
	if err := database.NewRepository(db).SaveHostObservations(ctx, projectUUID, "", obs); err != nil {
		return 0, err
	}
	return len(obs), nil
}
