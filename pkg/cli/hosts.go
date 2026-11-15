package cli

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/agent/recon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/tlsprobe"
)

// `vigolium hosts` reads what runs observed about hosts rather than about
// requests: DNS answers, the TLS handshake and certificate, the fingerprint
// phase's report and the not-found baseline. They live in host_observations,
// one row per (run, hostname, port); records only carry the single `ip`.

var (
	hostsHost         string
	hostsScanUUID     string
	hostsHistory      bool
	hostsHas          string
	hostsSoftNotFound bool
	hostsSANs         bool
	hostsLimit        int
	hostsOffset       int
	hostsFrom         string
	hostsTo           string
)

var hostsCmd = &cobra.Command{
	Use:   "hosts [host-pattern]",
	Short: "Read stored host facts: DNS, TLS certificate, fingerprint and not-found baseline",
	Long: "List what runs observed per host:port — DNS answers (`vigolium dns`, the probe phase), the TLS " +
		"handshake and leaf certificate (`run probe --tls-probe`, the fingerprint phase), the fingerprint report " +
		"and the not-found baseline (`vigolium fingerprint`). The latest observation per endpoint by default; " +
		"--history for every run's. DNS-only rows carry port 0. Never sends a request.",
	Example: "  vigolium hosts -j --compact\n" +
		"  vigolium hosts '*.example.com' --format tsv --fields hostname,port,title,server,favicon_mmh3\n" +
		"  vigolium hosts --has tls --sans            # certificate SANs, one per line: a ready -T list\n" +
		"  vigolium hosts --soft-404 -j               # origins answering 200 to a missing path",
	Args: cobra.MaximumNArgs(1),
	RunE: runHosts,
}

func init() {
	rootCmd.AddCommand(hostsCmd)
	f := hostsCmd.Flags()
	f.StringVar(&hostsHost, "host", "", "Only this hostname, or a pattern with * wildcards (same as the positional)")
	f.StringVar(&hostsScanUUID, "scan-uuid", "", "Only observations recorded by this run")
	f.BoolVar(&hostsHistory, "history", false, "Every observation, not just the latest per host:port")
	f.StringVar(&hostsHas, "has", "", "Only hosts carrying this fact: "+strings.Join(database.HostObservationHasValues(), ", "))
	f.BoolVar(&hostsSoftNotFound, "soft-404", false, "Only origins that answer 2xx/3xx to a path that does not exist")
	f.BoolVar(&hostsSANs, "sans", false, "Print the distinct DNS names in the matched certificates' SANs, one per line, and nothing else")
	registerTimeRangeFlags(hostsCmd, &hostsFrom, &hostsTo, "observations made")
	f.IntVarP(&hostsLimit, "limit", "n", 100, "Maximum hosts to list (0 = all)")
	f.IntVar(&hostsOffset, "offset", 0, "Hosts to skip (pagination)")
	f.BoolVarP(&globalStateless, "stateless", "S", false, "Read from --db (a standalone .sqlite) with project scoping off; never writes to your project DB")
	registerRowShapingFlags(f)
	registerTSVFlags(f)
}

// hostView is one `hosts -j` row: the stored observation plus the handful of
// facts a survey reads, lifted to the top so --fields and --format tsv reach
// them.
type hostView struct {
	Hostname   string `json:"hostname"`
	Port       int    `json:"port"`
	Origin     string `json:"origin,omitempty"`
	ObservedAt string `json:"observed_at"`
	ScanUUID   string `json:"scan_uuid,omitempty"`
	Complete   bool   `json:"complete"`

	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	CNAME []string `json:"cname,omitempty"`
	MX    []string `json:"mx,omitempty"`
	NS    []string `json:"ns,omitempty"`
	TXT   []string `json:"txt,omitempty"`
	SOA   []string `json:"soa,omitempty"`
	CAA   []string `json:"caa,omitempty"`

	// Survey facts, lifted from the nested documents below.
	Title        string   `json:"title,omitempty"`
	Server       string   `json:"server,omitempty"`
	StatusCode   int      `json:"status_code,omitempty"`
	Technology   []string `json:"technology,omitempty"`
	FaviconMMH3  *int32   `json:"favicon_mmh3,omitempty"`
	SoftNotFound *bool    `json:"soft_not_found,omitempty"`
	TLSVersion   string   `json:"tls_version,omitempty"`
	CertNotAfter string   `json:"cert_not_after,omitempty"`
	SANs         []string `json:"sans,omitempty"`

	// Favicon is the origin's icon: the probe's --favicon read, else the
	// fingerprint report's. FaviconMMH3 lifts its mmh3.
	Favicon     *recon.FaviconInfo         `json:"favicon,omitempty"`
	TLS         *tlsprobe.Info             `json:"tls,omitempty"`
	Fingerprint *recon.TechStackReport     `json:"fingerprint,omitempty"`
	NotFound    *database.NotFoundBaseline `json:"not_found,omitempty"`
}

// hostsShaping is hosts' --fields vocabulary; --compact drops the nested
// documents and keeps the lifted survey facts.
var hostsShaping = rowShaping{path: "hosts", defaultTSV: []string{"hostname", "port", "status_code", "title", "server", "favicon_mmh3", "soft_not_found"}}

func newHostView(o *database.HostObservation) hostView {
	v := hostView{
		Hostname: o.Hostname, Port: o.Port, ObservedAt: o.ObservedAt.UTC().Format("2006-01-02T15:04:05Z"),
		ScanUUID: o.ScanUUID, Complete: o.Complete,
		A: o.DNSA, AAAA: o.DNSAAAA, CNAME: o.DNSCNAME, MX: o.DNSMX, NS: o.DNSNS, TXT: o.DNSTXT, SOA: o.DNSSOA, CAA: o.DNSCAA,
		TLS: o.TLS, Fingerprint: o.Fingerprint, NotFound: o.NotFound,
	}
	if o.Port != 0 {
		scheme := "http"
		if o.Port == 443 || (o.TLS != nil && o.TLS.ProbeStatus) {
			scheme = "https"
		}
		v.Origin = hostLabel(scheme, o.Hostname, o.Port)
	}
	if fp := o.Fingerprint; fp != nil {
		v.Title, v.Server, v.StatusCode = fp.Title, fp.Server, fp.BaseStatus
		for _, s := range fp.Stacks {
			name := s.Name
			if s.Version != "" {
				name += ":" + s.Version
			}
			v.Technology = append(v.Technology, name)
		}
		v.Favicon = fp.Favicon
	}
	if o.Favicon != nil {
		v.Favicon = o.Favicon
	}
	if v.Favicon != nil {
		h := v.Favicon.MMH3
		v.FaviconMMH3 = &h
	}
	if o.NotFound != nil {
		soft := o.NotFound.SoftNotFound
		v.SoftNotFound = &soft
	}
	if t := o.TLS; t != nil && t.ProbeStatus {
		v.TLSVersion = t.TLSVersion
		if !t.NotAfter.IsZero() {
			v.CertNotAfter = t.NotAfter.UTC().Format("2006-01-02")
		}
		v.SANs = t.SubjectAN
	}
	return v
}

func runHosts(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()
	format, err := hostsShaping.prepare(cmd)
	if err != nil {
		return err
	}
	if hostsSANs && (globalJSON || format == "tsv") {
		return usageErrorf("--sans prints one name per line; drop -j/--format tsv")
	}
	pattern := strings.TrimSpace(hostsHost)
	if len(args) == 1 {
		if pattern != "" && pattern != args[0] {
			return usageErrorf("the positional host pattern and --host differ; pass one")
		}
		pattern = args[0]
	}
	if hostsHas != "" && !slices.Contains(database.HostObservationHasValues(), hostsHas) {
		return usageErrorf("--has %q: want one of %s", hostsHas, strings.Join(database.HostObservationHasValues(), ", "))
	}

	db, err := openReadDB(globDBSkipSet{})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	projectUUID, err := effectiveProjectUUID()
	if err != nil {
		return err
	}
	observedFrom, observedTo, err := parseDateRangeFlags(hostsFrom, hostsTo, timeFilterFromLabel, timeFilterToLabel)
	if err != nil {
		return err
	}
	q := database.HostObservationQuery{
		ProjectUUID: projectUUID, ScanUUID: strings.TrimSpace(hostsScanUUID), HostPattern: pattern,
		History: hostsHistory, Has: hostsHas, SoftNotFound: hostsSoftNotFound,
		ObservedFrom: observedFrom, ObservedTo: observedTo,
		Limit: hostsLimit, Offset: hostsOffset,
	}
	if hostsSANs {
		// Every matching host, but only those that carry a certificate.
		q.Limit, q.Offset = 0, 0
		if q.Has == "" {
			q.Has = "tls"
		}
	}
	rows, total, err := database.NewRepository(db).ListHostObservationsWithCount(context.Background(), q)
	if err != nil {
		return err
	}
	views := make([]hostView, 0, len(rows))
	for _, r := range rows {
		views = append(views, newHostView(r))
	}

	switch {
	case hostsSANs:
		return printHostSANs(views)
	case globalJSON:
		items, err := hostsShaping.apply(views)
		if err != nil {
			return err
		}
		opts := []envOpt{withProjectScope(projectUUID), withDBPath(resolvedReadDBPath())}
		if len(views) > 0 && views[0].Origin != "" {
			opts = append(opts, withQuery("traffic", "--host", views[0].Hostname, "--json", "--compact"))
		}
		return emitRead(cmd, "", items, int64(total), hostsOffset, hostsLimit, opts...)
	case format == "tsv":
		return hostsShaping.emitTSV(views)
	}
	printHostsTable(views, total)
	return nil
}

// printHostSANs prints the distinct certificate DNS names, wildcards dropped
// (there is no host to send to at *.example.com), one per line.
func printHostSANs(views []hostView) error {
	seen := map[string]bool{}
	var names []string
	for _, v := range views {
		for _, n := range v.SANs {
			n = strings.ToLower(strings.TrimSpace(n))
			if n == "" || strings.HasPrefix(n, "*") || seen[n] {
				continue
			}
			seen[n] = true
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Println(n)
	}
	return nil
}

func printHostsTable(views []hostView, total int) {
	if len(views) == 0 {
		fmt.Fprintf(os.Stderr, "%s No host observations stored. Run %s, %s, or %s first.\n", terminal.InfoSymbol(),
			terminal.Cyan("vigolium fingerprint -t <url>"), terminal.Cyan("vigolium dns <host>"),
			terminal.Cyan("vigolium run probe -T hosts.txt --tls-probe"))
		return
	}
	for _, v := range views {
		where := v.Hostname
		if v.Port != 0 {
			where += ":" + strconv.Itoa(v.Port)
		}
		line := terminal.BoldCyan(where)
		var parts []string
		if v.StatusCode != 0 {
			parts = append(parts, strconv.Itoa(v.StatusCode))
		}
		if v.Title != "" {
			parts = append(parts, strconv.Quote(v.Title))
		}
		if v.Server != "" {
			parts = append(parts, v.Server)
		}
		if len(v.A) > 0 {
			parts = append(parts, strings.Join(v.A, ","))
		}
		if v.TLSVersion != "" {
			parts = append(parts, v.TLSVersion)
		}
		if v.FaviconMMH3 != nil {
			parts = append(parts, "favicon "+strconv.Itoa(int(*v.FaviconMMH3)))
		}
		if v.SoftNotFound != nil && *v.SoftNotFound {
			parts = append(parts, terminal.Orange("soft-404"))
		}
		if len(v.Technology) > 0 {
			parts = append(parts, strings.Join(v.Technology, ","))
		}
		fmt.Printf("%s  %s\n", line, strings.Join(parts, "  "))
	}
	if total > len(views) {
		fmt.Fprintf(os.Stderr, "%s showing %d of %d; page with --offset or raise -n\n", terminal.InfoSymbol(), len(views), total)
	}
}
