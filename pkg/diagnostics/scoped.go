package diagnostics

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/http/proxyenv"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// Scoped readiness (`vigolium doctor --for scan|agent|server`).
//
// The full report answers "what is installed"; a scoped report answers "can I
// do X right now": each check says whether it COUNTS toward the verdict for
// that purpose, what it affects when it fails, and the argv that fixes it, and
// the verdict is the worst counted check — so `doctor --for scan` exits 1
// exactly when a scan would not work.

// Purposes `doctor --for` accepts.
const (
	PurposeScan   = "scan"
	PurposeAgent  = "agent"
	PurposeServer = "server"
)

// Purposes lists the valid --for values.
var Purposes = []string{PurposeScan, PurposeAgent, PurposeServer}

// Scoped check statuses. A counted check's status feeds the verdict:
// not_ready > degraded > ok; warning and skipped never do.
const (
	ScopedOK       = "ok"
	ScopedDegraded = "degraded"
	ScopedNotReady = "not_ready"
	ScopedWarning  = "warning"
	ScopedSkipped  = "skipped"
)

// ScopedCheck is one row of a scoped report.
type ScopedCheck struct {
	ID      string   `json:"id"`
	Status  string   `json:"status"`
	Counts  bool     `json:"counts"`
	Affects []string `json:"affects,omitempty"`
	Message string   `json:"message,omitempty"`
	FixArgv []string `json:"fix_argv,omitempty"`
}

// ScopedReport is the readiness of one purpose.
type ScopedReport struct {
	For    string        `json:"for"`
	Status Status        `json:"status"` // ready | degraded | not_ready
	Checks []ScopedCheck `json:"checks"`
}

// ScopedDeps are the inputs a scoped report needs beyond the full Report.
type ScopedDeps struct {
	Settings *config.Settings
	// Stateless skips the database check (-S scans use a temporary store).
	Stateless bool
	// Proxy is the --proxy URL. With it unset, the environment's proxies
	// (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY, NO_PROXY) are checked instead.
	Proxy string
	// Getenv reads the environment for the proxy variables (os.Getenv when
	// nil).
	Getenv func(string) string
	// Target, when set, adds DNS/TCP/TLS checks for that URL (doctor -t).
	Target string
	// DBDir is the database directory checked for free space ("" skips it).
	DBDir string
}

// Probes are the side-effecting checks, replaceable in tests.
var (
	scopedFreeBytes = freeBytes
	scopedFDLimit   = fdLimit
	scopedDial      = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	scopedLookupHost = net.DefaultResolver.LookupHost
	scopedNow        = time.Now
)

// Thresholds.
const (
	diskNotReadyBytes = 200 << 20 // < 200 MB free: a scan cannot write its store
	diskDegradedBytes = 1 << 30   // < 1 GB free: a large crawl will run out
	fdDegradedLimit   = 4096
	templatesStaleAge = 30 * 24 * time.Hour
	probeTimeout      = 5 * time.Second
)

// ValidPurpose reports whether p is a --for value.
func ValidPurpose(p string) bool {
	for _, v := range Purposes {
		if p == v {
			return true
		}
	}
	return false
}

// Scoped derives the readiness of purpose from a full report plus the scoped
// probes. Unknown purposes return an error.
func Scoped(purpose string, r *Report, deps ScopedDeps) (*ScopedReport, error) {
	if !ValidPurpose(purpose) {
		return nil, fmt.Errorf("unknown purpose %q (want one of: %s)", purpose, strings.Join(Purposes, ", "))
	}
	if r == nil {
		r = &Report{}
	}
	settings := deps.Settings
	if settings == nil {
		settings = config.DefaultSettings()
	}
	out := &ScopedReport{For: purpose}
	add := func(c ScopedCheck) { out.Checks = append(out.Checks, c) }

	add(fromResult("config", r.Config, ScopedDegraded, []string{"every setting (scope, pace, OAST) falls back to defaults"}))
	if purpose == PurposeScan && deps.Stateless {
		add(ScopedCheck{ID: "database", Status: ScopedSkipped, Counts: false, Message: "stateless (-S): the scan uses a temporary database"})
	} else {
		add(fromResult("database", r.Database, ScopedNotReady, []string{"storing records and findings"}))
	}

	switch purpose {
	case PurposeScan:
		add(fromResult("scope", r.Scope, ScopedDegraded, []string{"requests the broken rule touches"}))
		choice := proxyenv.Resolve(deps.Proxy, deps.Getenv)
		for _, c := range checkProxies(choice) {
			add(c)
		}
		add(checkDisk(deps.DBDir))
		add(checkFDs())
		add(chromiumCheck(r))
		add(templatesCheck(settings, r))
		var js *CheckResult
		if r.EmbeddedBinaries != nil {
			js = r.EmbeddedBinaries["jstangle"]
		}
		add(fromResult("jstangle", js, ScopedDegraded, []string{"JavaScript endpoint extraction in discovery"}))
		add(oastCheck(r.OAST))
		if deps.Target != "" {
			for _, c := range checkTarget(deps.Target, targetProxy(choice, deps.Target)) {
				add(c)
			}
		}
	case PurposeAgent:
		add(agentCheck(r.Agent))
		add(fromResult("sessions_dir", r.SessionsDir, ScopedDegraded, []string{"agent session persistence"}))
		add(fromResult("templates_dir", r.TemplatesDir, ScopedDegraded, []string{"agent prompt templates"}))
		add(chromiumCheck(r))
	case PurposeServer:
		add(fromResult("scope", r.Scope, ScopedDegraded, []string{"requests the broken rule touches"}))
		if r.Queue != nil {
			add(fromResult("queue", r.Queue, ScopedNotReady, []string{"server scan queue"}))
		}
		add(checkDisk(deps.DBDir))
		add(checkFDs())
	}

	out.Status = scopedVerdict(out.Checks)
	return out, nil
}

// scopedVerdict is the worst counted check.
func scopedVerdict(checks []ScopedCheck) Status {
	verdict := Status("ready")
	for _, c := range checks {
		if !c.Counts {
			continue
		}
		switch c.Status {
		case ScopedNotReady:
			return "not_ready"
		case ScopedDegraded:
			verdict = "degraded"
		}
	}
	return verdict
}

// fromResult maps a full-report check onto a scoped one: an error (or, for
// blocking checks, a warning too when failStatus is not_ready) takes
// failStatus; a warning on a non-blocking check is degraded.
func fromResult(id string, c *CheckResult, failStatus string, affects []string) ScopedCheck {
	sc := ScopedCheck{ID: id, Counts: true}
	if c == nil {
		sc.Status = ScopedSkipped
		sc.Counts = false
		sc.Message = "not checked"
		return sc
	}
	sc.Message = c.Message
	switch c.Status {
	case StatusOK:
		sc.Status = ScopedOK
	case StatusWarning:
		sc.Status = ScopedDegraded
		if failStatus == ScopedNotReady {
			sc.Status = ScopedNotReady
		}
		sc.Affects = affects
	default:
		sc.Status = failStatus
		sc.Affects = affects
	}
	return sc
}

func chromiumCheck(r *Report) ScopedCheck {
	t := r.Tools["chromium"]
	fix := []string{"vigolium", "doctor", "--fix", "--only", "chrome"}
	if t == nil {
		return ScopedCheck{ID: "chromium", Status: ScopedSkipped, Message: "not checked"}
	}
	msg := toolMsg(t)
	if t.Status == StatusOK {
		return ScopedCheck{ID: "chromium", Status: ScopedOK, Counts: true, Message: msg}
	}
	return ScopedCheck{ID: "chromium", Status: ScopedDegraded, Counts: true, Message: msg,
		Affects: []string{"spidering (browser crawl)", "DOM XSS confirmation"}, FixArgv: fix}
}

func toolMsg(t *ToolCheck) string {
	if t.Message != "" {
		return t.Message
	}
	return t.Path
}

// templatesCheck: missing templates degrade (no known-issue scan); stale
// templates are reported, not counted.
func templatesCheck(settings *config.Settings, r *Report) ScopedCheck {
	fix := []string{"vigolium", "doctor", "--fix", "--only", "nuclei"}
	dir := NucleiTemplatesDir(settings)
	if r.NucleiTemplates != nil && r.NucleiTemplates.Status != StatusOK {
		return ScopedCheck{ID: "nuclei_templates", Status: ScopedDegraded, Counts: true,
			Message: r.NucleiTemplates.Message, Affects: []string{"known-issue scan (nuclei)"}, FixArgv: fix}
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return ScopedCheck{ID: "nuclei_templates", Status: ScopedDegraded, Counts: true,
			Message: "nuclei templates not found at " + config.ContractPath(dir), Affects: []string{"known-issue scan (nuclei)"}, FixArgv: fix}
	}
	if age, ok := TemplatesAge(dir); ok && age > templatesStaleAge {
		return ScopedCheck{ID: "nuclei_templates", Status: ScopedWarning, Counts: false,
			Message: fmt.Sprintf("templates at %s are %d days old", config.ContractPath(dir), int(age.Hours()/24)),
			Affects: []string{"known-issue scan misses recent CVEs"}, FixArgv: fix}
	}
	return ScopedCheck{ID: "nuclei_templates", Status: ScopedOK, Counts: true, Message: "path=" + config.ContractPath(dir)}
}

// TemplatesAge is how old the templates install is: the pinned marker's
// install time when present (TemplatesMarkerFile), else the directory's mtime.
func TemplatesAge(dir string) (time.Duration, bool) {
	if m, err := ReadTemplatesMarker(dir); err == nil && !m.InstalledAt.IsZero() {
		return scopedNow().Sub(m.InstalledAt), true
	}
	info, err := os.Stat(dir)
	if err != nil {
		return 0, false
	}
	return scopedNow().Sub(info.ModTime()), true
}

func oastCheck(c *CheckResult) ScopedCheck {
	sc := fromResult("oast", c, ScopedDegraded, []string{"blind (out-of-band) checks"})
	// OAST disabled by config is a choice, not a failure.
	if c != nil && c.Status == StatusWarning {
		sc.Status = ScopedWarning
		sc.Counts = false
	}
	return sc
}

func agentCheck(a *AgentCheck) ScopedCheck {
	if a == nil {
		return ScopedCheck{ID: "agent", Status: ScopedSkipped, Message: "not checked"}
	}
	if a.Status == StatusOK && a.Unverified {
		return probeAgentEndpoint(a)
	}
	if a.Status == StatusOK {
		return ScopedCheck{ID: "agent", Status: ScopedOK, Counts: true, Message: a.Name}
	}
	return ScopedCheck{ID: "agent", Status: ScopedNotReady, Counts: true, Message: a.Name + ": " + a.Message,
		Affects: []string{"every agent mode"}}
}

// checkProxies checks every proxy target traffic may go through, naming
// where each came from and which requests it carries.
func checkProxies(choice proxyenv.Choice) []ScopedCheck {
	var out []ScopedCheck
	if err := choice.Err(); err != nil {
		out = append(out, ScopedCheck{ID: "proxy", Status: ScopedNotReady, Counts: true, Message: err.Error(),
			Affects: []string{"every proxied request"}})
	}
	routes := choice.Routes()
	for _, r := range choice.Proxies() {
		c := checkProxy(r.URL.String())
		var schemes []string
		for _, v := range routes {
			if v.Source == r.Source {
				schemes = append(schemes, v.Scheme)
			}
		}
		carries := "every request"
		if !r.Everything {
			carries = strings.Join(schemes, ", ") + " targets"
		}
		c.Message += fmt.Sprintf(" (from %s, for %s", r.Source, carries)
		if v, src := choice.NoProxy(); v != "" {
			c.Message += "; " + src + "=" + v
		}
		if !r.Everything {
			c.Message += "; loopback is not bypassed unless NO_PROXY names it"
		}
		c.Message += ")"
		out = append(out, c)
	}
	return out
}

// targetProxy is the proxy URL a request to target goes through, "" when it
// connects directly.
func targetProxy(choice proxyenv.Choice, target string) string {
	raw := target
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if r := choice.For(u); r != nil {
		return r.Redacted()
	}
	return ""
}

func checkProxy(proxy string) ScopedCheck {
	u, err := url.Parse(proxy)
	if err != nil || u.Host == "" {
		return ScopedCheck{ID: "proxy", Status: ScopedNotReady, Counts: true, Message: "unparseable --proxy " + proxy,
			Affects: []string{"every request"}}
	}
	host := u.Host
	if u.Port() == "" {
		switch u.Scheme {
		case "https":
			host += ":443"
		case "socks5", "socks5h":
			host += ":1080"
		default:
			host += ":80"
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	conn, err := scopedDial(ctx, "tcp", host)
	if err != nil {
		return ScopedCheck{ID: "proxy", Status: ScopedNotReady, Counts: true,
			Message: fmt.Sprintf("proxy %s unreachable: %v", host, err), Affects: []string{"every request"}}
	}
	_ = conn.Close()
	return ScopedCheck{ID: "proxy", Status: ScopedOK, Counts: true, Message: "reachable: " + host}
}

func checkDisk(dbDir string) ScopedCheck {
	dirs := []string{os.TempDir()}
	if dbDir != "" {
		dirs = append(dirs, dbDir)
	}
	status := ScopedOK
	var parts []string
	for _, d := range dirs {
		free, ok := scopedFreeBytes(existingParent(d))
		if !ok {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s: %s free", config.ContractPath(d), terminal.HumanBytes(int64(free))))
		switch {
		case free < diskNotReadyBytes:
			status = ScopedNotReady
		case free < diskDegradedBytes && status == ScopedOK:
			status = ScopedDegraded
		}
	}
	if len(parts) == 0 {
		return ScopedCheck{ID: "disk", Status: ScopedSkipped, Message: "free space not measurable on this platform"}
	}
	sc := ScopedCheck{ID: "disk", Status: status, Counts: true, Message: strings.Join(parts, ", ")}
	if status != ScopedOK {
		sc.Affects = []string{"the scan database and temp files"}
	}
	return sc
}

func existingParent(d string) string {
	for d != "" {
		if _, err := os.Stat(d); err == nil {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	return d
}

func checkFDs() ScopedCheck {
	limit, ok := scopedFDLimit()
	if !ok {
		return ScopedCheck{ID: "fd_limit", Status: ScopedSkipped, Message: "not measurable on this platform"}
	}
	if limit < fdDegradedLimit {
		return ScopedCheck{ID: "fd_limit", Status: ScopedDegraded, Counts: true,
			Message: fmt.Sprintf("open-file limit %d < %d; raise it with `ulimit -n 65535`", limit, fdDegradedLimit),
			Affects: []string{"concurrency (connections, browser, DB) fails with 'too many open files'"}}
	}
	return ScopedCheck{ID: "fd_limit", Status: ScopedOK, Counts: true, Message: fmt.Sprintf("open-file limit %d", limit)}
}

// checkTarget probes the target URL: DNS, TCP and (for https) TLS. Behind a
// proxy the direct DNS/TCP probes are skipped — the proxy resolves and
// connects.
func checkTarget(raw, proxy string) []ScopedCheck {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return []ScopedCheck{{ID: "target", Status: ScopedNotReady, Counts: true, Message: "unparseable target " + raw}}
	}
	if proxy != "" {
		return []ScopedCheck{{ID: "target_dns", Status: ScopedSkipped, Message: "behind the proxy " + proxy + ": the proxy resolves and connects"}}
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	var out []ScopedCheck
	if net.ParseIP(host) == nil {
		addrs, err := scopedLookupHost(ctx, host)
		if err != nil || len(addrs) == 0 {
			return append(out, ScopedCheck{ID: "target_dns", Status: ScopedNotReady, Counts: true,
				Message: fmt.Sprintf("%s does not resolve: %v", host, err), Affects: []string{"the whole scan"}})
		}
		sort.Strings(addrs)
		out = append(out, ScopedCheck{ID: "target_dns", Status: ScopedOK, Counts: true, Message: host + " → " + strings.Join(addrs, ", ")})
	}
	addr := net.JoinHostPort(host, port)
	conn, err := scopedDial(ctx, "tcp", addr)
	if err != nil {
		return append(out, ScopedCheck{ID: "target_tcp", Status: ScopedNotReady, Counts: true,
			Message: fmt.Sprintf("cannot connect to %s: %v", addr, err), Affects: []string{"the whole scan"}})
	}
	out = append(out, ScopedCheck{ID: "target_tcp", Status: ScopedOK, Counts: true, Message: "connected to " + addr})
	if u.Scheme != "https" {
		_ = conn.Close()
		return out
	}
	tc := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true}) //nolint:gosec // reachability probe, not trust
	_ = tc.SetDeadline(time.Now().Add(probeTimeout))
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return append(out, ScopedCheck{ID: "target_tls", Status: ScopedNotReady, Counts: true,
			Message: fmt.Sprintf("TLS handshake with %s failed: %v", addr, err), Affects: []string{"the whole scan"}})
	}
	_ = tc.Close()
	return append(out, ScopedCheck{ID: "target_tls", Status: ScopedOK, Counts: true, Message: "TLS handshake ok"})
}

// probeAgentEndpoint opens a TCP connection to an endpoint provider's base
// URL: `--for agent` is where a provider is actually reached.
func probeAgentEndpoint(a *AgentCheck) ScopedCheck {
	u, err := url.Parse(a.Endpoint)
	if err != nil || u.Host == "" {
		return ScopedCheck{ID: "agent", Status: ScopedNotReady, Counts: true,
			Message: "unparseable provider endpoint " + a.Endpoint, Affects: []string{"every agent mode"}}
	}
	host := u.Host
	if u.Port() == "" {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	conn, err := scopedDial(ctx, "tcp", host)
	if err != nil {
		return ScopedCheck{ID: "agent", Status: ScopedNotReady, Counts: true,
			Message: fmt.Sprintf("%s: endpoint %s unreachable: %v", a.Protocol, a.Endpoint, err),
			Affects: []string{"every agent mode"}}
	}
	_ = conn.Close()
	return ScopedCheck{ID: "agent", Status: ScopedOK, Counts: true, Message: fmt.Sprintf("%s: endpoint %s reachable", a.Protocol, a.Endpoint)}
}

// ProxyCheck is the full report's proxy row: which proxy every request goes
// through, where it was configured, and whether it accepts a connection.
// Loopback targets are not exempt from it (an explicit proxy URL, unlike Go's
// environment resolver, proxies localhost too).
func ProxyCheck(route *proxyenv.Route, source string) *CheckResult {
	if route == nil || route.URL == nil {
		return &CheckResult{Status: StatusOK, Message: "none: requests connect directly"}
	}
	msg := fmt.Sprintf("%s from %s; loopback targets go through it too", route.Redacted(), source)
	if !route.Everything {
		msg += " unless NO_PROXY names them"
	}
	sc := checkProxy(route.URL.String())
	if sc.Status != ScopedOK {
		return &CheckResult{Status: StatusError, Message: msg + " — " + sc.Message,
			Tip: "Start the proxy, or remove it (" + source + ") to connect directly."}
	}
	return &CheckResult{Status: StatusOK, Message: msg, Details: []string{sc.Message}}
}
