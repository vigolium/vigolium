package runner

import (
	"context"
	"fmt"
	neturl "net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/portsweep"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// maxPortSweepHosts caps how many distinct CLI hosts are swept in one scan so a
// large -T target file can't fan out into an unbounded number of probes. When the
// CLI hosts exceed this, the excess is skipped (and announced — never silently).
const maxPortSweepHosts = 512

// maxHostSweepConcurrency bounds how many hosts are swept in parallel. Each host
// already probes its ports concurrently, so this is a second, outer level of
// fan-out kept deliberately small.
const maxHostSweepConcurrency = 8

// runPortSweepPhase sweeps the alternate HTTP(S) ports of each original CLI
// target host (deep / --follow-subdomains only). Confirmed web services are
// appended to r.options.Targets before the ingestion/scan phases run, so they
// flow through the normal native pipeline. Hosts that look like all-ports-open
// honeypots are discarded.
func (r *Runner) runPortSweepPhase(ctx context.Context, _ *phaseInfra) error {
	phaseStart := time.Now()

	hosts, existing, truncated := r.collectSweepHosts()
	if len(hosts) == 0 {
		return nil
	}

	// Zero scalar fields fall back to portsweep's built-in defaults inside Sweep,
	// so the config is passed through as-is (no separate resolve step). Ports is
	// resolved here too so the displayed list matches what the sweep probes.
	cfg := r.settings.ScanningStrategy.PortSweep
	ports := cfg.Ports
	if len(ports) == 0 {
		ports = portsweep.DefaultPorts
	}
	if override := parsePortList(r.options.PortSweepPorts); len(override) > 0 {
		ports = override
	}

	r.printPhaseStart("PortSweep", "probing common alternate HTTP(S) ports on CLI target hosts")
	r.printPhaseDetail(fmt.Sprintf("Hosts: %s | Ports: %s",
		terminal.Orange(fmt.Sprintf("%d", len(hosts))),
		terminal.HiTeal(formatPortList(ports))))
	if truncated > 0 {
		r.printPhaseDetail(terminal.Orange(fmt.Sprintf(
			"note: %d additional host(s) skipped (port-sweep host cap %d)", truncated, maxPortSweepHosts)))
	}

	opts := portsweep.Options{
		Ports:         ports,
		Concurrency:   cfg.Concurrency,
		DialTimeout:   time.Duration(cfg.DialTimeoutMs) * time.Millisecond,
		HTTPTimeout:   time.Duration(cfg.HTTPTimeoutMs) * time.Millisecond,
		HoneypotRatio: cfg.HoneypotRatio,
	}

	results := r.sweepHosts(ctx, hosts, opts)

	// Collect confirmed services, dedup against targets the user already passed,
	// and against each other (across hosts). Order is deterministic for output.
	var (
		added     []string
		honeypots int
	)
	for _, res := range results {
		if res.Honeypot {
			honeypots++
			zap.L().Info("PortSweep: host skipped as honeypot",
				zap.String("host", res.Host),
				zap.Int("tcp_open", res.TCPOpen),
				zap.Int("probed", res.Probed))
			r.printPhaseDetail(fmt.Sprintf("%s %s — %s",
				terminal.Orange(terminal.SymbolArrow),
				terminal.Gray(res.Host),
				terminal.Orange(fmt.Sprintf("honeypot suspected (%d/%d ports open, identical responses) — discarded", res.TCPOpen, res.Probed))))
			continue
		}
		for _, pr := range res.Open {
			key := res.Host + ":" + strconv.Itoa(pr.Port)
			if _, dup := existing[key]; dup {
				continue
			}
			existing[key] = struct{}{}
			url := pr.URL(res.Host)
			added = append(added, url)
			if !r.options.Silent {
				server := pr.Server
				if server == "" {
					server = "?"
				}
				r.printPhaseDetail(fmt.Sprintf("%s %s (%s, %d, server: %s) — added",
					terminal.Green(terminal.SymbolArrow),
					terminal.Orange(fmt.Sprintf("%s:%d", res.Host, pr.Port)),
					pr.Scheme, pr.Status, terminal.Gray(server)))
			}
		}
	}

	if len(added) > 0 {
		r.options.Targets = append(r.options.Targets, added...)
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseDetail(fmt.Sprintf("Result: %s service(s) added, %s honeypot(s) discarded | Elapsed: %s",
		terminal.Orange(fmt.Sprintf("%d", len(added))),
		terminal.Orange(fmt.Sprintf("%d", honeypots)),
		terminal.Orange(fmtDuration(elapsed))))
	r.scanLogger.InfoWithMeta("port-sweep", "sweep complete", map[string]interface{}{
		"hosts":     len(hosts),
		"added":     len(added),
		"honeypots": honeypots,
		"ports":     len(ports),
		"truncated": truncated,
	})

	return nil
}

// sweepHosts runs portsweep.Sweep over hosts with bounded outer concurrency and
// returns the results in the same order as hosts.
func (r *Runner) sweepHosts(ctx context.Context, hosts []string, opts portsweep.Options) []portsweep.Result {
	results := make([]portsweep.Result, len(hosts))
	conc := maxHostSweepConcurrency
	if len(hosts) < conc {
		conc = len(hosts)
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for i, host := range hosts {
		select {
		case <-ctx.Done():
			wg.Wait()
			return results
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = portsweep.Sweep(ctx, host, opts)
		}(i, host)
	}
	wg.Wait()
	return results
}

// collectSweepHosts returns the distinct hostnames among the original CLI
// targets (capped at maxPortSweepHosts), the set of host:port pairs already
// targeted (so the sweep never re-adds a port the user passed explicitly), and
// the number of hosts skipped by the cap.
func (r *Runner) collectSweepHosts() (hosts []string, existing map[string]struct{}, truncated int) {
	existing = make(map[string]struct{})
	seen := make(map[string]struct{})
	for _, t := range r.options.Targets {
		host, port := hostAndPort(t)
		if host == "" {
			continue
		}
		if port != "" {
			existing[host+":"+port] = struct{}{}
		}
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		if len(hosts) >= maxPortSweepHosts {
			truncated++
			continue
		}
		hosts = append(hosts, host)
	}
	return hosts, existing, truncated
}

// hostAndPort extracts the lowercased hostname and (resolved) numeric port from a
// target URL. The port is the explicit one when present, otherwise the scheme
// default (https→443, http→80). Returns an empty host when the target cannot be
// parsed into one.
func hostAndPort(target string) (host, port string) {
	raw := strings.TrimSpace(target)
	if raw == "" {
		return "", ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := neturl.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", ""
	}
	host = strings.ToLower(u.Hostname())
	if p := u.Port(); p != "" {
		return host, p
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return host, "80"
	case "https":
		return host, "443"
	default:
		return host, ""
	}
}

// parsePortList parses a comma-separated port list, ignoring blanks and
// out-of-range / non-numeric entries. Returns nil when nothing valid is present.
func parsePortList(csv string) []int {
	if strings.TrimSpace(csv) == "" {
		return nil
	}
	var out []int
	seen := make(map[int]struct{})
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > 65535 {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

// formatPortList renders a port slice as a compact comma-separated string.
func formatPortList(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}
