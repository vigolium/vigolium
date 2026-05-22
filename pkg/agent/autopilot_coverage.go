package agent

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	oautopilot "github.com/vigolium/vigolium/pkg/olium/autopilot"
	"go.uber.org/zap"
)

// coverageProbeAdapter adapts *CoverageProbe to the interface autopilot.Run
// expects (oautopilot.CoverageProbeResultLite). Keeps the autopilot package
// free of any pkg/agent imports, breaking the would-be cycle.
type coverageProbeAdapter struct {
	inner *CoverageProbe
}

// Run runs the inner coverage probe and translates the result into the
// lite shape autopilot.Run consumes.
func (a *coverageProbeAdapter) Run(ctx context.Context) (*oautopilot.CoverageProbeResultLite, error) {
	res, err := a.inner.Run(ctx)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return &oautopilot.CoverageProbeResultLite{}, nil
	}
	return &oautopilot.CoverageProbeResultLite{NewSignatures: res.NewSignatures}, nil
}

// SnapshotSignatures forwards to the inner probe so the autopilot loop can
// take a baseline snapshot at run start.
func (a *coverageProbeAdapter) SnapshotSignatures(ctx context.Context) ([]string, error) {
	return a.inner.SnapshotSignatures(ctx)
}

// CoverageProbe runs a single deterministic discovery + OpenAPI/Swagger
// ingestion pass against a target, then snapshots the resulting http_record
// signatures. Used in two places:
//
//  1. Pre-flight (pipeline runner, before the agent starts) — populates the
//     project DB so the agent inherits known surface instead of starting
//     blank.
//  2. Post-halt verification (autopilot.Run, after the model calls halt_scan)
//     — re-runs the probe to surface any routes/specs the agent missed, then
//     diffs against the pre-halt snapshot to decide whether a re-entry is
//     warranted.
//
// All probe activity goes through runner.LaunchScan, which writes records to
// the project DB using the same model the agent's own tools use. The agent's
// query_records / inspect_record tools see them transparently on the next
// turn.
type CoverageProbe struct {
	// Target is the URL/hostname to probe. Required.
	Target string

	// ProjectUUID scopes the resulting http_records to the same project as
	// the autopilot run. Required.
	ProjectUUID string

	// AgenticScanUUID, when set, is recorded on the underlying Scan rows so
	// coverage-pass artifacts can be traced back to the parent autopilot
	// run.
	AgenticScanUUID string

	// ConfigPath optionally overrides the path to vigolium-configs.yaml so
	// the pass uses the same settings as the surrounding scan.
	ConfigPath string

	// Repo is the DB handle used for the snapshot diff. Required.
	Repo *database.Repository

	// Concurrency overrides the worker count. 0 = settings default.
	Concurrency int
}

// Validate returns nil iff the probe has the minimum information needed to
// run. Caller-side check so the higher-level pipeline can short-circuit
// rather than enter LaunchScan and fail mid-stream.
func (p *CoverageProbe) Validate() error {
	if p.Target == "" {
		return fmt.Errorf("coverage probe: Target is required")
	}
	if p.Repo == nil {
		return fmt.Errorf("coverage probe: Repo is required")
	}
	if p.ProjectUUID == "" {
		return fmt.Errorf("coverage probe: ProjectUUID is required")
	}
	return nil
}

// CoverageProbeResult summarizes a single coverage pass.
type CoverageProbeResult struct {
	// DiscoveryScanUUID is the Scan row created by the discovery pass. Empty
	// on a probe that skipped discovery (e.g. snapshot-only call).
	DiscoveryScanUUID string

	// SpecIngestScanUUID is the Scan row created by the OpenAPI/Swagger
	// ingestion pass. Empty when ingestion was skipped or no spec was
	// found.
	SpecIngestScanUUID string

	// SignaturesBefore is the set of (method, URL) signatures present in
	// the project for Target's hostname when Run() started.
	SignaturesBefore []string

	// SignaturesAfter is the same set after both passes completed.
	SignaturesAfter []string

	// NewSignatures = SignaturesAfter - SignaturesBefore. Sorted for
	// stable output.
	NewSignatures []string
}

// Run executes one coverage pass: a discovery scan followed by an
// api-spec-ingest module run, with a snapshot before/after. The two scans
// produce their own Scan rows in the DB (queryable from list_sessions /
// list_scans) so the operator can audit what the pass did even if the
// SignaturesAfter set ends up identical to the before set.
//
// Blocking. Errors from one phase don't abort the other — coverage is
// best-effort and a partial result is more useful than aborting the entire
// pass on a transient HTTP failure.
func (p *CoverageProbe) Run(ctx context.Context) (*CoverageProbeResult, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	hostname, err := extractHostname(p.Target)
	if err != nil {
		return nil, fmt.Errorf("coverage probe: %w", err)
	}

	result := &CoverageProbeResult{}

	before, err := p.snapshotSignatures(ctx, hostname)
	if err != nil {
		zap.L().Warn("coverage probe: snapshot-before failed", zap.Error(err))
	}
	result.SignaturesBefore = before

	// Phase 1: discovery. Crawls the target, populates http_records via
	// deparos. Modules empty so no active scanning fires; this is a pure
	// surface enumeration pass.
	discoveryParams := runner.LaunchParams{
		Targets:         []string{p.Target},
		ProjectUUID:     p.ProjectUUID,
		ConfigPath:      p.ConfigPath,
		EnableDiscovery: true,
		Repository:      p.Repo,
		Concurrency:     p.Concurrency,
		OnlyPhase:       "discovery",
	}
	if discRes, derr := runner.LaunchScan(ctx, discoveryParams); derr != nil {
		zap.L().Warn("coverage probe: discovery scan failed",
			zap.String("target", p.Target),
			zap.Error(derr))
	} else if discRes != nil {
		result.DiscoveryScanUUID = discRes.ScanUUID
	}

	// Phase 2: OpenAPI/Swagger ingestion. Runs only the api-spec-ingest
	// module against the records already in the project. SkipIngestion=true
	// prevents the runner from crawling again — we want it to operate on the
	// surface discovery just turned up.
	specParams := runner.LaunchParams{
		Targets:       []string{p.Target},
		ProjectUUID:   p.ProjectUUID,
		ConfigPath:    p.ConfigPath,
		Modules:       []string{"api-spec-ingest"},
		Repository:    p.Repo,
		Concurrency:   p.Concurrency,
		OnlyPhase:     "dynamic-assessment",
		SkipIngestion: true,
	}
	if specRes, serr := runner.LaunchScan(ctx, specParams); serr != nil {
		zap.L().Warn("coverage probe: spec ingest scan failed",
			zap.String("target", p.Target),
			zap.Error(serr))
	} else if specRes != nil {
		result.SpecIngestScanUUID = specRes.ScanUUID
	}

	after, err := p.snapshotSignatures(ctx, hostname)
	if err != nil {
		zap.L().Warn("coverage probe: snapshot-after failed", zap.Error(err))
	}
	result.SignaturesAfter = after

	result.NewSignatures = diffSignatures(before, after)
	return result, nil
}

// SnapshotSignatures captures the current set of (method, URL) signatures for
// the probe's target host without running any scans. Used by callers that
// need a pre-run baseline independent of Run() — e.g. the autopilot post-halt
// loop snapshots when the agent starts so it can compare against what
// the model + the post-halt probe produced.
func (p *CoverageProbe) SnapshotSignatures(ctx context.Context) ([]string, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	hostname, err := extractHostname(p.Target)
	if err != nil {
		return nil, err
	}
	return p.snapshotSignatures(ctx, hostname)
}

// snapshotSignatures is the unexported worker that turns http_record rows
// into stable (method, URL) keys. 5000 is more than enough for any
// reasonable single-target audit; larger projects fall through silently
// (the diff just under-counts — coverage is a heuristic anyway).
func (p *CoverageProbe) snapshotSignatures(ctx context.Context, hostname string) ([]string, error) {
	records, err := p.Repo.GetRecordsByHostname(ctx, p.ProjectUUID, hostname, 5000)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(records))
	sigs := make([]string, 0, len(records))
	for _, r := range records {
		sig := r.Method + " " + r.URL
		if _, dup := seen[sig]; dup {
			continue
		}
		seen[sig] = struct{}{}
		sigs = append(sigs, sig)
	}
	sort.Strings(sigs)
	return sigs, nil
}

// diffSignatures returns elements present in `after` that aren't in `before`.
// Both inputs must be sorted (snapshotSignatures returns sorted slices).
// Result is sorted and may be empty (no gap).
func diffSignatures(before, after []string) []string {
	if len(after) == 0 {
		return nil
	}
	if len(before) == 0 {
		out := make([]string, len(after))
		copy(out, after)
		return out
	}
	beforeSet := make(map[string]struct{}, len(before))
	for _, s := range before {
		beforeSet[s] = struct{}{}
	}
	var gap []string
	for _, s := range after {
		if _, ok := beforeSet[s]; !ok {
			gap = append(gap, s)
		}
	}
	return gap
}

// extractHostname pulls the hostname out of a target URL or bare host. Used
// to scope the snapshot query — http_records are stored with hostname split
// out from URL, so the query is host-keyed.
func extractHostname(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("empty target")
	}
	// Bare host (no scheme): parse with a synthetic scheme so url.Parse
	// populates Host rather than putting everything in Path.
	probe := target
	if !strings.Contains(target, "://") {
		probe = "http://" + target
	}
	u, err := url.Parse(probe)
	if err != nil {
		return "", fmt.Errorf("parse target %q: %w", target, err)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("no host in target %q", target)
	}
	return host, nil
}
