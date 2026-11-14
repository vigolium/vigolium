package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"gopkg.in/yaml.v3"
)

// Baselines and ignore files: CI gating without a persistent database.
//
// After `scan -S`, `finding`, `scan diff` and `scan status` have nothing to
// read, and suppression lived only in database status. --baseline compares the
// run's findings with a previous run's export (.jsonl or .sqlite) by finding
// hash, so --fail-on counts only NEW findings; --ignore-file lists hashes an
// operator ruled out (with a reason and an optional expiry), honoured by the
// gate and by `scan diff`.

// defaultIgnoreFile is read from the working directory when --ignore-file is
// not given.
const defaultIgnoreFile = ".vigolium-ignore.yaml"

var (
	scanBaselinePath string
	scanIgnoreFile   string
)

// registerBaselineFlags declares --baseline and --ignore-file.
func registerBaselineFlags(flags *pflag.FlagSet) {
	flags.StringVar(&scanBaselinePath, "baseline", "", "Previous run's findings (.jsonl export or .sqlite store): --fail-on counts only findings not in it; -j adds baseline{new,unchanged,fixed,ignored}")
	flags.StringVar(&scanIgnoreFile, "ignore-file", "", "YAML list of finding hashes to ignore ({hash, reason, expires}); default "+defaultIgnoreFile+" when present")
}

// ignoreEntry is one line of an ignore file.
type ignoreEntry struct {
	Hash    string `yaml:"hash"`
	Reason  string `yaml:"reason"`
	Expires string `yaml:"expires,omitempty"` // YYYY-MM-DD or RFC 3339; empty = never
}

// ignoreFileDoc accepts both `ignore: [...]` and a bare list.
type ignoreFileDoc struct {
	Ignore []ignoreEntry `yaml:"ignore"`
}

// ignoreSet maps a finding hash (or a ≥12-char prefix) to its entry.
type ignoreSet map[string]ignoreEntry

// matches reports whether hash is ignored (exact or by listed prefix).
func (s ignoreSet) matches(hash string) bool {
	if len(s) == 0 || hash == "" {
		return false
	}
	if _, ok := s[hash]; ok {
		return true
	}
	for h := range s {
		if len(h) >= database.MinFindingHashPrefix && strings.HasPrefix(hash, h) {
			return true
		}
	}
	return false
}

// loadIgnoreFile reads path (the default file when path is "" and it exists).
// Expired entries are dropped with a warning; a malformed file is an error.
func loadIgnoreFile(path string, now time.Time) (ignoreSet, error) {
	explicit := path != ""
	if !explicit {
		path = defaultIgnoreFile
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !explicit && errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, usageErrorf("--ignore-file %s: %w", path, err)
	}
	var doc ignoreFileDoc
	if err := yaml.Unmarshal(data, &doc); err != nil || doc.Ignore == nil {
		var list []ignoreEntry
		if lerr := yaml.Unmarshal(data, &list); lerr != nil {
			if err == nil {
				err = lerr
			}
			return nil, usageErrorf("--ignore-file %s: %w", path, err)
		}
		doc.Ignore = list
	}
	out := ignoreSet{}
	for i, e := range doc.Ignore {
		e.Hash = strings.ToLower(strings.TrimSpace(e.Hash))
		if e.Hash == "" {
			return nil, usageErrorf("--ignore-file %s: entry %d has no hash", path, i+1)
		}
		if exp := strings.TrimSpace(e.Expires); exp != "" {
			t, perr := parseIgnoreExpiry(exp)
			if perr != nil {
				return nil, usageErrorf("--ignore-file %s: entry %d: bad expires %q (want YYYY-MM-DD or RFC 3339)", path, i+1, exp)
			}
			if now.After(t) {
				if !globalSilent {
					fmt.Fprintf(os.Stderr, "%s ignore entry %s expired on %s; it no longer suppresses the finding\n", terminal.WarnPrefix(), e.Hash, exp)
				}
				continue
			}
		}
		out[e.Hash] = e
	}
	return out, nil
}

func parseIgnoreExpiry(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.Add(24*time.Hour - time.Nanosecond), nil // the whole day
	}
	return time.Parse(time.RFC3339, s)
}

// baselineFinding is what a baseline knows about one finding.
type baselineFinding struct {
	Hash     string
	Severity string
	Finding  *database.Finding
}

// loadBaseline reads a previous run's findings by hash. A .jsonl export is
// imported into a scratch store; a .sqlite store is merged into one (which
// re-keys a pre-identity-v2 store, so its hashes match this run's).
func loadBaseline(ctx context.Context, path string) (map[string]baselineFinding, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, usageErrorf("--baseline %s: %w", path, err)
	}
	var db *database.DB
	var err error
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jsonl", ".json", ".ndjson":
		db, err = loadStatelessJSONL(path)
	case ".sqlite", ".db", ".sqlite3":
		db, err = newScratchDB("baseline")
		if err == nil {
			if err = db.EnsureSchemaReady(ctx); err == nil {
				_, err = database.MergeSQLiteFile(ctx, db, path)
			}
		}
	default:
		return nil, usageErrorf("--baseline %s: want a .jsonl export or a .sqlite store", path)
	}
	if err != nil {
		if db != nil {
			_ = db.Close()
		}
		//vigolium:not-usage the baseline store exists but could not be read or merged
		return nil, fmt.Errorf("--baseline %s: %w", path, err)
	}
	defer func() { _ = db.Close() }()
	findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{}).Execute(ctx)
	if err != nil {
		//vigolium:not-usage a query failure on the loaded baseline
		return nil, fmt.Errorf("--baseline %s: read findings: %w", path, err)
	}
	out := make(map[string]baselineFinding, len(findings))
	for _, f := range findings {
		out[f.FindingHash] = baselineFinding{Hash: f.FindingHash, Severity: f.Severity, Finding: f}
	}
	return out, nil
}

// baselineCounts is the -j `baseline` object.
type baselineCounts struct {
	New       int `json:"new"`
	Unchanged int `json:"unchanged"`
	Fixed     int `json:"fixed"`
	Ignored   int `json:"ignored"`
}

// baselineGate holds the per-run baseline/ignore state the gate and the scan
// document read. Reset by resetFailOnGate.
var baselineGate struct {
	loaded   bool
	baseline map[string]baselineFinding // nil without --baseline
	ignore   ignoreSet
	counts   *baselineCounts // set once the run's findings were classified
}

// prepareBaselineGate loads --baseline and the ignore file once per run.
func prepareBaselineGate(ctx context.Context) error {
	baselineGate.loaded = true
	ig, err := loadIgnoreFile(scanIgnoreFile, time.Now())
	if err != nil {
		return asUsageError(err)
	}
	baselineGate.ignore = ig
	if scanBaselinePath != "" {
		b, err := loadBaseline(ctx, scanBaselinePath)
		if err != nil {
			return err
		}
		baselineGate.baseline = b
	}
	return nil
}

// gateFinding is one current finding, as the gate classifies it.
type gateFinding struct {
	Hash     string
	Severity string
}

// classifyForGate splits the run's findings: ignored ones never count, and
// with a baseline only new ones do. It records the -j `baseline` counts and
// returns the findings the --fail-on threshold should see.
func classifyForGate(current []gateFinding) []gateFinding {
	keep := make([]gateFinding, 0, len(current))
	var c baselineCounts
	seen := make(map[string]bool, len(current))
	for _, f := range current {
		seen[f.Hash] = true
		switch {
		case baselineGate.ignore.matches(f.Hash):
			c.Ignored++
		case baselineGate.baseline != nil && hasBaseline(f.Hash):
			c.Unchanged++
		default:
			c.New++
			keep = append(keep, f)
		}
	}
	if baselineGate.baseline != nil {
		for h := range baselineGate.baseline {
			if !seen[h] {
				c.Fixed++
			}
		}
	}
	if baselineGate.baseline != nil || len(baselineGate.ignore) > 0 {
		baselineGate.counts = &c
	}
	return keep
}

func hasBaseline(hash string) bool {
	_, ok := baselineGate.baseline[hash]
	return ok
}

// baselineDocument is the scan document's `baseline` value (nil when neither
// --baseline nor an ignore file applied).
func baselineDocument() *baselineCounts { return baselineGate.counts }

// isBaselineFileRef reports whether a scan diff argument names an export file
// rather than a scan.
func isBaselineFileRef(ref string) bool {
	switch strings.ToLower(filepath.Ext(ref)) {
	case ".jsonl", ".json", ".ndjson", ".sqlite", ".db", ".sqlite3":
	default:
		return false
	}
	info, err := os.Stat(ref)
	return err == nil && !info.IsDir()
}

// diffClassIgnored counts new findings an ignore file suppressed.
const diffClassIgnored = "ignored"

// diffAgainstBaselineFile compares a stored scan (head) with a previous run's
// export by finding hash: new = head \ file, unchanged = both, and the file's
// findings the head did not observe are fixed when the head completed (else
// not_reobserved: absence from a partial run is not a fix).
func diffAgainstBaselineFile(ctx context.Context, repo *database.Repository, projectUUID, path string, head *database.Scan) (*database.ScanDiff, error) {
	base, err := loadBaseline(ctx, path)
	if err != nil {
		return nil, err
	}
	filters := database.QueryFilters{ProjectUUID: projectUUID, ObservedInScan: head.UUID}
	if !scanDiffIncludeDismissed {
		filters.ExcludeStatuses = database.DismissedFindingStatuses
	}
	current, err := database.NewFindingsQueryBuilder(repo.DB(), filters).Execute(ctx)
	if err != nil {
		return nil, fmt.Errorf("scan diff: %w", err)
	}
	comparable := head.Completeness == database.CompletenessComplete
	diff := &database.ScanDiff{
		Base:       &database.Scan{UUID: "file:" + path, Status: "completed", Target: path},
		Head:       head,
		Comparable: comparable,
		History:    "complete",
		Counts:     map[string]int{},
	}
	if !comparable {
		diff.ComparabilityReasons = []string{database.ComparabilityHeadPartial}
	}
	for _, c := range database.DiffChanges {
		diff.Counts[c] = 0
	}
	seen := make(map[string]bool, len(current))
	for _, f := range current {
		seen[f.FindingHash] = true
		change := database.DiffNew
		if _, ok := base[f.FindingHash]; ok {
			change = database.DiffUnchanged
		}
		diff.Entries = append(diff.Entries, database.ScanDiffEntry{Finding: f, Change: change})
		diff.Counts[change]++
	}
	for h, b := range base {
		if seen[h] || b.Finding == nil {
			continue
		}
		change := database.DiffNotReobserved
		if comparable {
			change = database.DiffFixed
		}
		diff.Entries = append(diff.Entries, database.ScanDiffEntry{Finding: b.Finding, Change: change})
		diff.Counts[change]++
	}
	return diff, nil
}

// applyIgnoreToDiff drops new entries the ignore file lists and counts them
// under counts["ignored"].
func applyIgnoreToDiff(diff *database.ScanDiff, ignore ignoreSet) {
	if diff == nil || len(ignore) == 0 {
		return
	}
	kept := diff.Entries[:0]
	for _, e := range diff.Entries {
		if e.Change == database.DiffNew && e.Finding != nil && ignore.matches(e.Finding.FindingHash) {
			diff.Counts[database.DiffNew]--
			diff.Counts[diffClassIgnored]++
			continue
		}
		kept = append(kept, e)
	}
	diff.Entries = kept
}
