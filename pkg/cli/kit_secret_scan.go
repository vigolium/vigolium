package cli

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/secretscan"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/utils/textutil"
)

var (
	kitSecretMinConfidence string
	kitSecretRules         []string
	kitSecretExcludeRules  []string
	kitSecretRedact        bool
	kitSecretFailOnMatch   bool
	kitSecretMaxFileBytes  int64
)

// kitSecretMaxFileDefault caps a single file's size so a stray multi-GB blob in
// a scanned directory can't be slurped into memory. Overridable via --max-file-size.
const kitSecretMaxFileDefault = 16 << 20 // 16 MiB

var kitSecretScanCmd = &cobra.Command{
	Use:   "secret-scan [files|dirs|-]",
	Short: "Scan files or stdin for leaked credentials using the built-in secret catalog",
	Long: `Scan bytes for leaked secrets with vigolium's embedded detection catalog
(~12k kingfisher + vigolium rules, pure Go, no network). Positional arguments are
files or directories (walked recursively); '-' or no argument reads stdin.

  vigolium kit secret-scan config.env .github/            # files + dirs
  cat bundle.js | vigolium kit secret-scan -              # stdin
  vigolium kit secret-scan -j --min-confidence high src/  # high-confidence JSON

It reports where a secret is, never a verdict on exploitability. Full secret
values are shown by default (use --redact to mask). --fail-on-match exits 3 when
any secret is found, for CI/agent gating.`,
	RunE: runKitSecretScan,
}

func init() {
	f := kitSecretScanCmd.Flags()
	f.StringVar(&kitSecretMinConfidence, "min-confidence", "low", "Minimum confidence to report: low, medium, high")
	f.StringSliceVar(&kitSecretRules, "rule", nil, "Only report these rule IDs (comma-separated / repeatable)")
	f.StringSliceVar(&kitSecretExcludeRules, "exclude-rule", nil, "Skip these rule IDs (comma-separated / repeatable)")
	f.BoolVar(&kitSecretRedact, "redact", false, "Mask the secret value in output (show only a prefix/suffix)")
	f.BoolVar(&kitSecretFailOnMatch, "fail-on-match", false, "Exit 3 when at least one secret is found (for CI/agent gating)")
	f.Int64Var(&kitSecretMaxFileBytes, "max-file-size", kitSecretMaxFileDefault, "Skip files larger than this many bytes")
	kitCmd.AddCommand(kitSecretScanCmd)
}

// kitSecretMatch is one detected secret enriched with its source location.
type kitSecretMatch struct {
	RuleID     string  `json:"rule_id"`
	RuleName   string  `json:"rule_name"`
	Confidence string  `json:"confidence"`
	Secret     string  `json:"secret"`
	Entropy    float64 `json:"entropy"`
	File       string  `json:"file"`
	Line       int     `json:"line"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
}

type kitSecretReport struct {
	FilesScanned int              `json:"files_scanned"`
	Count        int              `json:"count"`
	Matches      []kitSecretMatch `json:"matches"`
}

func runKitSecretScan(cmd *cobra.Command, args []string) error {
	minRank, ok := confidenceRankFor(kitSecretMinConfidence)
	if !ok {
		return usageErrorf("--min-confidence: unknown value %q (want low, medium, or high)", kitSecretMinConfidence)
	}
	ruleAllow := toSet(kitSecretRules)
	ruleDeny := toSet(kitSecretExcludeRules)

	detector, err := secretscan.Default()
	if err != nil {
		return fmt.Errorf("loading secret catalog: %w", err)
	}
	if err := checkSecretRuleIDs(detector.RuleIDs(), kitSecretRules, kitSecretExcludeRules); err != nil {
		return err
	}

	// Expand the positional args into concrete file paths (dirs walked). No
	// args, or a lone "-", means stdin.
	inputs := args
	if len(inputs) == 0 {
		inputs = []string{"-"}
	}

	report := kitSecretReport{Matches: []kitSecretMatch{}}
	scanOne := func(label string, data []byte) {
		report.FilesScanned++
		for _, m := range detector.Detect(data) {
			if r, _ := confidenceRankFor(m.Confidence); r < minRank {
				continue
			}
			if len(ruleAllow) > 0 && !ruleAllow[m.RuleID] {
				continue
			}
			if ruleDeny[m.RuleID] {
				continue
			}
			secret := m.Secret
			if kitSecretRedact {
				secret = redactSecret(secret)
			}
			report.Matches = append(report.Matches, kitSecretMatch{
				RuleID:     m.RuleID,
				RuleName:   m.RuleName,
				Confidence: m.Confidence,
				Secret:     secret,
				Entropy:    m.Entropy,
				File:       label,
				Line:       lineOfOffset(data, m.Start),
				Start:      m.Start,
				End:        m.End,
			})
		}
	}

	for _, in := range inputs {
		if in == "-" || in == "" {
			data, _, rerr := kitReadInput("-")
			if rerr != nil {
				return rerr
			}
			scanOne("stdin", data)
			continue
		}
		info, statErr := os.Stat(in)
		if statErr != nil {
			return statErr
		}
		if info.IsDir() {
			if werr := scanSecretDir(in, scanOne); werr != nil {
				return werr
			}
			continue
		}
		if info.Size() > kitSecretMaxFileBytes {
			fmt.Fprintf(os.Stderr, "%s skipping %s (%d bytes > --max-file-size)\n", terminal.WarningSymbol(), in, info.Size())
			continue
		}
		data, rerr := os.ReadFile(in)
		if rerr != nil {
			return rerr
		}
		scanOne(in, data)
	}

	report.Count = len(report.Matches)
	// Stable ordering: by file, then offset.
	sort.SliceStable(report.Matches, func(i, j int) bool {
		if report.Matches[i].File != report.Matches[j].File {
			return report.Matches[i].File < report.Matches[j].File
		}
		return report.Matches[i].Start < report.Matches[j].Start
	})

	if globalJSON {
		if err := emitStructRead(cmd, report, "matches"); err != nil {
			return err
		}
	} else {
		printKitSecretHuman(report)
	}

	if kitSecretFailOnMatch && report.Count > 0 {
		// Returned, not os.Exit: the report above is already written, and the
		// process boundary owns the exit so defers run and --soft-fail applies.
		return asMatchErrorf("--fail-on-match: %d secret(s) matched", report.Count)
	}
	return nil
}

// scanSecretDir walks dir and calls scan for every regular file under the
// --max-file-size cap. Symlinks and unreadable entries are skipped, not fatal.
func scanSecretDir(dir string, scan func(label string, data []byte)) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s skipping %s: %v\n", terminal.WarningSymbol(), path, err)
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		if info.Size() > kitSecretMaxFileBytes {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "%s skipping %s: %v\n", terminal.WarningSymbol(), path, rerr)
			return nil
		}
		scan(path, data)
		return nil
	})
}

func printKitSecretHuman(report kitSecretReport) {
	if report.Count == 0 {
		fmt.Fprintf(os.Stderr, "%s no secrets found in %d file(s)\n", terminal.InfoSymbol(), report.FilesScanned)
		return
	}
	for _, m := range report.Matches {
		fmt.Printf("%s:%d\t%s\t%s\t%s\n",
			m.File, m.Line,
			terminal.Bold("["+m.Confidence+"]"),
			m.RuleName,
			m.Secret)
	}
	fmt.Fprintf(os.Stderr, "\n%s %d secret(s) across %d file(s)\n",
		terminal.InfoSymbol(), report.Count, report.FilesScanned)
}

// confidenceRankFor maps a catalog confidence string to an orderable rank.
// Unknown strings rank at 0 (treated as "low") so they are never silently
// dropped by a --min-confidence gate.
func confidenceRankFor(c string) (rank int, known bool) {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "low":
		return 0, true
	case "medium", "med":
		return 1, true
	case "high":
		return 2, true
	default:
		return 0, false
	}
}

// redactSecret masks a secret for display, keeping a short prefix/suffix so it
// stays identifiable without exposing the full value.
func redactSecret(s string) string {
	const keep = 3
	if len(s) <= 2*keep {
		return strings.Repeat("*", len(s))
	}
	return s[:keep] + strings.Repeat("*", len(s)-2*keep) + s[len(s)-keep:]
}

// lineOfOffset returns the 1-based line number of byte offset off within data.
func lineOfOffset(data []byte, off int) int {
	if off > len(data) {
		off = len(data)
	}
	if off < 0 {
		off = 0
	}
	return 1 + bytes.Count(data[:off], []byte{'\n'})
}

// toSet builds a lookup set from a slice of strings, ignoring empties.
func toSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]bool, len(items))
	for _, it := range items {
		if it = strings.TrimSpace(it); it != "" {
			m[it] = true
		}
	}
	return m
}

// checkSecretRuleIDs rejects a --rule/--exclude-rule ID the catalog does not
// carry: an unknown --rule used to report nothing, which reads as "no secret".
func checkSecretRuleIDs(known []string, lists ...[]string) error {
	set := toSet(known)
	for _, list := range lists {
		for _, id := range list {
			if _, ok := set[id]; ok || strings.TrimSpace(id) == "" {
				continue
			}
			e := clicommon.CLIError{
				Err:  fmt.Errorf("unknown secret rule %q", id),
				Hint: "Rule IDs are the rule_id values a match reports (kit secret-scan -j), e.g. kingfisher.aws.1",
			}
			// A near miss is the common case: a typo in a long, namespaced ID.
			best, bestDist := "", -1
			for _, k := range known {
				if d := textutil.Levenshtein(id, k); bestDist == -1 || d < bestDist {
					best, bestDist = k, d
				}
			}
			if bestDist >= 0 && bestDist <= max(2, len(id)/4) {
				e.DidYouMean = best
			}
			return e
		}
	}
	return nil
}
