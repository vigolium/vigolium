package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/jsext/exttest"
)

// `vigolium ext test <dir|file>`: run every extension's fixture cases and
// report pass/fail. File name extensions_testcmd.go, not extensions_test.go,
// which Go would read as a test file.

var extensionsTestCmd = &cobra.Command{
	Use:   "test <dir|file>",
	Short: "Run extensions against their fixture cases (offline; active ones against a local mock)",
	Long: `Run each extension's fixture cases and check what it reports.

Layout, next to each extension <name>.js | <name>.ts | <name>.vgm.yaml:

  <name>.fixtures/<case>.http             a raw request, a blank line, a raw response
  <name>.fixtures/<case>.expect.json      {"findings": N | [{"name~": "...", "severity": "...", "confidence": "..."}], "errors": 0}
  <name>.fixtures/<case>.responses/*.http canned responses for an active extension's requests

Instead of an .expect.json, a case may start with "// expect: {...}". Other
directives on leading comment lines: "// handler: scanPerInsertionPoint",
"// insertion: URL_PARAM:id", "// url: https://host" (the request's origin;
default http://<Host>). In a response file, "// match: <text>" serves it only
to a request whose target or body contains <text>; its request line is
METHOD /path (a path with ?query matches the full target).

A case with no .responses directory runs offline: every request the extension
makes is refused and counted (network_calls_blocked; vigolium.http.* throws).
A case with one runs against an in-process mock on 127.0.0.1 serving those
files, with the case's Host pointed at it. Nothing leaves the machine. No
database is opened: vigolium.db is unavailable.

Output is TAP-like; -j is one document whose items are the cases. Exit 1 when
any case fails. Extensions without fixtures and hooks are reported as skipped.`,
	Example: `  vigolium ext test ~/.vigolium/extensions
  vigolium ext test ./my-checks/reflected_param.js
  vigolium ext test public/presets/extensions -j`,
	Args: cobra.ExactArgs(1),
	RunE: runExtensionsTest,
}

// extTestExtras are the document's own top-level keys.
type extTestExtras struct {
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
}

func init() {
	extensionsCmd.AddCommand(extensionsTestCmd)
	registerCommandSchema(contract.Command{Name: "extensions test", Item: exttest.CaseResult{}, Extras: extTestExtras{},
		Description: "One item per fixture case (or per extension that ran none: skipped with a reason, or failed to load); passed/failed/skipped count them. ok is false when any case failed (exit 1)."})
}

func runExtensionsTest(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	path := args[0]
	if _, err := os.Stat(path); err != nil {
		return usageErrorf("cannot access %s: %v", path, err)
	}
	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return err
	}
	base := settings.DynamicAssessment.Extensions
	report, err := exttest.RunFixtures(path, exttest.FixtureOptions{Base: &base})
	if err != nil {
		return usageErrorf("%v", err)
	}

	var testErr error
	if report.Failed > 0 {
		testErr = codedErrorf(apicontract.CodeFailed, "ext test: %d of %d case(s) failed",
			report.Failed, report.Passed+report.Failed)
	}

	if globalJSON {
		opts := []envOpt{
			withExtra("passed", report.Passed),
			withExtra("failed", report.Failed),
			withExtra("skipped", report.Skipped),
		}
		n := len(report.Cases)
		if err := emitRead(cmd, "cases", report.Cases, int64(n), 0, n, opts...); err != nil {
			return err
		}
		return testErr
	}

	printExtTestTAP(report)
	return testErr
}

// printExtTestTAP prints the report as TAP: a plan line, one ok / not ok per
// case with a YAML-ish block for a failure, and a summary comment.
func printExtTestTAP(r *exttest.Report) {
	fmt.Println("TAP version 13")
	fmt.Printf("1..%d\n", len(r.Cases))
	for i, c := range r.Cases {
		label := c.Extension
		if c.Case != "" {
			label += " " + c.Case
		}
		switch c.Status {
		case exttest.StatusPass:
			fmt.Printf("ok %d - %s\n", i+1, label)
		case exttest.StatusSkip:
			fmt.Printf("ok %d - %s # SKIP %s\n", i+1, label, c.SkipReason)
		default:
			fmt.Printf("not ok %d - %s\n", i+1, label)
			fmt.Println("  ---")
			for _, f := range c.Failures {
				fmt.Printf("  - %s\n", strings.ReplaceAll(f, "\n", " "))
			}
			if len(c.UnmatchedRequests) > 0 {
				fmt.Printf("  unmatched mock requests: %s\n", strings.Join(c.UnmatchedRequests, ", "))
			}
			fmt.Println("  ...")
		}
	}
	fmt.Printf("# passed %d, failed %d, skipped %d\n", r.Passed, r.Failed, r.Skipped)
}
