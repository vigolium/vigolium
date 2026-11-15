package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

// resetCleanFlags restores the package-level clean flags between cases. The
// command tree is process-global, so a case that leaves a flag set otherwise
// changes the meaning of the next one.
func resetCleanFlags(t *testing.T) {
	t.Helper()
	cleanAll, cleanOrphans, cleanFindings = false, false, false
	cleanHost, cleanScanUUID, cleanBefore, cleanSeverity, cleanTable = "", "", "", "", ""
	cleanStatus = nil
	dbSearch = ""
	globalForce = false
	t.Cleanup(func() {
		cleanAll, cleanOrphans, cleanFindings = false, false, false
		cleanHost, cleanScanUUID, cleanBefore, cleanSeverity, cleanTable = "", "", "", "", ""
		cleanStatus = nil
		dbSearch = ""
		globalForce = false
	})
}

const testProject = "proj-under-test"

// The bug this file exists for: --findings-only reads as a narrowing modifier
// but is a mode switch, and the handler behind it applied severity and nothing
// else. A --host on the command line was accepted and dropped, so the delete
// was store-wide while the invocation looked scoped.
func TestFindingsOnlyCarriesEverySelector(t *testing.T) {
	resetCleanFlags(t)
	cleanFindings = true
	cleanHost = "api.example.invalid"
	cleanScanUUID = "scan-1"
	cleanSeverity = "high,critical"
	cleanStatus = []int{200, 500}
	dbSearch = "needle"

	sel, err := resolveCleanSelection(testProject)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if sel.Mode != cleanModeFindings {
		t.Errorf("mode = %q, want %q", sel.Mode, cleanModeFindings)
	}
	if sel.StoreWide {
		t.Error("findings-only must be project-scoped, not store-wide")
	}
	f := sel.Filters
	if f.ProjectUUID != testProject {
		t.Errorf("project not applied: %q", f.ProjectUUID)
	}
	if f.HostPattern != "api.example.invalid" {
		t.Errorf("--host dropped: %q", f.HostPattern)
	}
	if f.ScanUUID != "scan-1" {
		t.Errorf("--scan-uuid dropped: %q", f.ScanUUID)
	}
	if len(f.Severity) != 2 || f.Severity[0] != "high" || f.Severity[1] != "critical" {
		t.Errorf("--severity dropped or mangled: %v", f.Severity)
	}
	if len(f.StatusCodes) != 2 {
		t.Errorf("--status dropped: %v", f.StatusCodes)
	}
	if f.SearchTerm != "needle" {
		t.Errorf("--search dropped: %q", f.SearchTerm)
	}
}

func TestDefaultRecordsModeIsProjectScoped(t *testing.T) {
	resetCleanFlags(t)
	cleanHost = "api.example.invalid"

	sel, err := resolveCleanSelection(testProject)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if sel.Mode != cleanModeRecords {
		t.Errorf("mode = %q, want %q", sel.Mode, cleanModeRecords)
	}
	if sel.Filters.ProjectUUID != testProject {
		t.Errorf("project not applied: %q", sel.Filters.ProjectUUID)
	}
}

func TestOrphansIsProjectScopedAndRejectsSelectors(t *testing.T) {
	resetCleanFlags(t)
	cleanOrphans = true

	sel, err := resolveCleanSelection(testProject)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if sel.Filters.ProjectUUID != testProject {
		t.Error("orphan sweep must stay inside the active project")
	}
	if sel.StoreWide {
		t.Error("orphan sweep is scoped, not store-wide")
	}

	// A filter that reaches through a record can never match an orphan, so
	// accepting it would restate the original bug in a quieter form.
	resetCleanFlags(t)
	cleanOrphans = true
	cleanHost = "api.example.invalid"
	if _, err := resolveCleanSelection(testProject); err == nil {
		t.Fatal("--orphans --host must be rejected, not silently ignored")
	} else if !strings.Contains(err.Error(), "--host") {
		t.Errorf("rejection must name the offending flag, got: %v", err)
	}
}

// --table and --all truncate; they cannot narrow. Accepting a selector beside
// one made the command line read narrower than the delete actually was.
func TestStoreWideModesRejectScopedSelectors(t *testing.T) {
	cases := []struct {
		name  string
		setup func()
		want  string
	}{
		{"table with host", func() { cleanTable = "findings"; cleanHost = "x.invalid" }, "--host"},
		{"table with severity", func() { cleanTable = "findings"; cleanSeverity = "high" }, "--severity"},
		{"all with scan-uuid", func() { cleanAll = true; globalForce = true; cleanScanUUID = "s1" }, "--scan-uuid"},
		{"all with search", func() { cleanAll = true; globalForce = true; dbSearch = "q" }, "--search"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetCleanFlags(t)
			tc.setup()
			_, err := resolveCleanSelection(testProject)
			if err == nil {
				t.Fatalf("%s must be rejected, not silently ignored", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("rejection must name %s, got: %v", tc.want, err)
			}
		})
	}
}

func TestStoreWideModesAreLabeledStoreWide(t *testing.T) {
	resetCleanFlags(t)
	cleanTable = "findings"

	sel, err := resolveCleanSelection(testProject)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !sel.StoreWide {
		t.Error("--table addresses every project and must say so")
	}
	if sel.Filters.ProjectUUID != "" {
		t.Error("a store-wide selection must not carry a project filter it does not apply")
	}
	if !strings.Contains(sel.describeScope(), "ENTIRE") {
		t.Errorf("scope line must be unmistakable, got %q", sel.describeScope())
	}
}

func TestConflictingModesAreRejected(t *testing.T) {
	pairs := []struct{ a, b func() }{
		{func() { cleanFindings = true }, func() { cleanOrphans = true }},
		{func() { cleanTable = "findings" }, func() { cleanAll = true; globalForce = true }},
		{func() { cleanFindings = true }, func() { cleanTable = "findings" }},
	}
	for i, p := range pairs {
		resetCleanFlags(t)
		p.a()
		p.b()
		if _, err := resolveCleanSelection(testProject); err == nil {
			t.Errorf("case %d: conflicting modes must be rejected", i)
		} else if classifyExitCode(err) != ExitUsageError {
			t.Errorf("case %d: a bad combination is a usage error (exit 2), got %d", i, classifyExitCode(err))
		}
	}
}

func TestAllRequiresForce(t *testing.T) {
	resetCleanFlags(t)
	cleanAll = true

	_, err := resolveCleanSelection(testProject)
	if err == nil {
		t.Fatal("--all without --force must be rejected")
	}
	if classifyExitCode(err) != ExitUsageError {
		t.Errorf("exit code = %d, want %d", classifyExitCode(err), ExitUsageError)
	}

	resetCleanFlags(t)
	cleanAll = true
	globalForce = true
	if _, err := resolveCleanSelection(testProject); err != nil {
		t.Errorf("--all --force must be accepted: %v", err)
	}
}

func TestUnknownTableIsRejectedBeforeAnyDelete(t *testing.T) {
	resetCleanFlags(t)
	cleanTable = "not_a_table"

	_, err := resolveCleanSelection(testProject)
	if err == nil {
		t.Fatal("an unknown table must be rejected")
	}
	// The message lists the vocabulary so a typo is distinguishable from a
	// deliberately omitted value.
	if !strings.Contains(err.Error(), "Allowed tables:") {
		t.Errorf("rejection must list accepted tables, got: %v", err)
	}
}

func TestConfirmationRequiredIsAUsageError(t *testing.T) {
	// `go test` runs with stdin detached, which is exactly the non-interactive
	// case the gate exists for: no terminal, no --force, so it must refuse
	// rather than block or consume the stream.
	err := clicommon.Confirm("deleting 3 findings", false)
	if err == nil {
		t.Fatal("a mutation needing approval must be refused without a terminal")
	}
	if !errors.Is(err, errConfirmationRequired) {
		t.Fatal("the refusal must unwrap to errConfirmationRequired")
	}
	if got := classifyExitCode(err); got != ExitUsageError {
		t.Errorf("exit code = %d, want %d (nothing ran; --force is the missing argument)", got, ExitUsageError)
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("the refusal must name the flag that fixes it, got: %v", err)
	}
}

// describeAction feeds the confirmation prompt, so a mangled phrase is what the
// operator is asked to approve. The plural used to be a suffix appended to the
// whole noun phrase, which produced "deleting 5 row from every data tables" for
// --all and forced an awkward re-check of the mode for --table.
func TestDescribeActionPluralizesTheNounNotThePhrase(t *testing.T) {
	cases := []struct {
		name  string
		sel   *cleanSelection
		count int64
		want  string
	}{
		{"records plural", &cleanSelection{Mode: cleanModeRecords}, 5, "deleting 5 records in"},
		{"records singular", &cleanSelection{Mode: cleanModeRecords}, 1, "deleting 1 record in"},
		{"findings plural", &cleanSelection{Mode: cleanModeFindings}, 41, "deleting 41 findings in"},
		{"findings singular", &cleanSelection{Mode: cleanModeFindings}, 1, "deleting 1 finding in"},
		{"orphans plural", &cleanSelection{Mode: cleanModeOrphans}, 3, "deleting 3 findings in"},
		{"table plural", &cleanSelection{Mode: cleanModeTable, Table: "findings", StoreWide: true}, 7,
			`deleting 7 rows from "findings" in`},
		{"table singular", &cleanSelection{Mode: cleanModeTable, Table: "findings", StoreWide: true}, 1,
			`deleting 1 row from "findings" in`},
		// The regression: the suffix landed after "table", not after "row".
		{"all plural", &cleanSelection{Mode: cleanModeAll, StoreWide: true}, 275,
			"deleting 275 rows from every data table in"},
		{"all singular", &cleanSelection{Mode: cleanModeAll, StoreWide: true}, 1,
			"deleting 1 row from every data table in"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.sel.describeAction(tc.count)
			if !strings.HasPrefix(got, tc.want) {
				t.Errorf("describeAction(%d) = %q, want it to start with %q", tc.count, got, tc.want)
			}
			if strings.Contains(got, "tables") || strings.Contains(got, "recordss") {
				t.Errorf("mangled plural: %q", got)
			}
		})
	}
}

// --severity on its own deletes findings, not the records that carry them.
func TestSeverityAloneSelectsFindings(t *testing.T) {
	resetCleanFlags(t)
	cleanSeverity = "high"
	sel, err := resolveCleanSelection(testProject)
	if err != nil {
		t.Fatal(err)
	}
	if sel.Mode != cleanModeFindings {
		t.Fatalf("mode = %q, want findings", sel.Mode)
	}
}

// --all --dry-run deletes nothing, so it needs no --force.
func TestAllDryRunNeedsNoForce(t *testing.T) {
	resetCleanFlags(t)
	cleanAll, cleanDryRun = true, true
	t.Cleanup(func() { cleanDryRun = false })
	if _, err := resolveCleanSelection(testProject); err != nil {
		t.Fatalf("--all --dry-run: %v", err)
	}
	cleanDryRun = false
	if _, err := resolveCleanSelection(testProject); err == nil {
		t.Fatal("--all without --force or --dry-run accepted")
	}
}
