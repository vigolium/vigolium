package runner

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/work"
)

// emptyInput is an input source with nothing in it.
type emptyInput struct{}

func (emptyInput) Next(context.Context) (*work.WorkItem, error) { return nil, io.EOF }
func (emptyInput) Close() error                                 { return nil }

// runEmptyStoreAssessment runs `--only dynamic-assessment` with no targets over
// an empty store, with OAST off and a light tier cap, and returns the scan row
// and the event stream.
func runEmptyStoreAssessment(t *testing.T) (*database.Scan, *bytes.Buffer, ModuleSelection) {
	t.Helper()
	opts := types.DefaultOptions()
	opts.Silent = true
	opts.Retries = 0
	opts.Timeout = 5 * time.Second
	opts.OnlyPhase = "dynamic-assessment"
	opts.MaxModuleTier = "light"
	opts.ScanUUID = "honest-phase-state-scan"
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	settings := config.DefaultSettings()
	settings.OAST.Enabled = false
	if err := ApplyNativePhaseSelection(opts, nil); err != nil {
		t.Fatal(err)
	}

	dbCfg := settings.Database
	dbCfg.Driver = "sqlite"
	dbCfg.SQLite.Path = filepath.Join(t.TempDir(), "honest.sqlite")
	db, err := database.NewDB(&dbCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.EnsureSchemaReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	repo := database.NewRepository(db)

	var buf bytes.Buffer
	prev := scanevents.Default()
	scanevents.Install(scanevents.New(&buf, opts.ScanUUID))
	t.Cleanup(func() { scanevents.Install(prev) })

	// The database rescan's shape (`scan --all-records`): no target input,
	// the assessment reads the store.
	r, err := NewWithInputSource(opts, emptyInput{})
	if err != nil {
		t.Fatalf("runner.New: %v", err)
	}
	r.SetSettings(settings)
	r.SetRepository(repo)
	if err := r.RunNativeScan(); err != nil {
		t.Fatalf("RunNativeScan: %v", err)
	}
	r.Close()

	row, err := repo.GetScanByUUID(context.Background(), opts.ScanUUID)
	if err != nil {
		t.Fatal(err)
	}
	return row, &buf, FilterModulesForRun(opts, settings)
}

// An assessment the operator asked for by name, over a store with nothing in
// it, admits zero inputs: the row says skipped/no_inputs (not completed), the
// stream's phase.finished says skipped, and because the phase was named the
// scan is partial. The capabilities the configuration switched off ride on
// the phase as notes, with the modules each removed.
func TestEmptyStoreAssessmentIsSkippedNoInputs(t *testing.T) {
	row, buf, sel := runEmptyStoreAssessment(t)

	var da *database.PhaseOutcome
	for i := range row.PhaseOutcomes {
		if row.PhaseOutcomes[i].Phase == string(PhaseDynamicAssessment) {
			da = &row.PhaseOutcomes[i]
		}
	}
	if da == nil {
		t.Fatalf("no dynamic-assessment outcome in %+v", row.PhaseOutcomes)
	}
	if da.State != database.PhaseSkipped || !slices.Equal(da.Reasons, []string{database.ReasonNoInputs}) {
		t.Fatalf("dynamic-assessment = state %q reasons %v, want skipped [no_inputs]", da.State, da.Reasons)
	}
	if !da.Explicit {
		t.Error("a phase named with --only is recorded explicit")
	}
	if da.BenignSkip() {
		t.Error("an explicitly selected phase that assessed nothing is not a benign skip")
	}
	if row.Completeness != database.CompletenessPartial {
		t.Errorf("completeness = %q, want partial", row.Completeness)
	}

	for _, code := range []string{database.LimitOASTDisabled, database.LimitModuleTierCapped} {
		if !slices.Contains(da.Notes, code) {
			t.Errorf("notes %v lack %s", da.Notes, code)
		}
	}
	if len(sel.TierCapped) == 0 {
		t.Fatal("the light cap removed nothing; the fixture no longer exercises module_tier_capped")
	}
	want := slices.Clone(sel.TierCapped)
	slices.Sort(want)
	if got := da.NoteModules[database.LimitModuleTierCapped]; !slices.Equal(got, want) {
		t.Errorf("module_tier_capped modules = %v, want the selection's TierCapped %v", got, want)
	}
	if got := slices.Contains(da.Notes, database.LimitRiskyPayloadsDisabled); got != (len(sel.RiskWithheld) > 0) {
		t.Errorf("risky_payloads_disabled noted = %v, selection withheld %v", got, sel.RiskWithheld)
	}
	if _, ok := da.NoteModules[database.LimitOASTDisabled]; ok {
		t.Error("oast_disabled names no modules: no module declares that it plants an OAST payload")
	}

	finished := eventsOfType(t, buf, scanevents.TypePhaseFinished)
	var got map[string]any
	for _, ev := range finished {
		if ev["phase"] == string(PhaseDynamicAssessment) {
			got = ev
		}
	}
	if got == nil {
		t.Fatalf("no phase.finished for dynamic-assessment in:\n%s", buf.String())
	}
	if got["status"] != scanevents.StatusSkipped {
		t.Errorf("phase.finished status = %v, want skipped", got["status"])
	}
	reasons, _ := got["reasons"].([]any)
	if len(reasons) != 1 || reasons[0] != database.ReasonNoInputs {
		t.Errorf("phase.finished reasons = %v, want [no_inputs]", got["reasons"])
	}
}

// The selection's gates land on the running phase as notes naming the modules
// each removed; a gate that removed nothing notes nothing.
func TestNoteModuleGates(t *testing.T) {
	r := &Runner{}
	tr := r.beginPhase(context.Background(), "dynamic-assessment", nil)
	r.currentPhase.Store(tr)
	r.noteModuleGates(ModuleSelection{TierCapped: []string{"z-heavy", "a-heavy"}, RiskWithheld: []string{"php2shell"}})
	out := tr.outcome()
	if !slices.Equal(out.Notes, []string{database.LimitModuleTierCapped, database.LimitRiskyPayloadsDisabled}) {
		t.Fatalf("notes = %v", out.Notes)
	}
	if got := out.NoteModules[database.LimitModuleTierCapped]; !slices.Equal(got, []string{"a-heavy", "z-heavy"}) {
		t.Errorf("module_tier_capped = %v", got)
	}
	if got := out.NoteModules[database.LimitRiskyPayloadsDisabled]; !slices.Equal(got, []string{"php2shell"}) {
		t.Errorf("risky_payloads_disabled = %v", got)
	}
	if out.State != database.PhaseCompleted {
		t.Errorf("a note does not change the phase state: %q", out.State)
	}

	r2 := &Runner{}
	tr2 := r2.beginPhase(context.Background(), "dynamic-assessment", nil)
	r2.currentPhase.Store(tr2)
	r2.noteModuleGates(ModuleSelection{})
	if out := tr2.outcome(); len(out.Notes) != 0 || out.NoteModules != nil {
		t.Errorf("no gate fired, yet notes = %v %v", out.Notes, out.NoteModules)
	}
}

// A phase the plan brought along (not named) that admitted nothing is the
// plan working: benign, so the scan stays complete; named, it is a gap.
func TestNoInputsBenignOnlyWhenNotExplicit(t *testing.T) {
	implicit := database.PhaseOutcome{Phase: "dynamic-assessment", State: database.PhaseSkipped, Reasons: []string{database.ReasonNoInputs}}
	if c := completionOf([]database.PhaseOutcome{implicit}, ""); c.Completeness != database.CompletenessComplete {
		t.Errorf("implicit no_inputs: completeness = %q, want complete", c.Completeness)
	}
	explicit := implicit
	explicit.Explicit = true
	if c := completionOf([]database.PhaseOutcome{explicit}, ""); c.Completeness != database.CompletenessPartial {
		t.Errorf("explicit no_inputs: completeness = %q, want partial", c.Completeness)
	}
}
