package runner

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cftbrowser"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/knownissuescan"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/types"
)

// fakeChrome stages a machine with no browser: the download check says yes and
// the download itself is fn. Nothing reaches the network.
func fakeChrome(t *testing.T, fn func(context.Context, cftbrowser.ProgressFunc) (string, error)) {
	t.Helper()
	origNeeds, origEnsure := browserNeedsDownload, ensureCfTBrowser
	browserNeedsDownload = func(string, string) bool { return true }
	ensureCfTBrowser = fn
	t.Cleanup(func() { browserNeedsDownload, ensureCfTBrowser = origNeeds, origEnsure })
}

func setupEvents(t *testing.T, evs []scanevents.Event) []scanevents.Event {
	t.Helper()
	var out []scanevents.Event
	for _, ev := range evs {
		if ev.Type == scanevents.TypeScanSetup {
			out = append(out, ev)
		}
	}
	return out
}

// TestSpideringWithoutChromeEmitsSetupAndFails: spidering on a machine with no
// browser downloads Chrome BEFORE the phase ceiling starts (the download's ctx
// carries no deadline), announces it with scan.setup started → failed, and on
// failure the phase fails with a message naming the fix.
func TestSpideringWithoutChromeEmitsSetupAndFails(t *testing.T) {
	buf := captureEvents(t)
	var underDeadline []bool
	fakeChrome(t, func(ctx context.Context, progress cftbrowser.ProgressFunc) (string, error) {
		_, has := ctx.Deadline()
		underDeadline = append(underDeadline, has)
		progress(cftbrowser.ProgressEvent{State: cftbrowser.StateStarted})
		progress(cftbrowser.ProgressEvent{State: cftbrowser.StateDownloading, Bytes: 40 << 20, Total: 150 << 20})
		return "", errors.New("dial tcp: no route to host")
	})

	opts := types.DefaultOptions()
	opts.Silent = true
	opts.Targets = []string{"http://127.0.0.1:1"}
	opts.ProjectUUID = database.DefaultProjectUUID
	repo, _ := newHarvestTestRepo(t)
	r := &Runner{options: opts, repository: repo, settings: config.DefaultSettings()}
	tr := newLedger(string(PhaseSpidering))
	r.currentPhase.Store(tr)

	err := r.runSpideringPhase(context.Background(), &phaseInfra{scanUUID: "setup-test"})
	if err == nil {
		t.Fatal("spidering succeeded although the browser download failed")
	}
	if !strings.Contains(err.Error(), "vigolium doctor --fix --only chrome") {
		t.Errorf("error %q does not name the fix", err)
	}
	if len(underDeadline) != 1 || underDeadline[0] {
		t.Errorf("download ran %d time(s), under a deadline=%v; want once, outside the phase ceiling", len(underDeadline), underDeadline)
	}
	tr.noteError(err) // what the phase loop does with a returned error
	out := tr.outcome()
	if out.State != database.PhaseFailed || !strings.Contains(out.Message, "doctor --fix --only chrome") {
		t.Errorf("outcome = %+v, want failed with the fix in its message", out)
	}

	setup := setupEvents(t, decodeEvents(t, buf))
	if len(setup) != 2 {
		t.Fatalf("scan.setup events = %+v, want started + failed", setup)
	}
	if setup[0].State != "started" || setup[0].Component != "chrome" || setup[0].Phase != string(PhaseSpidering) {
		t.Errorf("first scan.setup = %+v", setup[0])
	}
	last := setup[1]
	if last.State != "failed" || last.Component != "chrome" || last.Message == "" || last.Bytes == nil || *last.Bytes != 40<<20 {
		t.Errorf("terminal scan.setup = %+v, want failed with message and bytes", last)
	}
}

// TestProvisionSpideringBrowserSuccess: a download that works emits started →
// finished with bytes and duration_ms; a machine with a browser emits nothing.
func TestProvisionSpideringBrowserSuccess(t *testing.T) {
	buf := captureEvents(t)
	fakeChrome(t, func(_ context.Context, progress cftbrowser.ProgressFunc) (string, error) {
		progress(cftbrowser.ProgressEvent{State: cftbrowser.StateStarted})
		progress(cftbrowser.ProgressEvent{State: cftbrowser.StateFinished, Bytes: 150 << 20})
		return "/tmp/chrome", nil
	})
	r := &Runner{options: &types.Options{Silent: true}}
	r.currentPhase.Store(newLedger(string(PhaseSpidering)))

	if err := r.provisionSpideringBrowser(context.Background(), *config.DefaultSpideringConfig()); err != nil {
		t.Fatal(err)
	}
	setup := setupEvents(t, decodeEvents(t, buf))
	if len(setup) != 2 || setup[0].State != "started" || setup[1].State != "finished" {
		t.Fatalf("scan.setup events = %+v, want started + finished", setup)
	}
	if setup[1].Bytes == nil || *setup[1].Bytes != 150<<20 || setup[1].Message != "" {
		t.Errorf("finished event = %+v", setup[1])
	}

	browserNeedsDownload = func(string, string) bool { return false }
	buf.Reset()
	if err := r.provisionSpideringBrowser(context.Background(), *config.DefaultSpideringConfig()); err != nil {
		t.Fatal(err)
	}
	if got := setupEvents(t, decodeEvents(t, buf)); len(got) != 0 {
		t.Errorf("browser present but scan.setup emitted: %+v", got)
	}
}

// TestProvisionNucleiTemplatesFailure: a failed clone emits scan.setup
// started → failed for nuclei and marks the phase with reason error.
func TestProvisionNucleiTemplatesFailure(t *testing.T) {
	buf := captureEvents(t)
	orig := ensureNucleiTemplates
	ensureNucleiTemplates = func(tc knownissuescan.Config, p knownissuescan.TemplatesProgress) error {
		dir := tc.TemplatesDir
		failure := errors.New("clone failed; Install with: vigolium doctor --fix --only nuclei")
		p(knownissuescan.TemplatesStarted, dir, nil)
		p(knownissuescan.TemplatesFailed, dir, failure)
		return failure
	}
	t.Cleanup(func() { ensureNucleiTemplates = orig })

	settings := config.DefaultSettings()
	settings.KnownIssueScan.TemplatesDir = t.TempDir() + "/missing"
	r := &Runner{options: &types.Options{Silent: true}, settings: settings}
	tr := newLedger(string(PhaseKnownIssueScan))
	r.currentPhase.Store(tr)

	if err := r.provisionNucleiTemplates(context.Background(), nil); err == nil {
		t.Fatal("want the clone error")
	}
	if !slices.Contains(tr.outcome().Reasons, database.ReasonError) {
		t.Errorf("phase reasons = %v, want error", tr.outcome().Reasons)
	}
	setup := setupEvents(t, decodeEvents(t, buf))
	if len(setup) != 2 || setup[0].Component != "nuclei" || setup[1].State != "failed" {
		t.Fatalf("scan.setup events = %+v, want nuclei started + failed", setup)
	}
}
