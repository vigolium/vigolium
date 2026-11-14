package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cftbrowser"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/knownissuescan"
	"github.com/vigolium/vigolium/pkg/nucleitemplates"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// Lazy first-run dependencies.
//
// The CLI does not install Chrome or nuclei-templates before a scan (an eager
// first-run step could stall a scan-url for minutes before its first request).
// Instead the phase that needs a dependency provisions it when it
// runs, announces the step on stderr with an ETA, and emits scan.setup
// {component, state, bytes, duration_ms} so a machine reader can tell a setup
// pause from a hung scan. Provisioning happens BEFORE the phase starts its own
// clock, so a download is never charged to the phase's time budget.

// Setup components, named after their `vigolium doctor --fix --only` ids so the
// failure hint and the event agree.
const (
	setupComponentChrome = "chrome"
	setupComponentNuclei = "nuclei"
)

// Package vars so tests can provision without a network fetch.
var (
	browserNeedsDownload  = spitolas.BrowserNeedsDownload
	ensureCfTBrowser      = cftbrowser.EnsureBrowser
	ensureNucleiTemplates = knownissuescan.EnsureTemplates
)

// setupStep is one in-flight provisioning step: it owns the stderr lines and
// the scan.setup events for that step.
type setupStep struct {
	r           *Runner
	component   string
	label       string
	start       time.Time
	lastQuarter int64
	announced   bool
}

// beginSetup prints the step's ETA line and emits scan.setup{state:started}.
func (r *Runner) beginSetup(component, label, eta string) *setupStep {
	s := &setupStep{r: r, component: component, label: label, start: time.Now()}
	r.printPhaseDetail(fmt.Sprintf("Setup: %s — %s", terminal.HiTeal(label), eta))
	scanevents.Emit(scanevents.Event{
		Type:      scanevents.TypeScanSetup,
		Phase:     r.currentPhaseName(),
		Component: component,
		State:     "started",
	})
	return s
}

// progress prints the download size once it is known, then every quarter.
func (s *setupStep) progress(bytes, total int64) {
	if total <= 0 {
		return
	}
	if !s.announced {
		s.announced = true
		s.r.printPhaseDetail(fmt.Sprintf("Setup: downloading %s %s …", s.label, terminal.HiTeal(terminal.HumanBytes(total))))
	}
	quarter := bytes * 4 / total
	if quarter > s.lastQuarter && quarter < 4 {
		s.lastQuarter = quarter
		s.r.printPhaseDetail(fmt.Sprintf("Setup: %s %d%% (%s of %s, %s elapsed)", s.label, quarter*25,
			terminal.HumanBytes(bytes), terminal.HumanBytes(total), fmtDuration(time.Since(s.start))))
	}
}

// finish emits scan.setup{finished|failed} and prints the outcome line.
func (s *setupStep) finish(bytes int64, err error) {
	elapsed := time.Since(s.start)
	ev := scanevents.Event{
		Type:       scanevents.TypeScanSetup,
		Phase:      s.r.currentPhaseName(),
		Component:  s.component,
		State:      "finished",
		DurationMS: elapsed.Milliseconds(),
	}
	if bytes > 0 {
		ev.Bytes = scanevents.Int64(bytes)
	}
	if err != nil {
		ev.State = "failed"
		ev.Message = err.Error()
		s.r.printPhaseDetail(fmt.Sprintf("Setup: %s %s after %s", s.label, terminal.Red("failed"), fmtDuration(elapsed)))
	} else {
		size := ""
		if bytes > 0 {
			size = terminal.HumanBytes(bytes) + " in "
		}
		s.r.printPhaseDetail(fmt.Sprintf("Setup: %s ready (%s%s)", s.label, size, fmtDuration(elapsed)))
	}
	scanevents.Emit(ev)
}

// provisionSpideringBrowser downloads Chrome for Testing when the crawl would
// otherwise have to (no configured, embedded, system or cached browser), before
// the spidering phase starts its deadline. A failure is returned with a message
// naming the install command; the phase records it as failed.
func (r *Runner) provisionSpideringBrowser(ctx context.Context, cfg config.SpideringConfig) error {
	if !browserNeedsDownload(cfg.BrowserEngine, cfg.BrowserPath) {
		return nil
	}
	step := r.beginSetup(setupComponentChrome, "Chrome for Testing",
		"no browser found, downloading it once (~150 MB, typically under a minute; not counted against the spidering budget)")
	var bytes int64
	_, err := ensureCfTBrowser(ctx, func(ev cftbrowser.ProgressEvent) {
		if ev.Bytes > bytes {
			bytes = ev.Bytes
		}
		if ev.State == cftbrowser.StateDownloading {
			step.progress(ev.Bytes, ev.Total)
		}
	})
	step.finish(bytes, err)
	if err != nil {
		// Returned, so the phase-error policy records it (failed, with this
		// message) and the scan carries on without the crawl.
		return fmt.Errorf("chrome for testing download failed: %w; run 'vigolium doctor --fix --only chrome' to install it, or point spidering.browser_path at an installed Chrome/Chromium", err)
	}
	return nil
}

// provisionNucleiTemplates clones nuclei-templates when they are missing and the
// known-issue scan has hosts to run against, before the nuclei leg starts its
// deadline. A failure marks the phase with reason error (the phase itself
// carries on with the secret scan); the caller records the returned error and
// skips the nuclei leg.
func (r *Runner) provisionNucleiTemplates(ctx context.Context, inScopeHosts []database.HostTarget) error {
	tc := r.knownIssueTemplatesConfig()
	if knownissuescan.TemplatesPresent(tc.TemplatesDir) {
		return nil
	}
	// Nothing to scan means nothing to clone: the nuclei leg skips itself.
	if r.repository != nil {
		paths, err := r.repository.GetDistinctPaths(ctx, r.options.ProjectUUID, inScopeHosts...)
		if err == nil && len(paths) == 0 {
			return nil
		}
	}
	var step *setupStep
	err := ensureNucleiTemplates(tc, func(state, _ string, _ error) {
		if state == knownissuescan.TemplatesStarted {
			step = r.beginSetup(setupComponentNuclei, "nuclei-templates",
				"not found, downloading the release archive once (typically under a minute; not counted against the known-issue-scan budget)")
		}
	})
	if step != nil {
		step.finish(0, err)
	}
	if err != nil {
		// The error already names `vigolium doctor --fix --only nuclei`.
		r.currentPhase.Load().markPartial(database.ReasonError)
		return err
	}
	return nil
}

// knownIssueTemplatesConfig is where this scan's nuclei templates live and how
// a missing copy may be installed: the templates directory, --offline and the
// pinned release, resolved from the run's options and settings.
func (r *Runner) knownIssueTemplatesConfig() knownissuescan.Config {
	tc := knownissuescan.Config{Offline: r.offline()}
	if r.settings != nil {
		kis := &r.settings.KnownIssueScan
		if kis.TemplatesDir != "" {
			tc.TemplatesDir = config.ExpandPath(kis.TemplatesDir)
		}
		tc.TemplatesPin = nucleitemplates.Pin{Version: kis.TemplatesVersion, SHA256: kis.TemplatesSHA256}
	}
	return tc
}
