package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/runner"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// applyProbeFlags validates --redirect-mode and records which of the flags a
// probe-only run defaults were explicitly typed.
//
// It deliberately does NOT apply the probe phase's defaults. Those live in
// runner.ApplyNativePhaseSelection, the one seam the CLI, the REST API and the
// programmatic launcher all pass through, so a probe run behaves the same
// whichever way it was started. All this layer owns is the flag surface:
// rejecting a bad value with a usage error, and answering "did the operator
// type it" — a question only cobra can answer.
func applyProbeFlags(opts *types.Options, cmd *cobra.Command) error {
	if err := validateRedirectMode(opts.RedirectMode); err != nil {
		return err
	}
	opts.RecordRedirectChainSet = cmd.Flags().Changed("record-redirect-chain")
	opts.NoWafPacingSet = cmd.Flags().Changed("no-waf-pacing")
	return nil
}

// scanExportOnly backs --export-only: the raw flag values, as typed.
var scanExportOnly []string

// scanExportScope is the resolved scope for a run's jsonl envelope, consumed by
// streamJSONLExport and nothing else.
//
// Deliberately NOT the `export` command's topExportOnly. That global is read by
// streamExportData for EVERY format - html, report, pdf, sarif, bundle and the
// stateless console dump all stream through the same gate - so writing it here
// made `run probe -o report.html --format html` render a report with its
// findings silently removed. A flag that documents itself as narrowing the jsonl
// envelope has to reach only the jsonl envelope.
var scanExportScope = fullExportScope

// applyExportScope resolves which record types this run's jsonl envelope carries.
//
// An explicit --export-only always wins. Otherwise a probe-only run defaults to
// http records alone, because on that run the two envelope types are the same
// information twice: the only modules a sweep runs are the 26 fingerprint ones
// (whose findings are all "Technology Detected: X") and surface-scoring (which
// emits nothing), and the fingerprint verdict now lands on the record itself in
// http_records.technology. Emitting both doubles the file to restate what the
// record already says.
//
// Any other run keeps the full envelope: a real scan's findings are not
// derivable from its records, so narrowing there would silently drop results.
//
// The probe default is resolved here rather than in runner.ApplyNativePhaseSelection
// (where applyProbeOnlyDefaults lives) because it governs a CLI-only output path:
// the REST API and the programmatic launcher never reach streamExportData, so
// there is no second caller for the two to disagree about.
//
// Called AFTER phase selection, which is what resolves ProbeEnabled.
func applyExportScope(opts *types.Options) error {
	if len(scanExportOnly) > 0 {
		scope := newExportScope(scanExportOnly)
		if err := scope.validate("--export-only"); err != nil {
			return asUsageError(err)
		}
		scanExportScope = scope
		return nil
	}
	if runner.IsProbeOnlyRun(opts) {
		scanExportScope = newExportScope([]string{"http"})
	}
	return nil
}

// warnInertProbeFlags reports probe-phase flags the operator typed on a run that
// will not execute the probe phase.
//
// Each of these flags is silent about doing nothing otherwise: --tls-probe and
// --favicon are read only by runProbePhase, and RecordRedirectChain reaches
// only the probe phase's ExecutorConfig. The repo already settled this shape for the pace qualifiers —
// a qualifier naming a skipped phase "warns loudly rather than failing, but it
// must not be silent, since that is a cap the operator believes is in force and
// is not". Same reasoning: an operator who typed --tls-probe believes they are
// getting certificates.
//
// Called AFTER phase selection, which is what resolves ProbeEnabled.
func warnInertProbeFlags(opts *types.Options, cmd *cobra.Command) {
	if opts == nil || cmd == nil || opts.ProbeEnabled || opts.Silent {
		return
	}
	for _, f := range []struct{ name, effect string }{
		{"tls-probe", "no TLS handshake is performed"},
		{"favicon", "no icon is fetched"},
		{"record-redirect-chain", "redirect hops are not recorded"},
	} {
		// flagOn, not Changed: `--tls-probe=false` is an operator saying they do
		// NOT want the probe behaviour, and warning that their off switch has no
		// effect on a phase that is not running is noise about a non-problem.
		if flagOn(cmd, f.name) {
			fmt.Fprintf(os.Stderr, "%s %s only affects the %s phase, which this run does not include — %s. Add %s or use %s.\n",
				terminal.WarnPrefix(),
				terminal.BoldCyan("--"+f.name),
				terminal.BoldCyan("probe"),
				f.effect,
				terminal.BoldCyan("--probe"),
				terminal.BoldCyan("vigolium run probe"))
		}
	}
}

// validateRedirectMode rejects an unknown --redirect-mode up front. The
// resolver falls back to "in-scope" on an unrecognised value so a library caller
// cannot accidentally get "follow nothing" — which is the right default there
// and the wrong one here, where a typo must not silently change what the scan
// follows.
func validateRedirectMode(mode string) error {
	mode = strings.TrimSpace(mode)
	if mode == "" || vighttp.ValidRedirectMode(mode) {
		return nil
	}
	return usageErrorf("invalid --redirect-mode value %q; valid modes: %s",
		mode, strings.Join(vighttp.RedirectModes, ", "))
}
