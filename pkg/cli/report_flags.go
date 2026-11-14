package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/pkg/output"
)

// Report-rendering knobs shared by every command that renders a report from the
// format table: the scan commands (scan, run, scan-url, scan-request), export
// and import. One registration so the help text cannot diverge between them.
//
// The defaults hold for commands that render without registering the flags
// (the REST server's post-scan reports).
var (
	reportMaxBodyBytes = output.DefaultMarkdownMaxBodyBytes
	reportPDFTimeout   time.Duration
	// reportNoRedact is --no-redact (SAFE-12): keep credentials in shareable
	// report evidence.
	reportNoRedact bool
)

// registerReportFlags declares --max-body-bytes and --pdf-timeout.
func registerReportFlags(flags *pflag.FlagSet) {
	flags.IntVar(&reportMaxBodyBytes, "max-body-bytes", output.DefaultMarkdownMaxBodyBytes,
		"Cap each HTTP request/response embedded in a Markdown report at this many bytes (UTF-8 safe, with a note naming the command that prints it whole); 0 or negative = no cap")
	flags.DurationVar(&reportPDFTimeout, "pdf-timeout", 0,
		fmt.Sprintf("Bound the headless-Chrome PDF render (0 = $VIGOLIUM_PDF_TIMEOUT, else %s)", output.DefaultPDFTimeout))
	flags.BoolVar(&reportNoRedact, "no-redact", false,
		"Keep credential headers, cookie values and sensitive query parameters in HTML/PDF/SARIF/Markdown report evidence (redacted by default; also output.redact_evidence: false). JSONL and the database always keep the raw exchange")
}

// validateReportFlags rejects knob values no renderer can honour.
func validateReportFlags() error {
	if reportPDFTimeout < 0 {
		return usageErrorf("--pdf-timeout must not be negative, got %s", reportPDFTimeout)
	}
	return nil
}

// applyReportFlags copies the report knobs into meta: the Markdown body cap,
// the PDF timeout, the --fail-on threshold the junit format fails at, and the
// follow-up composer that pins report follow-ups to this run's --db/project.
//
// discardedStore says the report renders from a database deleted when the
// command exits (a stateless scan's temp DB). No follow-up command can reopen
// it, so follow-ups are suppressed rather than pointed at a store that is gone
// (or, bare, at the default store, where the same finding id names another row).
func applyReportFlags(meta *output.HTMLReportMeta, discardedStore bool) {
	meta.MaxBodyBytes = reportMaxBodyBytes
	if reportMaxBodyBytes <= 0 {
		meta.MaxBodyBytes = -1
	}
	meta.PDFTimeout = reportPDFTimeout
	meta.NoRedact = reportNoRedact || redactEvidenceDisabledInConfig()
	meta.RedactHeaders = operatorHeaderNames()
	meta.FailOn = scanFailOn
	meta.FollowUp = followUpQuery
	if discardedStore {
		meta.FollowUp = func(...string) string { return "" }
	}
}

// redactEvidenceDisabledInConfig reads output.redact_evidence from the
// effective config; only an explicit false disables report redaction.
func redactEvidenceDisabledInConfig() bool {
	settings := settingsOrDefaults()
	return settings != nil && settings.Output.RedactEvidence != nil && !*settings.Output.RedactEvidence
}

// operatorHeaderNames are the lowercased names of the operator's -H headers,
// redacted in report evidence on top of
// the built-in credential table (SAFE-12).
func operatorHeaderNames() map[string]struct{} {
	out := map[string]struct{}{}
	add := func(h string) {
		if name, _, ok := strings.Cut(h, ":"); ok {
			if n := strings.ToLower(strings.TrimSpace(name)); n != "" {
				out[n] = struct{}{}
			}
		}
	}
	if scanOpts != nil {
		for _, h := range scanOpts.Headers {
			add(h)
		}
	}
	return out
}
