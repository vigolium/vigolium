package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// resolveScanInputFormat is the -i format `vigolium scan` parses with: the
// operator's -I when given, else the content-detected format.
func resolveScanInputFormat() string {
	inputFormat := globalInputMode
	if inputFormat == "urls" && !scanOpts.InputFileModeExplicit {
		if detected := detectInputFormat(globalInput); detected != "" {
			inputFormat = detected
		}
	}
	return inputFormat
}

// isOpenAPIFormat reports whether format names the OpenAPI parser.
func isOpenAPIFormat(format string) bool {
	return format == "openapi" || format == "swagger"
}

// deriveFileInputScope gives a file-input scan with no -t a host scope
// (SAFE-4). Without one the scope-origin index was empty, which admits every
// host: `scan -i capture.har` scanned — and ran nuclei against — every
// third-party host in the capture, session headers attached.
//
// The scope is the file's primary host (source.HostCensus): the first
// record's host for a traffic export, servers[0] for a spec. A target list
// (-I urls, Burp scope) scopes to every host it names, and so does a spec
// with an explicit --spec-url. --scope-origin all keeps the old behaviour.
// The result lands in opts.ScopeTargets (scope only, never a seed) and
// opts.ScopeCensus (for the plan and the banner line printed here).
func deriveFileInputScope(settings *config.Settings, opts *types.Options) {
	if opts == nil || globalInput == "" || globalInput == "-" {
		return
	}
	if len(opts.Targets) > 0 || len(globalTargets) > 0 || len(opts.TargetsFilePaths) > 0 {
		return
	}
	mode := config.DefaultCLIOriginMode
	if settings != nil {
		mode = config.ResolveCLIOriginMode(settings.Scope.CLIOriginMode)
	}
	if mode == "all" {
		return
	}
	format := resolveScanInputFormat()
	if format == "urls" && !scanOpts.InputFileModeExplicit {
		// The parser displaces the URL-list default by content; the scope
		// rule (target list vs capture) must judge the same format.
		if det, derr := source.DetectFormat(globalInput); derr == nil && det.Detected() {
			format = det.Format
		}
	}
	census, primary, err := source.HostCensus(globalInput, format)
	if err != nil || len(census) == 0 {
		if err != nil {
			zap.L().Debug("could not derive scope from input file", zap.String("file", globalInput), zap.Error(err))
		}
		return
	}
	var scope []string
	if source.IsTargetListFormat(format) || (isOpenAPIFormat(format) && globalSpecURL) {
		for host := range census {
			scope = append(scope, host)
		}
		sort.Strings(scope)
	} else if primary != "" {
		scope = []string{primary}
	}
	if len(scope) == 0 {
		return
	}
	opts.ScopeTargets = scope
	opts.ScopeCensus = census

	if globalJSON || globalSilent {
		return
	}
	matcher := config.NewScopeMatcher(settings.Scope, scope...)
	excludedHosts, excludedRecords := 0, 0
	for host, n := range census {
		if !matcher.HostInScope(host) {
			excludedHosts++
			excludedRecords += n
		}
	}
	line := fmt.Sprintf("Scope derived from %s: %s", globalInput, terminal.BoldCyan(strings.Join(scope, ", ")))
	if excludedHosts > 0 {
		line += fmt.Sprintf(" — %d other host(s) with %d record(s) excluded", excludedHosts, excludedRecords)
	}
	line += "; pass -t or --scope-origin all to widen"
	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.NoteSymbol(), line)
}
