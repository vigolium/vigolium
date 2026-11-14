package cli

import (
	"fmt"
	"net/http"
	"net/url"
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

// deriveFileInputScope gives a file-input scan with no -t a host scope.
// Without one the scope-origin index was empty, which admits every
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
	scope, census := fileInputScope(globalInput, resolveScanInputFormat(), scanOpts.InputFileModeExplicit, globalSpecURL)
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

// specFetchClient is the client a spec URL is fetched with: through --proxy
// when one is set, else nil (the loader's proxy-environment client).
func specFetchClient(proxy string) *http.Client {
	if proxy == "" {
		return nil
	}
	u, err := url.Parse(proxy)
	if err != nil {
		return nil
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
}

// fileInputScope is the scope an input file derives: its primary
// host for a capture or spec, every host for a target list or a spec scanned
// with --spec-url. format is the parser's format before content detection;
// census is the per-host record count. Empty when nothing can be derived.
func fileInputScope(path, format string, formatExplicit, specURL bool) (scope []string, census map[string]int) {
	if format == "urls" && !formatExplicit {
		// The parser displaces the URL-list default by content; the scope
		// rule (target list vs capture) must judge the same format.
		if det, derr := source.DetectFormat(path); derr == nil && det.Detected() {
			format = det.Format
		}
	}
	census, primary, err := source.HostCensus(path, format)
	if err != nil || len(census) == 0 {
		if err != nil {
			zap.L().Debug("could not derive scope from input file", zap.String("file", path), zap.Error(err))
		}
		return nil, nil
	}
	if source.IsTargetListFormat(format) || (source.IsOpenAPIFormat(format) && specURL) {
		for host := range census {
			scope = append(scope, host)
		}
		sort.Strings(scope)
	} else if primary != "" {
		scope = []string{primary}
	}
	return scope, census
}

// ingestScanScope is the scope `ingest --scan-on-receive` scans under when no
// -t names one: derived from the ingested file, unless the origin
// mode is "all" or the input is stdin / a URL.
func ingestScanScope(settings *config.Settings) ([]string, map[string]int) {
	in := ingestOpts.Input
	if in == "" || in == "-" || len(globalTargets) > 0 || strings.Contains(in, "://") {
		return nil, nil
	}
	if settings != nil && config.ResolveCLIOriginMode(settings.Scope.CLIOriginMode) == "all" {
		return nil, nil
	}
	return fileInputScope(in, ingestOpts.InputFormat, ingestInputFormatExplicit, ingestOpts.UseSpecServers)
}
