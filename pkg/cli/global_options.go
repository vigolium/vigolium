package cli

import "github.com/vigolium/vigolium/pkg/types"

// globalFlagsToOptions copies the global transport and pace flags into opts:
// --timeout, --proxy, --verbose, --debug, --dump-traffic, --concurrency,
// --max-per-host, --no-waf-pacing and --max-host-error. Every command that
// sends target traffic through a types.Options starts from it, so a new global
// flag of this kind is added here once.
func globalFlagsToOptions(opts *types.Options) {
	opts.Timeout = globalTimeout
	opts.ProxyURL = globalProxy
	opts.Verbose = globalVerbose
	opts.Debug = globalDebug
	opts.DumpTraffic = globalDumpTraffic
	opts.Concurrency = globalConcurrency
	opts.MaxPerHost = globalMaxPerHost
	opts.NoWafPacing = globalNoWafPacing
	opts.MaxHostError = globalMaxHostError
	opts.Offline = globalOffline
}

// globalScanFlagsToOptions is globalFlagsToOptions plus the global flags a
// Runner-backed scan reads: --silent, --json, --config,
// --max-findings-per-module and --no-tech-filter.
func globalScanFlagsToOptions(opts *types.Options) {
	globalFlagsToOptions(opts)
	opts.Silent = globalSilent
	opts.JSONOutput = globalJSON
	opts.ConfigPath = globalConfig
	opts.MaxFindingsPerModule = globalMaxFindingsPerModule
	opts.NoTechFilter = globalNoTechFilter
}
