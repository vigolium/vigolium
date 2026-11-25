package cli

import "github.com/spf13/pflag"

// registerAllowWritesFlag declares --allow-writes for the scan commands (scan,
// run via registerScanPipelineFlags; scan-url, scan-request via
// registerLightweightScanIOFlags). It binds into scanOpts.AllowWrites.
//
// Off, the dynamic assessment re-sends a stored record whose method is not
// GET/HEAD/OPTIONS only when that record was first stored with a real
// response (a proxy, browser or scan capture); a write template — an ingested
// spec operation, a request-only stub — is held back and counted in the
// templates_skipped_unsafe_method caveat, and the executor never fetches a
// baseline for one. kit unlock-walk has its own --allow-writes for the
// browser walk; the two are separate commands, not one flag.
func registerAllowWritesFlag(flags *pflag.FlagSet) {
	flags.BoolVar(&scanOpts.AllowWrites, "allow-writes", false,
		"Let the dynamic assessment send stored write templates (POST/PUT/PATCH/DELETE first stored without a response, e.g. ingested spec operations). Off, they are skipped and counted in the templates_skipped_unsafe_method caveat")
}
