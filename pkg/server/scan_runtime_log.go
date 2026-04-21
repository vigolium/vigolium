package server

import (
	"github.com/vigolium/vigolium/internal/config"
)

// forceNativePersistLogs returns a shallow clone of settings with
// scanning_strategy.scan_logs.persist_logs forced to true. Used by every
// REST-API native scan entry point so the scan always produces a
// {sessions_dir}/{scan_uuid}/runtime.log file that API clients can later
// fetch via `vigolium log <uuid>` or the log-ls TUI. Agentic scans via REST
// already write runtime.log unconditionally (handlers_agent.go,
// agentic_scans.go); this is the native-scan parity.
//
// The clone is safe to mutate — nested struct fields are value-copied, and
// only the PersistLogs *bool pointer on the clone is replaced, leaving the
// original h.settings untouched.
func forceNativePersistLogs(settings *config.Settings) *config.Settings {
	if settings == nil {
		settings = config.DefaultSettings()
	}
	clone := *settings
	trueVal := true
	clone.ScanningStrategy.ScanLogs.PersistLogs = &trueVal
	return &clone
}
