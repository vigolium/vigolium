package clicommon

import "go.uber.org/zap"

// SyncLogger flushes buffered log entries. Defer it in command RunE functions.
func SyncLogger() {
	_ = zap.L().Sync()
}
