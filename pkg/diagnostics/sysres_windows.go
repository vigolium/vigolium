//go:build windows

package diagnostics

func freeBytes(string) (uint64, bool) { return 0, false }

func fdLimit() (uint64, bool) { return 0, false }
