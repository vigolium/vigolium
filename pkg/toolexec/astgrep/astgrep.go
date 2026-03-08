package astgrep

import (
	"context"
	"sync"
)

var (
	defaultScanner     *Scanner
	defaultScannerOnce sync.Once
	defaultScannerErr  error
)

// ScanDir is a convenience function that uses the default global scanner.
// The scanner is lazily initialized with default configuration.
func ScanDir(ctx context.Context, targetDir, framework string) (*ScanResult, error) {
	scanner, err := getDefaultScanner()
	if err != nil {
		return nil, err
	}
	return scanner.ScanDirWithFramework(ctx, targetDir, framework)
}

// getDefaultScanner returns the lazily-initialized default scanner.
func getDefaultScanner() (*Scanner, error) {
	defaultScannerOnce.Do(func() {
		defaultScanner, defaultScannerErr = NewScanner(nil)
	})
	return defaultScanner, defaultScannerErr
}

// EnsureBinary pre-downloads the binary using the default scanner.
func EnsureBinary(ctx context.Context) error {
	scanner, err := getDefaultScanner()
	if err != nil {
		return err
	}
	return scanner.EnsureBinary(ctx)
}

// Version returns the ast-grep binary version using the default scanner.
func Version() string {
	scanner, err := getDefaultScanner()
	if err != nil {
		return ""
	}
	return scanner.Version()
}

// Must is a helper that panics if scanner creation fails.
func Must(scanner *Scanner, err error) *Scanner {
	if err != nil {
		panic(err)
	}
	return scanner
}
