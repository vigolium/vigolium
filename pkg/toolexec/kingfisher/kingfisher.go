package kingfisher

import (
	"context"
	"sync"
)

var (
	defaultScanner     *Scanner
	defaultScannerOnce sync.Once
	defaultScannerErr  error
)

// Scan is a convenience function that uses the default global scanner.
// The scanner is lazily initialized with default configuration.
//
// For custom configuration, create a Scanner with NewScanner().
func Scan(ctx context.Context, body []byte) (*ScanResult, error) {
	scanner, err := getDefaultScanner()
	if err != nil {
		return nil, err
	}
	return scanner.Scan(ctx, body)
}

// ScanFile is a convenience function that uses the default global scanner.
func ScanFile(ctx context.Context, filePath string) (*ScanResult, error) {
	scanner, err := getDefaultScanner()
	if err != nil {
		return nil, err
	}
	return scanner.ScanFile(ctx, filePath)
}

// getDefaultScanner returns the lazily-initialized default scanner.
func getDefaultScanner() (*Scanner, error) {
	defaultScannerOnce.Do(func() {
		defaultScanner, defaultScannerErr = NewScanner(nil)
	})
	return defaultScanner, defaultScannerErr
}

// EnsureBinary pre-downloads the binary using the default scanner.
// Useful for initialization to avoid delay on first scan.
func EnsureBinary(ctx context.Context) error {
	scanner, err := getDefaultScanner()
	if err != nil {
		return err
	}
	return scanner.EnsureBinary(ctx)
}

// Version returns the kingfisher binary version using the default scanner.
func Version() string {
	scanner, err := getDefaultScanner()
	if err != nil {
		return ""
	}
	return scanner.Version()
}

// Must is a helper that panics if scanner creation fails.
// Useful for package-level initialization.
func Must(scanner *Scanner, err error) *Scanner {
	if err != nil {
		panic(err)
	}
	return scanner
}
