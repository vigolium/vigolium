package nginx_path_escape

import "github.com/vigolium/vigolium/pkg/modules/shared/diffscan"

// Options configures the Nginx Path Escape Detection module.
type Options struct {
	// DiffScanOptions configures the differential analysis engine
	DiffScanOptions *diffscan.Option

	// BaselineRequests is the number of requests to send for baseline stabilization
	BaselineRequests int

	// MaxPathLevels limits how many path levels to test (0 = unlimited).
	// For /a/b/c/d/e with MaxPathLevels=3:
	//   Tests: /a/b/c/d/e (level 0), /a/b/c/d (level 1), /a/b/c (level 2)
	MaxPathLevels int
}

// DefaultOptions returns the default configuration.
func DefaultOptions() *Options {
	return &Options{
		BaselineRequests: 2,
		MaxPathLevels:    5,
		DiffScanOptions: &diffscan.Option{
			Confirmations:             3,
			QuantitativeConfirmations: 10,
			QuantileFactor:            5,
			QuantitativeDiffKeys:      []string{},
		},
	}
}
