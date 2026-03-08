package smart_behavior_detection

import "github.com/vigolium/vigolium/pkg/modules/shared/diffscan"

// Options configures the Smart Behavior Detection module.
type Options struct {
	EnableStringDelimiterDetection bool
	EnableNumericContextDetection  bool
	EnableConcatenationTesting     bool
	EnableOrderByInjection         bool

	// SoftConcatenators are operators used in concatenation testing
	SoftConcatenators []string

	// DiffScanOptions configures the differential analysis engine
	DiffScanOptions *diffscan.Option
}

// DefaultOptions returns the default configuration.
func DefaultOptions() *Options {
	return &Options{
		EnableStringDelimiterDetection: true,
		EnableNumericContextDetection:  true,
		EnableConcatenationTesting:     true,
		EnableOrderByInjection:         true,
		SoftConcatenators:              []string{"||", "+", " ", ".", "&", ","},
		DiffScanOptions: &diffscan.Option{
			Confirmations:             3,
			QuantitativeConfirmations: 50,
			QuantileFactor:            5,
			QuantitativeDiffKeys:      []string{},
		},
	}
}
