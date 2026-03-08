package race_interference

// Options configures the race interference scanner behavior.
type Options struct {
	// EnableInputStorageDetection detects input values persisting across requests (cache poisoning).
	EnableInputStorageDetection bool

	// EnableCrossContaminationDetection detects data from request X appearing in response Y.
	EnableCrossContaminationDetection bool

	// EnableRequestInterferenceDetection detects divergent responses from parallel requests.
	EnableRequestInterferenceDetection bool

	// BaselineRequestCount is the number of sequential requests for establishing baseline.
	BaselineRequestCount int

	// ParallelProbeCount is the number of concurrent requests in the parallel probe phase.
	ParallelProbeCount int

	// ConfirmationRequestCount is the number of sequential requests for confirmation.
	ConfirmationRequestCount int
}

// DefaultOptions returns the default scanner options.
func DefaultOptions() Options {
	return Options{
		EnableInputStorageDetection:        true,
		EnableCrossContaminationDetection:  true,
		EnableRequestInterferenceDetection: true,
		BaselineRequestCount:               3,
		ParallelProbeCount:                 9,
		ConfirmationRequestCount:           9,
	}
}
