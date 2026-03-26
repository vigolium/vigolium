package diffscan

type Option struct {
	Confirmations             int
	QuantitativeConfirmations int
	QuantileFactor            int
	QuantitativeDiffKeys      []string
	// CustomCanary is prepended to canaryKeys for response fingerprinting.
	CustomCanary string
}

func NewOption() *Option {
	return &Option{
		Confirmations:             5,
		QuantitativeConfirmations: 50,
		QuantileFactor:            5,
		QuantitativeDiffKeys:      []string{},
	}
}
