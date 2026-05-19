package config

// HTTPConfig holds global outbound-HTTP settings applied across every scan
// phase (dynamic-assessment, discovery, fingerprinting, external harvesting).
// Nested under scanning_strategy; config path is scanning_strategy.http.*.
type HTTPConfig struct {
	// UserAgent overrides the User-Agent header on every outgoing scanner
	// request. Empty (the default) keeps the built-in Chrome string. The
	// literal {version} is replaced with the running binary version, so
	// "Mozilla/5.0 (compatible; Vigolium/{version}; +https://github.com/vigolium/vigolium)"
	// stays correct across upgrades. An explicit -H 'User-Agent: ...' flag
	// still takes precedence over this for the dynamic-assessment phase.
	UserAgent string `yaml:"user_agent"`
}

// DefaultHTTPConfig returns the zero-value HTTP config: empty UserAgent means
// the built-in Chrome default is used (pure opt-in, no behavior change).
func DefaultHTTPConfig() *HTTPConfig {
	return &HTTPConfig{
		UserAgent: "",
	}
}
