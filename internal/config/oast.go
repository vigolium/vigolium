package config

// OASTConfig configures Out-of-Band Application Security Testing (OAST)
// using an interactsh server for callback detection.
type OASTConfig struct {
	Enabled      bool   `yaml:"enabled"`       // default: true
	ServerURL    string `yaml:"server_url"`    // interactsh server URL, default: "oast.pro"
	Token        string `yaml:"token"`         // optional auth token
	PollInterval int    `yaml:"poll_interval"` // seconds between polls, default: 5
	GracePeriod  int    `yaml:"grace_period"`  // seconds to wait after scan ends for late callbacks, default: 10

	OastURL         string `yaml:"oast_url"`          // fixed callback URL (empty = auto-generate via interactsh)
	BlindXSSSrc     string `yaml:"blind_xss_src"`     // JS script src for blind XSS payloads
	EnabledBlindXSS bool   `yaml:"enabled_blind_xss"` // default: false
}

// DefaultOASTConfig returns sensible OAST defaults (enabled by default).
func DefaultOASTConfig() *OASTConfig {
	return &OASTConfig{
		Enabled:      true,
		ServerURL:    "oast.pro",
		PollInterval: 5,
		GracePeriod:  10,
	}
}
