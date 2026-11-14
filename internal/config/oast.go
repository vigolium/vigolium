package config

// DefaultOASTServer is the public interactsh server used when server_url is
// unset, and the one fallback_to_default falls back TO. Named rather than
// repeated so the fallback cannot drift from the default it is named after.
const DefaultOASTServer = "oast.pro"

// OASTConfig configures Out-of-Band Application Security Testing (OAST)
// using an interactsh server for callback detection.
type OASTConfig struct {
	Enabled   bool   `yaml:"enabled"`    // default: true
	ServerURL string `yaml:"server_url"` // interactsh server URL, default: "oast.pro"
	Token     string `yaml:"token"`      // optional auth token
	// FallbackToDefault re-registers against DefaultOASTServer when the
	// configured server_url does not answer, so one dead or misspelled host
	// does not silently cost a scan every blind/out-of-band check. Default
	// true. The token is NOT carried to the fallback - it belongs to the server
	// the operator named.
	//
	// Turn it off where a callback may not reach a third party: an
	// out-of-band callback carries whatever the payload pulled out of the
	// target, so on an engagement whose scope names the collector, falling back
	// to a public server is an egress the operator did not authorize.
	FallbackToDefault bool `yaml:"fallback_to_default"` // default: true
	PollInterval      int  `yaml:"poll_interval"`       // seconds between polls, default: 5
	GracePeriod       int  `yaml:"grace_period"`        // seconds to wait after scan ends for late callbacks, default: 10

	OastURL         string `yaml:"oast_url"`          // fixed callback URL (empty = auto-generate via interactsh)
	BlindXSSSrc     string `yaml:"blind_xss_src"`     // JS script src for blind XSS payloads
	EnabledBlindXSS bool   `yaml:"enabled_blind_xss"` // default: false

	// KeepSession keeps the interactsh registration open when a scan ends
	// (stored in oast_sessions) instead of deregistering, so late callbacks are
	// collected by `vigolium oast poll` or the server's periodic poller.
	// Default true; never applies to a stateless (-S) scan, whose store is
	// discarded.
	KeepSession bool `yaml:"keep_session"`
	// SessionPollInterval is how often, in minutes, `vigolium server` polls
	// kept sessions. Default 5; 0 or negative disables the server poller.
	SessionPollInterval int `yaml:"session_poll_interval"`
}

// DefaultOASTConfig returns sensible OAST defaults (enabled by default).
func DefaultOASTConfig() *OASTConfig {
	return &OASTConfig{
		Enabled:             true,
		ServerURL:           DefaultOASTServer,
		FallbackToDefault:   true,
		PollInterval:        5,
		GracePeriod:         10,
		KeepSession:         true,
		SessionPollInterval: 5,
	}
}
