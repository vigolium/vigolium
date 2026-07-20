package config

import (
	"crypto/rand"
	"fmt"
)

// DefaultBurpBridgeURL is the loopback address the Vigolium Burp extension
// listens on. Kept as a literal rather than referencing burpbridge.DefaultURL
// because pkg/burpbridge imports pkg/database, which imports this package —
// TestDefaultBurpBridgeURLMatchesBridge in pkg/cli guards the two staying equal.
const DefaultBurpBridgeURL = "http://127.0.0.1:9009"

// ServerConfig holds API server configuration
type ServerConfig struct {
	AuthAPIKey         string `yaml:"auth_api_key"`
	UsersFile          string `yaml:"users_file"`
	ServicePort        int    `yaml:"service_port"`
	IngestProxyPort    int    `yaml:"ingest_proxy_port"`
	CORSAllowedOrigins string `yaml:"cors_allowed_origins"`
	EnableMetrics      bool   `yaml:"enable_metrics"`
	DisableSwagger     bool   `yaml:"disable_swagger"`
	AgentHeavyMax      int    `yaml:"agent_heavy_max"`     // max concurrent heavy agent runs (autopilot/swarm); 0 = default 5
	AgentLightMax      int    `yaml:"agent_light_max"`     // max concurrent light agent runs (query/chat); 0 = default 10
	AgentQueueTimeout  string `yaml:"agent_queue_timeout"` // max wait when all agent slots busy; 0/empty = default 30s
	License            string `yaml:"license"`             // license identifier surfaced in /server-info for UI display
	MirrorFSPath       string `yaml:"mirror_fs_path"`      // when set, mirror ingested traffic + findings to this dir as a live filesystem tree (see --mirror-fs)
	EnableBurpBridge   bool   `yaml:"enable_burp_bridge"`  // opt in to merging live Burp Proxy history into /api/http-records using BurpBridgeURL (see -B/--burp-bridge-url)
	BurpBridgeURL      string `yaml:"burp_bridge_url"`     // loopback Burp bridge address used when EnableBurpBridge is set; -B/--burp-bridge-url and $VIGOLIUM_BURP_BRIDGE_URL take precedence
}

// DefaultServerConfig returns default server configuration
// with an auto-generated random API key
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		AuthAPIKey:         GenerateRandomHex(20),
		UsersFile:          "~/.vigolium/users.json",
		ServicePort:        9002,
		CORSAllowedOrigins: "reflect-origin",
		EnableMetrics:      true,
		BurpBridgeURL:      DefaultBurpBridgeURL,
	}
}

// GenerateRandomHex returns a random hex string of the specified length.
// length must be even; the result is length/2 random bytes encoded as hex.
func GenerateRandomHex(length int) string {
	b := make([]byte, length/2)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
