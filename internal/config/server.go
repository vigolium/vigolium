package config

import (
	"crypto/rand"
	"fmt"
)

// ServerConfig holds API server configuration
type ServerConfig struct {
	AuthAPIKey         string `yaml:"auth_api_key"`
	UsersFile          string `yaml:"users_file"`
	ServicePort        int    `yaml:"service_port"`
	IngestProxyPort    int    `yaml:"ingest_proxy_port"`
	CORSAllowedOrigins string `yaml:"cors_allowed_origins"`
	EnableMetrics      bool   `yaml:"enable_metrics"`
	DisableSwagger     bool   `yaml:"disable_swagger"`
	AgentHeavyMax      int    `yaml:"agent_heavy_max"`      // max concurrent heavy agent runs (autopilot/swarm); 0 = default 5
	AgentLightMax      int    `yaml:"agent_light_max"`      // max concurrent light agent runs (query/chat); 0 = default 10
	AgentQueueTimeout  string `yaml:"agent_queue_timeout"`  // max wait when all agent slots busy; 0/empty = default 30s
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
	}
}

// GenerateRandomHex returns a random hex string of the specified length.
// length must be even; the result is length/2 random bytes encoded as hex.
func GenerateRandomHex(length int) string {
	b := make([]byte, length/2)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
