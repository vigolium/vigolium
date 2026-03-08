package harness

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LoadAgentFixture loads a single agent fixture from a JSON file.
func LoadAgentFixture(path string) (*AgentFixture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read agent fixture %s: %w", path, err)
	}

	var fixture AgentFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		return nil, fmt.Errorf("parse agent fixture %s: %w", path, err)
	}

	return &fixture, nil
}

// LoadAgentParsingDefinition loads a single parsing definition from a YAML file.
func LoadAgentParsingDefinition(path string) (*AgentParsingDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read agent parsing definition %s: %w", path, err)
	}

	var def AgentParsingDefinition
	if err := yaml.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("parse agent parsing definition %s: %w", path, err)
	}

	return &def, nil
}

// LoadAgentParsingDefinitionsFromDir loads all parsing definitions from a directory.
func LoadAgentParsingDefinitionsFromDir(dir string) ([]*AgentParsingDefinition, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("glob agent parsing definitions: %w", err)
	}

	var defs []*AgentParsingDefinition
	for _, f := range files {
		def, err := LoadAgentParsingDefinition(f)
		if err != nil {
			return nil, err
		}
		defs = append(defs, def)
	}
	return defs, nil
}

// LoadAgentQualityDefinition loads a single quality definition from a YAML file.
func LoadAgentQualityDefinition(path string) (*AgentQualityDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read agent quality definition %s: %w", path, err)
	}

	var def AgentQualityDefinition
	if err := yaml.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("parse agent quality definition %s: %w", path, err)
	}

	// Default assertion to "soft"
	if def.Assertion == "" {
		def.Assertion = "soft"
	}

	return &def, nil
}

// LoadAgentQualityDefinitionsFromDir loads all quality definitions from a directory.
func LoadAgentQualityDefinitionsFromDir(dir string) ([]*AgentQualityDefinition, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("glob agent quality definitions: %w", err)
	}

	var defs []*AgentQualityDefinition
	for _, f := range files {
		def, err := LoadAgentQualityDefinition(f)
		if err != nil {
			return nil, err
		}
		defs = append(defs, def)
	}
	return defs, nil
}

// LoadAgentHandoffDefinition loads a single handoff definition from a YAML file.
func LoadAgentHandoffDefinition(path string) (*AgentHandoffDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read agent handoff definition %s: %w", path, err)
	}

	var def AgentHandoffDefinition
	if err := yaml.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("parse agent handoff definition %s: %w", path, err)
	}

	// Default assertion to "strict" for each record
	for i := range def.Expected.Records {
		if def.Expected.Records[i].Assertion == "" {
			def.Expected.Records[i].Assertion = "strict"
		}
	}

	return &def, nil
}

// LoadAgentHandoffDefinitionsFromDir loads all handoff definitions from a directory.
func LoadAgentHandoffDefinitionsFromDir(dir string) ([]*AgentHandoffDefinition, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("glob agent handoff definitions: %w", err)
	}

	var defs []*AgentHandoffDefinition
	for _, f := range files {
		def, err := LoadAgentHandoffDefinition(f)
		if err != nil {
			return nil, err
		}
		defs = append(defs, def)
	}
	return defs, nil
}

// LoadAgentE2EDefinition loads a single E2E definition from a YAML file.
func LoadAgentE2EDefinition(path string) (*AgentE2EDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read agent E2E definition %s: %w", path, err)
	}

	var def AgentE2EDefinition
	if err := yaml.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("parse agent E2E definition %s: %w", path, err)
	}

	// Default assertion to "soft"
	if def.Expected.Assertion == "" {
		def.Expected.Assertion = "soft"
	}

	return &def, nil
}

// LoadAgentE2EDefinitionsFromDir loads all E2E definitions from a directory.
func LoadAgentE2EDefinitionsFromDir(dir string) ([]*AgentE2EDefinition, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("glob agent E2E definitions: %w", err)
	}

	var defs []*AgentE2EDefinition
	for _, f := range files {
		def, err := LoadAgentE2EDefinition(f)
		if err != nil {
			return nil, err
		}
		defs = append(defs, def)
	}
	return defs, nil
}

// AgentDefinitionsDir returns the path to the whitebox agent definitions directory.
func AgentDefinitionsDir() string {
	base := DefinitionsDir()
	return filepath.Join(base, "whitebox", "agent")
}

// AgentFixturesDir returns the path to the agent fixtures directory.
func AgentFixturesDir() string {
	candidates := []string{
		"../../testdata/agent-fixtures",
		"../testdata/agent-fixtures",
		"test/testdata/agent-fixtures",
	}
	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	return "test/testdata/agent-fixtures"
}
