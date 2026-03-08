package harness

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LoadSASTExtractionDefinition loads a single extraction definition from a YAML file.
func LoadSASTExtractionDefinition(path string) (*SASTExtractionDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read extraction definition %s: %w", path, err)
	}

	var def SASTExtractionDefinition
	if err := yaml.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("parse extraction definition %s: %w", path, err)
	}

	// Default assertion to "strict"
	for i := range def.ExpectedRoutes {
		if def.ExpectedRoutes[i].Assertion == "" {
			def.ExpectedRoutes[i].Assertion = "strict"
		}
	}

	return &def, nil
}

// LoadSASTExtractionDefinitionsFromDir loads all extraction definitions from a directory.
func LoadSASTExtractionDefinitionsFromDir(dir string) ([]*SASTExtractionDefinition, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("glob extraction definitions: %w", err)
	}

	var defs []*SASTExtractionDefinition
	for _, f := range files {
		def, err := LoadSASTExtractionDefinition(f)
		if err != nil {
			return nil, err
		}
		defs = append(defs, def)
	}
	return defs, nil
}

// LoadSASTSARIFDefinition loads a single SARIF definition from a YAML file.
func LoadSASTSARIFDefinition(path string) (*SASTSARIFDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read SARIF definition %s: %w", path, err)
	}

	var def SASTSARIFDefinition
	if err := yaml.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("parse SARIF definition %s: %w", path, err)
	}

	// Default format to "sarif"
	if def.Format == "" {
		def.Format = "sarif"
	}

	return &def, nil
}

// LoadSASTSARIFDefinitionsFromDir loads all SARIF definitions from a directory.
func LoadSASTSARIFDefinitionsFromDir(dir string) ([]*SASTSARIFDefinition, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("glob SARIF definitions: %w", err)
	}

	var defs []*SASTSARIFDefinition
	for _, f := range files {
		def, err := LoadSASTSARIFDefinition(f)
		if err != nil {
			return nil, err
		}
		defs = append(defs, def)
	}
	return defs, nil
}

// LoadSASTHandoffDefinition loads a single handoff definition from a YAML file.
func LoadSASTHandoffDefinition(path string) (*SASTHandoffDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read handoff definition %s: %w", path, err)
	}

	var def SASTHandoffDefinition
	if err := yaml.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("parse handoff definition %s: %w", path, err)
	}

	return &def, nil
}

// LoadSASTHandoffDefinitionsFromDir loads all handoff definitions from a directory.
func LoadSASTHandoffDefinitionsFromDir(dir string) ([]*SASTHandoffDefinition, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("glob handoff definitions: %w", err)
	}

	var defs []*SASTHandoffDefinition
	for _, f := range files {
		def, err := LoadSASTHandoffDefinition(f)
		if err != nil {
			return nil, err
		}
		defs = append(defs, def)
	}
	return defs, nil
}

// SASTDefinitionsDir returns the path to the whitebox SAST definitions directory.
func SASTDefinitionsDir() string {
	base := DefinitionsDir()
	return filepath.Join(base, "whitebox")
}
