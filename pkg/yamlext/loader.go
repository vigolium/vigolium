package yamlext

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

const yamlExtSuffix = ".vgm.yaml"

// IsYAMLExtension returns true if the filename has the .vgm.yaml extension.
func IsYAMLExtension(name string) bool {
	return strings.HasSuffix(name, yamlExtSuffix)
}

// LoadExtension parses and validates a single .vgm.yaml file.
func LoadExtension(path string) (*ExtensionDef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read YAML extension %s: %w", path, err)
	}

	var def ExtensionDef
	if err := yaml.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("failed to parse YAML extension %s: %w", path, err)
	}

	def.sourcePath = path

	// Apply defaults
	if def.MatchersCondition == "" {
		def.MatchersCondition = "or"
	}
	if def.ID == "" {
		base := filepath.Base(path)
		def.ID = strings.TrimSuffix(base, yamlExtSuffix)
		def.ID = strings.ReplaceAll(def.ID, "_", "-")
	}
	if def.Name == "" {
		def.Name = def.ID
	}

	// Validate required fields
	if def.Type == "" {
		return nil, fmt.Errorf("YAML extension %s: missing required field 'type'", path)
	}

	switch def.Type {
	case "active", "passive", "pre_hook", "post_hook":
		// valid
	default:
		return nil, fmt.Errorf("YAML extension %s: invalid type %q (must be active, passive, pre_hook, or post_hook)", path, def.Type)
	}

	return &def, nil
}

// LoadFromConfig discovers and loads all .vgm.yaml files from the extensions config.
func LoadFromConfig(cfg *config.ExtensionsConfig) ([]*ExtensionDef, error) {
	var defs []*ExtensionDef

	// Load from extension_dir
	if cfg.ExtensionDir != "" {
		dir := config.ExpandPath(cfg.ExtensionDir)
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			dirDefs, err := loadFromDir(dir)
			if err != nil {
				zap.L().Warn("Error loading YAML extensions from directory",
					zap.String("dir", dir), zap.Error(err))
			}
			defs = append(defs, dirDefs...)
		}
	}

	// Load explicit script paths (only .vgm.yaml ones)
	for _, scriptPath := range cfg.CustomDir {
		path := config.ExpandPath(scriptPath)
		if !IsYAMLExtension(path) {
			continue
		}
		def, err := LoadExtension(path)
		if err != nil {
			zap.L().Warn("Failed to load YAML extension",
				zap.String("path", path), zap.Error(err))
			continue
		}
		defs = append(defs, def)
	}

	return defs, nil
}

func loadFromDir(dir string) ([]*ExtensionDef, error) {
	var defs []*ExtensionDef

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !IsYAMLExtension(entry.Name()) {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		def, err := LoadExtension(path)
		if err != nil {
			zap.L().Warn("Failed to load YAML extension",
				zap.String("path", path), zap.Error(err))
			continue
		}
		defs = append(defs, def)
	}

	return defs, nil
}
