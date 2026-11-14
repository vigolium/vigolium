package diagnostics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// TemplatesMarkerFile is written into the nuclei templates directory by the
// pinned-archive install (`vigolium doctor --fix --only nuclei`): which
// release it is, its archive digest, and when it was installed, so doctor can
// say "stale" from a fact rather than a directory mtime.
const TemplatesMarkerFile = ".vigolium-templates.json"

// TemplatesMarker is the content of TemplatesMarkerFile.
type TemplatesMarker struct {
	Version     string    `json:"version"`
	SHA256      string    `json:"sha256,omitempty"`
	Source      string    `json:"source,omitempty"`
	InstalledAt time.Time `json:"installed_at"`
}

// ReadTemplatesMarker reads dir's marker.
func ReadTemplatesMarker(dir string) (*TemplatesMarker, error) {
	data, err := os.ReadFile(filepath.Join(dir, TemplatesMarkerFile))
	if err != nil {
		return nil, err
	}
	var m TemplatesMarker
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// WriteTemplatesMarker writes dir's marker.
func WriteTemplatesMarker(dir string, m TemplatesMarker) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, TemplatesMarkerFile), data, 0o644)
}
