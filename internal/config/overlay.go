package config

import (
	"fmt"
	"strings"
	"sync"
)

// OverlayEntry is one `--set <dotted.key>=<value>` from the command line.
type OverlayEntry struct {
	Key   string
	Value string
}

// The process overlay is the invocation's `--set` entries. It is process-wide
// because every loader of the effective settings (the CLI, the runner, an
// agent's in-process scan) must see the same values, and the overlay belongs
// to the invocation, not to any one of them. It is set once, by the root
// command, before anything loads settings.
var (
	overlayMu sync.RWMutex
	overlay   []OverlayEntry
)

// ParseOverlay parses `key=value` entries and checks each against a copy of
// the built-in defaults with SetField, the same key and value parsing
// `config set` uses. An unknown key wraps ErrUnknownKey and names it; a value
// the key cannot hold wraps ErrInvalidValue.
func ParseOverlay(raw []string) ([]OverlayEntry, error) {
	out := make([]OverlayEntry, 0, len(raw))
	probe := DefaultSettings()
	for _, r := range raw {
		k, v, ok := strings.Cut(r, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, fmt.Errorf("--set %q: want <dotted.key>=<value>: %w", r, ErrInvalidValue)
		}
		v = strings.TrimSpace(v)
		// The overlay is re-applied after every layer (applyProcessOverlay), so
		// an entry must be idempotent: `.add` would append once per layer.
		if strings.HasSuffix(k, ".add") && SettingPath(k) != k {
			return nil, fmt.Errorf("--set %s: `.add` is not an overlay operation; give the whole list (--set %s=[a,b]): %w",
				k, SettingPath(k), ErrInvalidValue)
		}
		if err := SetField(probe, k, v); err != nil {
			return nil, fmt.Errorf("--set %s: %w", k, err)
		}
		out = append(out, OverlayEntry{Key: k, Value: v})
	}
	return out, nil
}

// SetProcessOverlay installs entries as this invocation's overlay (nil clears
// it).
func SetProcessOverlay(entries []OverlayEntry) {
	overlayMu.Lock()
	defer overlayMu.Unlock()
	overlay = append([]OverlayEntry(nil), entries...)
}

// ProcessOverlay returns the installed overlay entries.
func ProcessOverlay() []OverlayEntry {
	overlayMu.RLock()
	defer overlayMu.RUnlock()
	return append([]OverlayEntry(nil), overlay...)
}

// applyProcessOverlay writes the overlay onto settings in order. Every layer
// that can change settings (the config file, the project overlay, a scanning
// profile) re-applies it last, so an entry outranks each of them as a typed
// flag does.
func applyProcessOverlay(settings *Settings) error {
	if settings == nil {
		return nil
	}
	for _, e := range ProcessOverlay() {
		if err := SetField(settings, e.Key, e.Value); err != nil {
			return fmt.Errorf("--set %s: %w", e.Key, err)
		}
	}
	return nil
}
