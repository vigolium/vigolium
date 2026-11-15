package cli

import (
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/yamlext"
)

// `extensions ls` under -j printed the human table, or — when extensions are
// disabled — a single prose line on stdout with exit 0:
//
//	▼ Extensions not enabled. Enable with: vigolium config set ...
//
// A caller cannot distinguish that from a successful empty catalog without
// string-matching the advice, and "extensions are off" is a state it needs to
// branch on. The machine view reports it as a field.

// extensionView is one extension in the catalog.
//
// The field NAMES deliberately match server.ExtensionInfo, which
// GET /api/extensions has been returning for the same objects: `language` (not
// "format") and `file` (not "path"). Two machine descriptions of one object
// that disagree about their key names is worse than either name alone, and a
// consumer reading both surfaces should not need a translation table. The two
// structs should be hoisted into one shared type; until then, keeping the keys
// identical is what makes that hoist a non-breaking change.
type extensionView struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	Language             string   `json:"language"` // "js" or "yaml"
	Type                 string   `json:"type"`
	Severity             string   `json:"severity,omitempty"`
	Confidence           string   `json:"confidence,omitempty"`
	ScanTypes            []string `json:"scan_types,omitempty"`
	Tags                 []string `json:"tags,omitempty"`
	Scope                string   `json:"scope,omitempty"`
	Description          string   `json:"description,omitempty"`
	ConfirmationCriteria string   `json:"confirmation_criteria,omitempty"`
	File                 string   `json:"file,omitempty"`
}

// emitExtensionsJSON writes the extension catalog.
func emitExtensionsJSON(cmd *cobra.Command, opts *extensionOptions, filter string) error {
	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return err
	}

	extCfg := &settings.DynamicAssessment.Extensions
	enabled := extCfg.Enabled

	views := []extensionView{}
	// Extensions are only LOADED when enabled; reporting an empty catalog with
	// enabled:false is the honest answer rather than implying none are installed.
	if enabled {
		scripts, loadErr := jsext.LoadScripts(extCfg)
		if loadErr != nil {
			return loadErr
		}
		for _, s := range scripts {
			m := s.Metadata
			if !extensionMatchesFilter(m, filter) {
				continue
			}
			if opts.ExtType != "all" && string(m.Type) != opts.ExtType {
				continue
			}
			views = append(views, extensionView{
				ID:                   m.ID,
				Name:                 m.Name,
				Language:             "js",
				Type:                 string(m.Type),
				Severity:             m.Severity,
				Confidence:           m.Confidence,
				ScanTypes:            m.ScanTypes,
				Tags:                 m.Tags,
				Scope:                m.Scope,
				Description:          m.Description,
				ConfirmationCriteria: m.ConfirmationCriteria,
				File:                 config.ContractPath(s.Path),
			})
		}

		defs, _ := yamlext.LoadFromConfig(extCfg)
		for _, d := range defs {
			if !yamlMatchesFilter(d, filter) {
				continue
			}
			if opts.ExtType != "all" && d.Type != opts.ExtType {
				continue
			}
			views = append(views, extensionView{
				ID:                   d.ID,
				Name:                 d.Name,
				Language:             "yaml",
				Type:                 d.Type,
				Severity:             d.Severity,
				Confidence:           d.Confidence,
				ScanTypes:            d.ScanTypes,
				Tags:                 d.Tags,
				Scope:                d.Scope,
				Description:          d.Description,
				ConfirmationCriteria: d.ConfirmationCriteria,
			})
		}
	}

	env := newMachineEnvelope(cmd, "extensions", views, int64(len(views)), 0, len(views))
	// The state that made the prose line necessary, as a field a caller can
	// branch on instead of a sentence it has to match.
	env.With("extensions_enabled", enabled)
	env.With("extension_dir", config.ContractPath(config.ExpandPath(extCfg.ExtensionDir)))
	if len(extCfg.CustomDir) > 0 {
		dirs := make([]string, 0, len(extCfg.CustomDir))
		for _, d := range extCfg.CustomDir {
			dirs = append(dirs, config.ContractPath(config.ExpandPath(d)))
		}
		env.With("custom_dirs", dirs)
	}
	if filter != "" {
		env.With("filter", filter)
	}
	if opts != nil && opts.ExtType != "" && opts.ExtType != "all" {
		env.With("type_filter", opts.ExtType)
	}
	return writeAgentJSON(env)
}
