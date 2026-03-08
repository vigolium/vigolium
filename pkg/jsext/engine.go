package jsext

import (
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/yamlext"
	"go.uber.org/zap"
)

// Engine manages JS extension loading and provides module/hook access.
type Engine struct {
	cfg            *config.ExtensionsConfig
	httpClient     *http.Requester
	scripts        []*LoadedScript
	activeModules  []modules.ActiveModule
	passiveModules []modules.PassiveModule
	preHooks       []PreHookExecutor
	postHooks      []PostHookExecutor
}

// NewEngine creates a new JS extension engine and loads all configured scripts.
// engineOpts may be nil when scanner context is not available (e.g., CLI listing).
func NewEngine(cfg *config.ExtensionsConfig, httpClient *http.Requester, engineOpts *EngineOptions) (*Engine, error) {
	if cfg == nil || !cfg.Enabled {
		return &Engine{}, nil
	}

	scripts, err := LoadScripts(cfg)
	if err != nil {
		return nil, err
	}

	// Build base APIOptions from config + engine options
	opts := APIOptions{
		HTTPClient:  httpClient,
		ConfigVars:  cfg.Variables,
		AllowExec:   cfg.AllowExec,
		SandboxDir:  cfg.SandboxDir,
		ExecTimeout: cfg.ExecTimeout(),
	}
	if engineOpts != nil {
		opts.ScopeMatcher = engineOpts.ScopeMatcher
		opts.ScopeConfig = engineOpts.ScopeConfig
		opts.ScanUUID = engineOpts.ScanUUID
		opts.Repository = engineOpts.Repository
		opts.LLMClient = engineOpts.LLMClient
		opts.AgentDefs = engineOpts.AgentDefs
	}

	e := &Engine{
		cfg:        cfg,
		httpClient: httpClient,
		scripts:    scripts,
	}

	for _, script := range scripts {
		// Each script gets its own copy of opts with the script ID set
		scriptOpts := opts
		scriptOpts.ScriptID = script.Metadata.ID

		switch script.Metadata.Type {
		case ScriptTypeActive:
			mod, err := NewJSActiveModule(script, scriptOpts)
			if err != nil {
				zap.L().Warn("Failed to load active JS module",
					zap.String("script", script.Path), zap.Error(err))
				continue
			}
			e.activeModules = append(e.activeModules, mod)
			zap.L().Info("Loaded JS active module",
				zap.String("id", mod.ID()),
				zap.String("path", script.Path))

		case ScriptTypePassive:
			mod, err := NewJSPassiveModule(script, scriptOpts)
			if err != nil {
				zap.L().Warn("Failed to load passive JS module",
					zap.String("script", script.Path), zap.Error(err))
				continue
			}
			e.passiveModules = append(e.passiveModules, mod)
			zap.L().Info("Loaded JS passive module",
				zap.String("id", mod.ID()),
				zap.String("path", script.Path))

		case ScriptTypePreHook:
			hook, err := NewPreHook(script, scriptOpts)
			if err != nil {
				zap.L().Warn("Failed to load pre-hook",
					zap.String("script", script.Path), zap.Error(err))
				continue
			}
			e.preHooks = append(e.preHooks, hook)
			zap.L().Info("Loaded JS pre-hook",
				zap.String("id", script.Metadata.ID),
				zap.String("path", script.Path))

		case ScriptTypePostHook:
			hook, err := NewPostHook(script, scriptOpts)
			if err != nil {
				zap.L().Warn("Failed to load post-hook",
					zap.String("script", script.Path), zap.Error(err))
				continue
			}
			e.postHooks = append(e.postHooks, hook)
			zap.L().Info("Loaded JS post-hook",
				zap.String("id", script.Metadata.ID),
				zap.String("path", script.Path))

		default:
			zap.L().Warn("Unknown script type",
				zap.String("type", string(script.Metadata.Type)),
				zap.String("path", script.Path))
		}
	}

	// Load YAML extensions from the same config
	yamlDefs, yamlErr := yamlext.LoadFromConfig(cfg)
	if yamlErr != nil {
		zap.L().Warn("Error loading YAML extensions", zap.Error(yamlErr))
	}
	for _, def := range yamlDefs {
		// JS escape hatch: if script field is set, wrap as JS and route through JS pipeline
		if def.Script != "" {
			jsScript := buildYAMLJSScript(def)
			jsScriptOpts := opts
			jsScriptOpts.ScriptID = jsScript.Metadata.ID
			switch jsScript.Metadata.Type {
			case ScriptTypeActive:
				mod, modErr := NewJSActiveModule(jsScript, jsScriptOpts)
				if modErr != nil {
					zap.L().Warn("Failed to load YAML+JS active module",
						zap.String("id", def.ID), zap.Error(modErr))
					continue
				}
				e.activeModules = append(e.activeModules, mod)
			case ScriptTypePassive:
				mod, modErr := NewJSPassiveModule(jsScript, jsScriptOpts)
				if modErr != nil {
					zap.L().Warn("Failed to load YAML+JS passive module",
						zap.String("id", def.ID), zap.Error(modErr))
					continue
				}
				e.passiveModules = append(e.passiveModules, mod)
			case ScriptTypePreHook:
				hook, hookErr := NewPreHook(jsScript, jsScriptOpts)
				if hookErr != nil {
					zap.L().Warn("Failed to load YAML+JS pre-hook",
						zap.String("id", def.ID), zap.Error(hookErr))
					continue
				}
				e.preHooks = append(e.preHooks, hook)
			case ScriptTypePostHook:
				hook, hookErr := NewPostHook(jsScript, jsScriptOpts)
				if hookErr != nil {
					zap.L().Warn("Failed to load YAML+JS post-hook",
						zap.String("id", def.ID), zap.Error(hookErr))
					continue
				}
				e.postHooks = append(e.postHooks, hook)
			}
			continue
		}

		switch def.Type {
		case "active":
			mod, modErr := yamlext.NewYAMLActiveModule(def, cfg.Variables, httpClient)
			if modErr != nil {
				zap.L().Warn("Failed to load YAML active module",
					zap.String("id", def.ID), zap.Error(modErr))
				continue
			}
			e.activeModules = append(e.activeModules, mod)
			zap.L().Info("Loaded YAML active module",
				zap.String("id", mod.ID()),
				zap.String("path", def.SourcePath()))

		case "passive":
			mod, modErr := yamlext.NewYAMLPassiveModule(def, cfg.Variables)
			if modErr != nil {
				zap.L().Warn("Failed to load YAML passive module",
					zap.String("id", def.ID), zap.Error(modErr))
				continue
			}
			e.passiveModules = append(e.passiveModules, mod)
			zap.L().Info("Loaded YAML passive module",
				zap.String("id", mod.ID()),
				zap.String("path", def.SourcePath()))

		case "pre_hook":
			e.preHooks = append(e.preHooks, yamlext.NewYAMLPreHook(def, cfg.Variables))
			zap.L().Info("Loaded YAML pre-hook",
				zap.String("id", def.ID),
				zap.String("path", def.SourcePath()))

		case "post_hook":
			e.postHooks = append(e.postHooks, yamlext.NewYAMLPostHook(def, cfg.Variables))
			zap.L().Info("Loaded YAML post-hook",
				zap.String("id", def.ID),
				zap.String("path", def.SourcePath()))

		default:
			zap.L().Warn("Unknown YAML extension type",
				zap.String("type", def.Type),
				zap.String("path", def.SourcePath()))
		}
	}

	return e, nil
}

// buildYAMLJSScript wraps a YAML extension's script field into a LoadedScript
// for processing through the existing JS pipeline.
func buildYAMLJSScript(def *yamlext.ExtensionDef) *LoadedScript {
	// Wrap the script content in a module.exports object
	source := "module.exports = {\n"
	source += "  id: " + jsStringLiteral(def.ID) + ",\n"
	source += "  name: " + jsStringLiteral(def.Name) + ",\n"
	source += "  type: " + jsStringLiteral(def.Type) + ",\n"
	if def.Description != "" {
		source += "  description: " + jsStringLiteral(def.Description) + ",\n"
	}
	if def.Severity != "" {
		source += "  severity: " + jsStringLiteral(def.Severity) + ",\n"
	}
	if def.Scope != "" {
		source += "  scope: " + jsStringLiteral(def.Scope) + ",\n"
	}
	if len(def.ScanTypes) > 0 {
		source += "  scanTypes: ["
		for i, st := range def.ScanTypes {
			if i > 0 {
				source += ", "
			}
			source += jsStringLiteral(st)
		}
		source += "],\n"
	}
	if len(def.Tags) > 0 {
		source += "  tags: ["
		for i, tag := range def.Tags {
			if i > 0 {
				source += ", "
			}
			source += jsStringLiteral(tag)
		}
		source += "],\n"
	}
	source += def.Script + "\n"
	source += "};\n"

	return &LoadedScript{
		Path:   def.SourcePath(),
		Source: source,
		Metadata: ScriptMetadata{
			ID:                   def.ID,
			Name:                 def.Name,
			Type:                 ScriptType(def.Type),
			Description:          def.Description,
			Severity:             def.Severity,
			ScanTypes:            def.ScanTypes,
			Scope:                def.Scope,
			Tags:                 def.Tags,
			ConfirmationCriteria: def.ConfirmationCriteria,
		},
	}
}

func jsStringLiteral(s string) string {
	// Simple JSON-safe string escaping
	result := "\""
	for _, c := range s {
		switch c {
		case '"':
			result += "\\\""
		case '\\':
			result += "\\\\"
		case '\n':
			result += "\\n"
		case '\r':
			result += "\\r"
		case '\t':
			result += "\\t"
		default:
			result += string(c)
		}
	}
	result += "\""
	return result
}

// Scripts returns all loaded scripts.
func (e *Engine) Scripts() []*LoadedScript {
	return e.scripts
}

// ActiveModules returns JS active modules.
func (e *Engine) ActiveModules() []modules.ActiveModule {
	return e.activeModules
}

// PassiveModules returns JS passive modules.
func (e *Engine) PassiveModules() []modules.PassiveModule {
	return e.passiveModules
}

// PreHooks returns pre-hooks (JS and YAML).
func (e *Engine) PreHooks() []PreHookExecutor {
	return e.preHooks
}

// PostHooks returns post-hooks (JS and YAML).
func (e *Engine) PostHooks() []PostHookExecutor {
	return e.postHooks
}
