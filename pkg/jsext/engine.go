package jsext

import (
	"fmt"

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
	failures       []LoadFailure
}

// NewEngine creates a new JS extension engine and loads all configured scripts.
// engineOpts may be nil when scanner context is not available (e.g., CLI listing).
func NewEngine(cfg *config.ExtensionsConfig, httpClient *http.Requester, engineOpts *EngineOptions) (*Engine, error) {
	if cfg == nil || !cfg.Enabled {
		return &Engine{}, nil
	}

	scripts, failures := LoadScriptsReport(cfg)

	// Extension HTTP is scope-checked like module traffic unless
	// extensions.allow_out_of_scope (SAFE-14): every vigolium.http.* path —
	// plain, session, batch — goes through this requester view.
	if engineOpts != nil && engineOpts.ScopeMatcher != nil && !cfg.AllowOutOfScope && httpClient != nil {
		httpClient = httpClient.WithHostFilter(engineOpts.ScopeMatcher.HostInScope)
	}

	// Build base APIOptions from config + engine options
	opts := APIOptions{
		HTTPClient:      httpClient,
		ConfigVars:      cfg.Variables,
		AllowExec:       cfg.AllowExec,
		SandboxDir:      cfg.SandboxDir,
		ExecTimeout:     cfg.ExecTimeout(),
		AllowOutOfScope: cfg.AllowOutOfScope,
	}
	// One extension call is bounded by extensions.limits.timeout (SAFE-14);
	// it used to be a hard-coded 60s whatever the config said.
	SetCallTimeout(cfg.Limits.TimeoutDuration())
	if cfg.Limits.MaxMemoryMB > 0 {
		zap.L().Warn("extensions.limits.max_memory_mb is not enforced (the JS VM has no memory limit); ignoring it",
			zap.Int("max_memory_mb", cfg.Limits.MaxMemoryMB))
	}
	if engineOpts != nil {
		opts.ScopeMatcher = engineOpts.ScopeMatcher
		opts.ScopeConfig = engineOpts.ScopeConfig
		opts.ScanUUID = engineOpts.ScanUUID
		opts.ProjectUUID = engineOpts.ProjectUUID
		opts.Repository = engineOpts.Repository
		opts.LLMClient = engineOpts.LLMClient
		opts.OASTService = engineOpts.OASTService
	}

	e := &Engine{
		cfg:        cfg,
		httpClient: httpClient,
		scripts:    scripts,
		failures:   failures,
	}
	// moduleFailed records a module or hook constructor failure for a script
	// whose metadata did load.
	moduleFailed := func(script *LoadedScript, err error) {
		e.failures = append(e.failures, LoadFailure{
			Path: script.Path, ID: "ext-" + script.Metadata.ID,
			Stage: LoadStageModule, Err: err, Explicit: script.Explicit,
		})
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
				moduleFailed(script, err)
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
				moduleFailed(script, err)
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
				moduleFailed(script, err)
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
				moduleFailed(script, err)
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
			e.failures = append(e.failures, LoadFailure{
				Path: script.Path, ID: "ext-" + script.Metadata.ID, Stage: LoadStageUnknownType,
				Err:      fmt.Errorf("unknown extension type %q (must be active, passive, pre_hook or post_hook)", script.Metadata.Type),
				Explicit: script.Explicit,
			})
		}
	}

	// Load YAML extensions from the same config
	yamlDefs, yamlFailures := yamlext.LoadFromConfigReport(cfg)
	for _, f := range yamlFailures {
		e.failures = append(e.failures, LoadFailure{
			Path: f.Path, Stage: LoadStage(f.Stage), Err: f.Err, Explicit: f.Explicit,
		})
	}
	// yamlFailed records a module constructor failure for a YAML extension.
	yamlFailed := func(def *yamlext.ExtensionDef, err error) {
		e.failures = append(e.failures, LoadFailure{
			Path: def.SourcePath(), ID: "ext-" + def.ID,
			Stage: LoadStageModule, Err: err, Explicit: def.Explicit(),
		})
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
					yamlFailed(def, modErr)
					continue
				}
				e.activeModules = append(e.activeModules, mod)
			case ScriptTypePassive:
				mod, modErr := NewJSPassiveModule(jsScript, jsScriptOpts)
				if modErr != nil {
					zap.L().Warn("Failed to load YAML+JS passive module",
						zap.String("id", def.ID), zap.Error(modErr))
					yamlFailed(def, modErr)
					continue
				}
				e.passiveModules = append(e.passiveModules, mod)
			case ScriptTypePreHook:
				hook, hookErr := NewPreHook(jsScript, jsScriptOpts)
				if hookErr != nil {
					zap.L().Warn("Failed to load YAML+JS pre-hook",
						zap.String("id", def.ID), zap.Error(hookErr))
					yamlFailed(def, hookErr)
					continue
				}
				e.preHooks = append(e.preHooks, hook)
			case ScriptTypePostHook:
				hook, hookErr := NewPostHook(jsScript, jsScriptOpts)
				if hookErr != nil {
					zap.L().Warn("Failed to load YAML+JS post-hook",
						zap.String("id", def.ID), zap.Error(hookErr))
					yamlFailed(def, hookErr)
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
				yamlFailed(def, modErr)
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
				yamlFailed(def, modErr)
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
		Path:     def.SourcePath(),
		Source:   source,
		Explicit: def.Explicit(),
		Metadata: ScriptMetadata{
			ID:                   def.ID,
			Name:                 def.Name,
			Type:                 ScriptType(def.Type),
			Description:          def.Description,
			Severity:             def.Severity,
			ScanTypes:            def.ScanTypes,
			Scope:                def.Scope,
			Tags:                 def.Tags,
			Confidence:           def.Confidence,
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

// Failures lists every extension that did not load: unreadable, failed to
// transpile or compile, threw at top level, had unusable metadata or schema, an
// unknown type, or a module/hook that could not be built. Each is also logged.
func (e *Engine) Failures() []LoadFailure {
	return e.failures
}

// ExplicitFailures is the subset of Failures the user named directly (--ext,
// extensions.custom_dir), which a scan treats as fatal.
func (e *Engine) ExplicitFailures() []LoadFailure {
	var out []LoadFailure
	for _, f := range e.failures {
		if f.Explicit {
			out = append(out, f)
		}
	}
	return out
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
