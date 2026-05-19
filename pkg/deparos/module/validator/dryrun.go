package validator

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/deparos/config"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/module"
)

// DryRun simulates module matching against test paths.
func DryRun(cfg *config.ModuleConfig, opts DryRunOptions) (*DryRunResult, error) {
	start := time.Now()

	if cfg == nil {
		return nil, fmt.Errorf("module config is nil")
	}

	if len(opts.Paths) == 0 {
		return nil, fmt.Errorf("no test paths provided")
	}

	// Load configured modules
	var modules []*module.ConfiguredModule
	for _, customCfg := range cfg.Custom {
		if !customCfg.Enabled {
			continue
		}
		m, err := module.NewConfiguredModule(customCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create module %q: %w", customCfg.Name, err)
		}
		modules = append(modules, m)
	}

	// Sort modules by priority (lower = first)
	sort.Slice(modules, func(i, j int) bool {
		return modules[i].Priority() < modules[j].Priority()
	})

	// Load wordlist samples if config provided
	var wordlistSamples *WordlistSamples
	if opts.ConfigPath != "" {
		globalCfg, err := loadGlobalConfig(opts.ConfigPath)
		if err == nil && globalCfg != nil {
			wordlistSamples = loadWordlistSamplesFromConfig(&globalCfg.Filenames.Wordlists, opts.SampleCount)
		}
	}

	result := &DryRunResult{
		Paths: make([]PathResult, 0, len(opts.Paths)),
		Summary: DryRunSummary{
			TotalPaths:       len(opts.Paths),
			TasksBySource:    make(map[string]int),
			ModulesTriggered: []string{},
		},
	}

	triggeredModules := make(map[string]bool)

	// Simulate each path
	for _, testPath := range opts.Paths {
		pathResult := simulatePath(cfg, modules, testPath, wordlistSamples, opts.SampleCount)
		result.Paths = append(result.Paths, pathResult)

		// Update summary
		if len(pathResult.MatchedModules) > 0 {
			result.Summary.PathsWithMatches++
		} else {
			result.Summary.PathsNoMatch++
		}

		result.Summary.TotalTaskSpecs += pathResult.TotalTaskSpecs

		if pathResult.StopRecursion {
			result.Summary.StopRecursionAt = append(result.Summary.StopRecursionAt, testPath)
		}

		for _, match := range pathResult.MatchedModules {
			triggeredModules[match.Name] = true
			for _, task := range match.TasksGenerated {
				result.Summary.TasksBySource[task.WordlistSource] += task.TaskSpecCount
			}
		}
	}

	// Collect triggered modules
	for name := range triggeredModules {
		result.Summary.ModulesTriggered = append(result.Summary.ModulesTriggered, name)
	}
	sort.Strings(result.Summary.ModulesTriggered)

	result.Duration = time.Since(start)
	return result, nil
}

// simulatePath simulates module matching for a single path.
func simulatePath(cfg *config.ModuleConfig, modules []*module.ConfiguredModule, testPath string, samples *WordlistSamples, sampleCount int) PathResult {
	result := PathResult{
		Path:           testPath,
		MatchedModules: []ModuleMatch{},
	}

	// Ensure path ends with /
	if !strings.HasSuffix(testPath, "/") {
		testPath += "/"
	}

	for i, mod := range modules {
		// Get the original config for this module
		modCfg := cfg.Custom[findConfigIndex(cfg.Custom, mod.Name())]

		// Check which patterns match
		matchedPatterns := getMatchingPatterns(modCfg.Patterns, testPath)
		if len(matchedPatterns) == 0 {
			continue
		}

		// Simulate OnDirectoryMatch
		ctx := context.Background()
		event := &module.DirectoryEvent{Path: testPath}
		moduleResult, err := mod.OnDirectoryMatch(ctx, event)
		if err != nil || moduleResult == nil {
			continue
		}

		// Build module match
		match := ModuleMatch{
			Name:             mod.Name(),
			Priority:         mod.Priority(),
			PatternsMatched:  matchedPatterns,
			TasksGenerated:   buildTaskInfos(modCfg, testPath, samples, sampleCount),
			BlockPatterns:    moduleResult.BlockTaskPatterns,
			StopRecursion:    moduleResult.StopRecursion,
			SkipDefaultLogic: moduleResult.SkipDefaultLogic,
		}

		// Count task specs
		for _, task := range match.TasksGenerated {
			result.TotalTaskSpecs += task.TaskSpecCount
		}

		result.MatchedModules = append(result.MatchedModules, match)

		// Update path result flags
		result.StopRecursion = result.StopRecursion || moduleResult.StopRecursion
		result.SkipDefault = result.SkipDefault || moduleResult.SkipDefaultLogic

		// Check if module stops processing
		if moduleResult.StopProcessing {
			break
		}

		_ = i // satisfy linter
	}

	return result
}

// findConfigIndex finds the index of a module config by name.
func findConfigIndex(configs []config.CustomModuleConfig, name string) int {
	for i, cfg := range configs {
		if cfg.Name == name {
			return i
		}
	}
	return 0
}

// getMatchingPatterns returns which patterns match the path.
func getMatchingPatterns(patterns []config.PatternConfig, testPath string) []PatternMatch {
	var matches []PatternMatch

	for i, p := range patterns {
		patternType, err := module.ParsePatternType(p.Type)
		if err != nil {
			continue
		}

		pattern := module.Pattern{
			Type:       patternType,
			Value:      p.Value,
			Negated:    p.Negated,
			MatchFiles: p.MatchFiles,
		}
		_ = pattern.Compile()

		if pattern.Matches(testPath) {
			matches = append(matches, PatternMatch{
				Index:   i,
				Type:    p.Type,
				Value:   p.Value,
				Negated: p.Negated,
			})
		}
	}

	return matches
}

// buildTaskInfos builds task info list from module config.
func buildTaskInfos(modCfg config.CustomModuleConfig, basePath string, samples *WordlistSamples, sampleCount int) []TaskInfo {
	var tasks []TaskInfo

	for _, taskCfg := range modCfg.Actions.Tasks {
		// Count task specs (1 per extension, or 1 if no extensions)
		taskSpecCount := len(taskCfg.Extensions)
		if taskSpecCount == 0 {
			taskSpecCount = 1
		}

		// Get priority
		priority := uint8(6)
		if taskCfg.Priority != nil {
			priority = *taskCfg.Priority
		}

		task := TaskInfo{
			WordlistSource: string(taskCfg.Wordlist),
			Extensions:     taskCfg.Extensions,
			Priority:       priority,
			CustomFile:     taskCfg.File,
			InlineCount:    len(taskCfg.Inline),
			TaskSpecCount:  taskSpecCount,
			SampleURLs:     generateSampleURLs(taskCfg, basePath, samples, sampleCount),
		}

		tasks = append(tasks, task)
	}

	return tasks
}

// generateSampleURLs generates sample URLs for a task.
func generateSampleURLs(taskCfg config.TaskActionConfig, basePath string, samples *WordlistSamples, count int) []string {
	if count <= 0 {
		count = 5
	}

	var words []string

	switch taskCfg.Wordlist {
	case config.WordlistObservedNames:
		// Use placeholder
		words = []string{"{name}"}
	case config.WordlistObservedPaths:
		// Use placeholder
		words = []string{"{path}"}
	case config.WordlistShortFiles:
		if samples != nil && len(samples.ShortFiles) > 0 {
			words = samples.ShortFiles
		} else {
			words = []string{"{short_file}"}
		}
	case config.WordlistLongFiles:
		if samples != nil && len(samples.LongFiles) > 0 {
			words = samples.LongFiles
		} else {
			words = []string{"{long_file}"}
		}
	case config.WordlistShortDirs:
		if samples != nil && len(samples.ShortDirs) > 0 {
			words = samples.ShortDirs
		} else {
			words = []string{"{short_dir}"}
		}
	case config.WordlistLongDirs:
		if samples != nil && len(samples.LongDirs) > 0 {
			words = samples.LongDirs
		} else {
			words = []string{"{long_dir}"}
		}
	case config.WordlistCustom:
		if len(taskCfg.Inline) > 0 {
			words = taskCfg.Inline
		} else if taskCfg.File != "" {
			words = LoadSampleLines(taskCfg.File, count)
		}
		if len(words) == 0 {
			words = []string{"{custom}"}
		}
	}

	// Limit words
	if len(words) > count {
		words = words[:count]
	}

	// Generate URLs
	var urls []string
	extensions := taskCfg.Extensions
	if len(extensions) == 0 {
		extensions = []string{""} // No extension
	}

	// Generate one URL per word (up to count)
	for i, word := range words {
		if i >= count {
			break
		}
		ext := extensions[i%len(extensions)]
		url := buildURL(basePath, word, ext)
		urls = append(urls, url)
	}

	return urls
}

// buildURL constructs a URL from base path, word, and extension.
func buildURL(basePath, word, ext string) string {
	// Ensure basePath ends with /
	if !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}

	if ext == "" {
		return path.Join(basePath, word)
	}

	// Normalize extension
	ext = strings.TrimPrefix(ext, ".")
	return path.Join(basePath, word+"."+ext)
}

// loadGlobalConfig loads global config.yaml for wordlist paths.
func loadGlobalConfig(cfgPath string) (*config.Config, error) {
	// For now, return nil - full implementation would load YAML
	// This is a placeholder for when user provides -c flag
	_ = cfgPath
	return nil, nil
}

// loadWordlistSamplesFromConfig loads sample words from wordlist files.
func loadWordlistSamplesFromConfig(cfg *config.WordlistConfig, count int) *WordlistSamples {
	if cfg == nil {
		return nil
	}

	samples := &WordlistSamples{}

	if cfg.ShortFilePath != "" {
		samples.ShortFiles = LoadSampleLines(cfg.ShortFilePath, count)
	}
	if cfg.LongFilePath != "" {
		samples.LongFiles = LoadSampleLines(cfg.LongFilePath, count)
	}
	if cfg.ShortDirPath != "" {
		samples.ShortDirs = LoadSampleLines(cfg.ShortDirPath, count)
	}
	if cfg.LongDirPath != "" {
		samples.LongDirs = LoadSampleLines(cfg.LongDirPath, count)
	}

	return samples
}
