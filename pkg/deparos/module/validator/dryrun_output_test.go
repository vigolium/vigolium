package validator

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/deparos/config"
)

// dryRunConfig builds a config with a matching module plus a disabled module.
func dryRunConfig(t *testing.T) *config.ModuleConfig {
	t.Helper()
	dir := t.TempDir()
	wl := filepath.Join(dir, "custom.txt")
	require.NoError(t, os.WriteFile(wl, []byte("one\ntwo\nthree\n"), 0o644))

	return &config.ModuleConfig{
		Custom: []config.CustomModuleConfig{
			{
				Name:     "api-module",
				Enabled:  true,
				Priority: 2,
				Patterns: []config.PatternConfig{
					{Type: "path_contains", Value: "api"},
				},
				Actions: config.ActionConfig{
					StopRecursion:     true,
					SkipDefaultLogic:  true,
					BlockTaskPatterns: []string{".*\\.bak$", ".*~$", ".*\\.old$", ".*\\.tmp$"},
					Tasks: []config.TaskActionConfig{
						{
							Wordlist:   config.WordlistShortFiles,
							Extensions: []string{"json", "xml"},
							Priority:   ptrUint8(7),
						},
						{
							Wordlist: config.WordlistCustom,
							File:     wl,
						},
						{
							Wordlist: config.WordlistCustom,
							Inline:   []string{"inline-a", "inline-b"},
						},
						{
							Wordlist: config.WordlistObservedNames,
						},
					},
				},
			},
			{
				Name:     "disabled-module",
				Enabled:  false,
				Priority: 1,
				Patterns: []config.PatternConfig{
					{Type: "path_contains", Value: "api"},
				},
			},
		},
	}
}

func TestDryRun_Errors(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		_, err := DryRun(nil, DryRunOptions{Paths: []string{"/api/"}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nil")
	})

	t.Run("no paths", func(t *testing.T) {
		_, err := DryRun(validModuleConfig(), DryRunOptions{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no test paths")
	})

	t.Run("invalid module pattern type", func(t *testing.T) {
		cfg := &config.ModuleConfig{
			Custom: []config.CustomModuleConfig{
				{
					Name:     "bad",
					Enabled:  true,
					Patterns: []config.PatternConfig{{Type: "bogus", Value: "x"}},
				},
			},
		}
		_, err := DryRun(cfg, DryRunOptions{Paths: []string{"/api/"}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create module")
	})
}

func TestDryRun_Match(t *testing.T) {
	cfg := dryRunConfig(t)
	result, err := DryRun(cfg, DryRunOptions{
		Paths:       []string{"/api/", "/static/"},
		SampleCount: 3,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 2, result.Summary.TotalPaths)
	assert.Equal(t, 1, result.Summary.PathsWithMatches)
	assert.Equal(t, 1, result.Summary.PathsNoMatch)
	assert.Greater(t, int64(result.Duration), int64(0))

	// The matched module triggers => recorded in summary and stop-recursion list.
	assert.Equal(t, []string{"api-module"}, result.Summary.ModulesTriggered)
	assert.Contains(t, result.Summary.StopRecursionAt, "/api/")
	assert.Greater(t, result.Summary.TotalTaskSpecs, 0)
	assert.NotEmpty(t, result.Summary.TasksBySource)

	require.Len(t, result.Paths, 2)

	// Find the matched path result.
	var matched, noMatch *PathResult
	for i := range result.Paths {
		switch result.Paths[i].Path {
		case "/api/":
			matched = &result.Paths[i]
		case "/static/":
			noMatch = &result.Paths[i]
		}
	}
	require.NotNil(t, matched)
	require.NotNil(t, noMatch)

	assert.Empty(t, noMatch.MatchedModules)

	require.Len(t, matched.MatchedModules, 1)
	mm := matched.MatchedModules[0]
	assert.Equal(t, "api-module", mm.Name)
	assert.Equal(t, 2, mm.Priority)
	assert.True(t, mm.StopRecursion)
	assert.True(t, mm.SkipDefaultLogic)
	assert.True(t, matched.StopRecursion)
	assert.True(t, matched.SkipDefault)
	assert.NotEmpty(t, mm.BlockPatterns)
	require.NotEmpty(t, mm.PatternsMatched)
	assert.Equal(t, "path_contains", mm.PatternsMatched[0].Type)
	assert.Equal(t, "api", mm.PatternsMatched[0].Value)

	// 4 tasks: shortfiles(2 ext)+custom-file+custom-inline+observed
	require.Len(t, mm.TasksGenerated, 4)

	// short_files task -> 2 task specs (2 extensions).
	short := findTaskBySource(mm.TasksGenerated, "short_files")
	require.NotNil(t, short)
	assert.Equal(t, 2, short.TaskSpecCount)
	assert.Equal(t, uint8(7), short.Priority)
	assert.ElementsMatch(t, []string{"json", "xml"}, short.Extensions)
	assert.NotEmpty(t, short.SampleURLs)

	// custom inline task carries inline count and sample URLs from inline words.
	custom := findCustomInlineTask(mm.TasksGenerated)
	require.NotNil(t, custom)
	assert.Equal(t, 2, custom.InlineCount)
	assert.Equal(t, uint8(6), custom.Priority) // default priority
	assert.NotEmpty(t, custom.SampleURLs)

	// observed_names task uses placeholder sample URLs.
	observed := findTaskBySource(mm.TasksGenerated, "observed_names")
	require.NotNil(t, observed)
	assert.NotEmpty(t, observed.SampleURLs)

	// Total task specs across the path: 2 + 1 + 1 + 1 = 5.
	assert.Equal(t, 5, matched.TotalTaskSpecs)
}

func TestDryRun_StopProcessing(t *testing.T) {
	// Two enabled modules both match; the higher priority one stops processing
	// via... actually ConfiguredModule never sets StopProcessing, so both match.
	cfg := &config.ModuleConfig{
		Custom: []config.CustomModuleConfig{
			{
				Name:     "first",
				Enabled:  true,
				Priority: 1,
				Patterns: []config.PatternConfig{{Type: "path_contains", Value: "api"}},
			},
			{
				Name:     "second",
				Enabled:  true,
				Priority: 2,
				Patterns: []config.PatternConfig{{Type: "path_contains", Value: "api"}},
			},
		},
	}
	result, err := DryRun(cfg, DryRunOptions{Paths: []string{"/api/v1/"}})
	require.NoError(t, err)
	require.Len(t, result.Paths, 1)
	// Both modules match the path.
	assert.Len(t, result.Paths[0].MatchedModules, 2)
	assert.ElementsMatch(t, []string{"first", "second"}, result.Summary.ModulesTriggered)
}

func TestDryRun_AllWordlistSourcePlaceholders(t *testing.T) {
	// Exercise the placeholder branches in generateSampleURLs for every
	// wordlist source that lacks loaded samples.
	cfg := &config.ModuleConfig{
		Custom: []config.CustomModuleConfig{
			{
				Name:     "all-sources",
				Enabled:  true,
				Patterns: []config.PatternConfig{{Type: "path_contains", Value: "api"}},
				Actions: config.ActionConfig{
					Tasks: []config.TaskActionConfig{
						{Wordlist: config.WordlistObservedNames},
						{Wordlist: config.WordlistObservedPaths},
						{Wordlist: config.WordlistShortFiles},
						{Wordlist: config.WordlistLongFiles},
						{Wordlist: config.WordlistShortDirs},
						{Wordlist: config.WordlistLongDirs},
						{Wordlist: config.WordlistCustom}, // empty -> {custom} placeholder
					},
				},
			},
		},
	}
	result, err := DryRun(cfg, DryRunOptions{Paths: []string{"/api/"}, SampleCount: 2})
	require.NoError(t, err)
	require.Len(t, result.Paths, 1)
	require.Len(t, result.Paths[0].MatchedModules, 1)

	tasks := result.Paths[0].MatchedModules[0].TasksGenerated
	require.Len(t, tasks, 7)
	for _, task := range tasks {
		assert.NotEmpty(t, task.SampleURLs, "source %s should have a placeholder sample URL", task.WordlistSource)
	}
}

func TestDryRun_WordLimitAndExtensionCycling(t *testing.T) {
	// Inline word count (5) exceeds SampleCount (2) to exercise the word-limit
	// branch, with multiple extensions to exercise extension cycling in URLs.
	cfg := &config.ModuleConfig{
		Custom: []config.CustomModuleConfig{
			{
				Name:     "inline-heavy",
				Enabled:  true,
				Patterns: []config.PatternConfig{{Type: "path_contains", Value: "api"}},
				Actions: config.ActionConfig{
					Tasks: []config.TaskActionConfig{
						{
							Wordlist:   config.WordlistCustom,
							Inline:     []string{"w1", "w2", "w3", "w4", "w5"},
							Extensions: []string{"php", "asp"},
						},
					},
				},
			},
		},
	}
	result, err := DryRun(cfg, DryRunOptions{Paths: []string{"/api/"}, SampleCount: 2})
	require.NoError(t, err)
	task := result.Paths[0].MatchedModules[0].TasksGenerated[0]
	// Limited to SampleCount sample URLs.
	assert.Len(t, task.SampleURLs, 2)
	assert.Contains(t, task.SampleURLs[0], "w1.php")
	assert.Contains(t, task.SampleURLs[1], "w2.asp")
}

func TestDryRun_CustomFileSampleURLs(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "custom.txt")
	require.NoError(t, os.WriteFile(wl, []byte("filea\nfileb\n"), 0o644))

	cfg := &config.ModuleConfig{
		Custom: []config.CustomModuleConfig{
			{
				Name:     "custom-file",
				Enabled:  true,
				Patterns: []config.PatternConfig{{Type: "path_contains", Value: "api"}},
				Actions: config.ActionConfig{
					Tasks: []config.TaskActionConfig{
						{Wordlist: config.WordlistCustom, File: wl},
					},
				},
			},
		},
	}
	result, err := DryRun(cfg, DryRunOptions{Paths: []string{"/api/"}})
	require.NoError(t, err)
	task := result.Paths[0].MatchedModules[0].TasksGenerated[0]
	assert.Equal(t, wl, task.CustomFile)
	assert.NotEmpty(t, task.SampleURLs)
	assert.Contains(t, task.SampleURLs[0], "filea")
}

func TestDryRun_ConfigPathLoadsNoSamples(t *testing.T) {
	// loadGlobalConfig is a placeholder that returns (nil, nil); exercise the
	// branch where ConfigPath is set but yields no samples.
	cfg := dryRunConfig(t)
	result, err := DryRun(cfg, DryRunOptions{
		Paths:      []string{"/api/"},
		ConfigPath: "/tmp/whatever-config.yaml",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 1, result.Summary.PathsWithMatches)
}

func TestWriteValidationResult(t *testing.T) {
	cfg := validModuleConfig()
	// add a warning-producing config to exercise the warnings branch
	cfg.Custom = append(cfg.Custom, config.CustomModuleConfig{
		Name:     "warner",
		Patterns: []config.PatternConfig{{Type: "file_glob", Value: "**/*.js"}},
		Actions: config.ActionConfig{
			Tasks: []config.TaskActionConfig{
				{Wordlist: config.WordlistShortFiles, Extensions: []string{".php"}},
			},
		},
	})
	result := ValidateConfig(cfg, ValidateOptions{})

	t.Run("json round-trips", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, WriteValidationResult(&buf, result, FormatJSON))
		var decoded ValidationResult
		jsonRoundTrips(t, &buf, &decoded)
		assert.Equal(t, result.Valid, decoded.Valid)
		assert.Len(t, decoded.Modules, len(result.Modules))
	})

	t.Run("text non-empty", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, WriteValidationResult(&buf, result, FormatText))
		out := buf.String()
		assert.Contains(t, out, "Module Validation")
		assert.Contains(t, out, "Module Summary:")
		assert.Contains(t, out, "Warnings:")
	})

	t.Run("unknown format falls back to text", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, WriteValidationResult(&buf, result, OutputFormat("yaml")))
		assert.Contains(t, buf.String(), "Module Validation")
	})

	t.Run("invalid result renders errors", func(t *testing.T) {
		bad := ValidateConfig(&config.ModuleConfig{
			Custom: []config.CustomModuleConfig{
				{Name: "", Patterns: nil},
			},
		}, ValidateOptions{})
		var buf bytes.Buffer
		require.NoError(t, WriteValidationResult(&buf, bad, FormatText))
		out := buf.String()
		assert.Contains(t, out, "INVALID")
		assert.Contains(t, out, "Errors:")
	})

	t.Run("long module name truncated", func(t *testing.T) {
		longCfg := &config.ModuleConfig{
			Custom: []config.CustomModuleConfig{
				{
					Name:     "this-is-a-really-long-module-name-that-exceeds-the-column-width",
					Patterns: []config.PatternConfig{{Type: "path_contains", Value: "x"}},
				},
			},
		}
		res := ValidateConfig(longCfg, ValidateOptions{})
		var buf bytes.Buffer
		require.NoError(t, WriteValidationResult(&buf, res, FormatText))
		assert.Contains(t, buf.String(), "...")
	})
}

func TestWriteDryRunResult(t *testing.T) {
	cfg := dryRunConfig(t)
	result, err := DryRun(cfg, DryRunOptions{
		Paths:       []string{"/api/", "/static/"},
		SampleCount: 3,
	})
	require.NoError(t, err)

	t.Run("json round-trips", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, WriteDryRunResult(&buf, result, FormatJSON))
		var decoded DryRunResult
		jsonRoundTrips(t, &buf, &decoded)
		assert.Equal(t, result.Summary.TotalPaths, decoded.Summary.TotalPaths)
		assert.Len(t, decoded.Paths, len(result.Paths))
	})

	t.Run("text non-empty", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, WriteDryRunResult(&buf, result, FormatText))
		out := buf.String()
		assert.Contains(t, out, "Dry-Run Simulation")
		assert.Contains(t, out, "MATCHED MODULES")
		assert.Contains(t, out, "No modules matched this path")
		assert.Contains(t, out, "SUMMARY")
		assert.Contains(t, out, "Sample URLs")
		assert.Contains(t, out, "block_task_patterns")
		assert.Contains(t, out, "Would stop recursion")
		assert.Contains(t, out, "Modules triggered")
	})

	t.Run("unknown format falls back to text", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, WriteDryRunResult(&buf, result, OutputFormat("yaml")))
		assert.Contains(t, buf.String(), "Dry-Run Simulation")
	})

	t.Run("few block patterns are not truncated", func(t *testing.T) {
		few := &config.ModuleConfig{
			Custom: []config.CustomModuleConfig{
				{
					Name:     "few-blocks",
					Enabled:  true,
					Patterns: []config.PatternConfig{{Type: "path_contains", Value: "api"}},
					Actions: config.ActionConfig{
						BlockTaskPatterns: []string{".*\\.bak$", ".*~$"},
						Tasks: []config.TaskActionConfig{
							{Wordlist: config.WordlistShortFiles, Extensions: []string{"json"}},
						},
					},
				},
			},
		}
		res, err := DryRun(few, DryRunOptions{Paths: []string{"/api/"}})
		require.NoError(t, err)
		var buf bytes.Buffer
		require.NoError(t, WriteDryRunResult(&buf, res, FormatText))
		out := buf.String()
		assert.Contains(t, out, ".bak")
		// No truncation suffix should appear for only 2 patterns.
		assert.NotContains(t, out, "more]")
	})

	t.Run("module with no tasks and no block patterns", func(t *testing.T) {
		bare := &config.ModuleConfig{
			Custom: []config.CustomModuleConfig{
				{
					Name:     "bare",
					Enabled:  true,
					Patterns: []config.PatternConfig{{Type: "path_contains", Value: "api"}},
				},
			},
		}
		res, err := DryRun(bare, DryRunOptions{Paths: []string{"/api/"}})
		require.NoError(t, err)
		var buf bytes.Buffer
		require.NoError(t, WriteDryRunResult(&buf, res, FormatText))
		out := buf.String()
		assert.Contains(t, out, "(none)")
		assert.Contains(t, out, "stop_recursion: false")
	})
}

func findTaskBySource(tasks []TaskInfo, source string) *TaskInfo {
	for i := range tasks {
		if tasks[i].WordlistSource == source && tasks[i].InlineCount == 0 {
			return &tasks[i]
		}
	}
	return nil
}

func findCustomInlineTask(tasks []TaskInfo) *TaskInfo {
	for i := range tasks {
		if tasks[i].WordlistSource == "custom" && tasks[i].InlineCount > 0 {
			return &tasks[i]
		}
	}
	return nil
}
