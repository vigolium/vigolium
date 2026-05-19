package module

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/config"
)

func TestModuleResult_MergeResult(t *testing.T) {
	t.Run("merges nil result", func(t *testing.T) {
		r := &ModuleResult{StopRecursion: true}

		r.MergeResult(nil)

		assert.True(t, r.StopRecursion)
	})

	t.Run("boolean OR for stop flags", func(t *testing.T) {
		tests := []struct {
			name   string
			base   *ModuleResult
			other  *ModuleResult
			expect bool
		}{
			{
				name:   "false || true = true",
				base:   &ModuleResult{StopRecursion: false},
				other:  &ModuleResult{StopRecursion: true},
				expect: true,
			},
			{
				name:   "true || false = true",
				base:   &ModuleResult{StopRecursion: true},
				other:  &ModuleResult{StopRecursion: false},
				expect: true,
			},
			{
				name:   "false || false = false",
				base:   &ModuleResult{StopRecursion: false},
				other:  &ModuleResult{StopRecursion: false},
				expect: false,
			},
			{
				name:   "true || true = true",
				base:   &ModuleResult{StopRecursion: true},
				other:  &ModuleResult{StopRecursion: true},
				expect: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				tt.base.MergeResult(tt.other)
				assert.Equal(t, tt.expect, tt.base.StopRecursion)
			})
		}
	})

	t.Run("all boolean flags use OR", func(t *testing.T) {
		base := &ModuleResult{
			StopRecursion:    false,
			StopProcessing:   false,
			SkipDefaultLogic: true,
		}
		other := &ModuleResult{
			StopRecursion:    true,
			StopProcessing:   true,
			SkipDefaultLogic: false,
		}

		base.MergeResult(other)

		assert.True(t, base.StopRecursion)
		assert.True(t, base.StopProcessing)
		assert.True(t, base.SkipDefaultLogic)
	})

	t.Run("appends tasks from other", func(t *testing.T) {
		base := &ModuleResult{
			Tasks: []TaskSpec{
				{WordlistSource: config.WordlistObservedNames, Priority: 1},
			},
		}
		other := &ModuleResult{
			Tasks: []TaskSpec{
				{WordlistSource: config.WordlistShortFiles, Priority: 5},
				{WordlistSource: config.WordlistLongFiles, Priority: 9},
			},
		}

		base.MergeResult(other)

		assert.Len(t, base.Tasks, 3)
		assert.Equal(t, config.WordlistObservedNames, base.Tasks[0].WordlistSource)
		assert.Equal(t, config.WordlistShortFiles, base.Tasks[1].WordlistSource)
		assert.Equal(t, config.WordlistLongFiles, base.Tasks[2].WordlistSource)
	})

	t.Run("appends block patterns", func(t *testing.T) {
		base := &ModuleResult{
			BlockTaskPatterns: []string{".*/css/.*"},
		}
		other := &ModuleResult{
			BlockTaskPatterns: []string{".*/images/.*", ".*/fonts/.*"},
		}

		base.MergeResult(other)

		assert.Len(t, base.BlockTaskPatterns, 3)
		assert.Contains(t, base.BlockTaskPatterns, ".*/css/.*")
		assert.Contains(t, base.BlockTaskPatterns, ".*/images/.*")
		assert.Contains(t, base.BlockTaskPatterns, ".*/fonts/.*")
	})

	t.Run("takes first queue cleanup", func(t *testing.T) {
		base := &ModuleResult{
			QueueCleanup: &QueueCleanupRequest{
				Pattern: "/admin.*",
				Action:  QueueActionRemoveMatching,
			},
		}
		other := &ModuleResult{
			QueueCleanup: &QueueCleanupRequest{
				Pattern: "/test.*",
				Action:  QueueActionPauseMatching,
			},
		}

		base.MergeResult(other)

		require.NotNil(t, base.QueueCleanup)
		assert.Equal(t, "/admin.*", base.QueueCleanup.Pattern) // First one kept
	})

	t.Run("sets queue cleanup when base is nil", func(t *testing.T) {
		base := &ModuleResult{}
		other := &ModuleResult{
			QueueCleanup: &QueueCleanupRequest{
				Pattern: "/test.*",
				Action:  QueueActionPauseMatching,
			},
		}

		base.MergeResult(other)

		require.NotNil(t, base.QueueCleanup)
		assert.Equal(t, "/test.*", base.QueueCleanup.Pattern)
	})
}

func TestNewStopRecursionResult(t *testing.T) {
	result := NewStopRecursionResult()

	assert.True(t, result.StopRecursion)
	assert.True(t, result.SkipDefaultLogic)
	assert.False(t, result.StopProcessing)
}

func TestNormalizeExtension(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "strips leading dot",
			input:  ".js",
			expect: "js",
		},
		{
			name:   "keeps extension without dot",
			input:  "js",
			expect: "js",
		},
		{
			name:   "handles compound extension",
			input:  ".min.js",
			expect: "min.js",
		},
		{
			name:   "empty string stays empty",
			input:  "",
			expect: "",
		},
		{
			name:   "dot-only becomes empty",
			input:  ".",
			expect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeExtension(tt.input)
			assert.Equal(t, tt.expect, result)
		})
	}
}

func TestNewBlockTaskResult(t *testing.T) {
	result := NewBlockTaskResult(".*/css/.*", ".*/images/.*")

	assert.Len(t, result.BlockTaskPatterns, 2)
	assert.Contains(t, result.BlockTaskPatterns, ".*/css/.*")
	assert.Contains(t, result.BlockTaskPatterns, ".*/images/.*")
}

func TestNewQueueCleanupResult(t *testing.T) {
	t.Run("remove action", func(t *testing.T) {
		result := NewQueueCleanupResult("/admin.*", QueueActionRemoveMatching)

		require.NotNil(t, result.QueueCleanup)
		assert.Equal(t, "/admin.*", result.QueueCleanup.Pattern)
		assert.Equal(t, QueueActionRemoveMatching, result.QueueCleanup.Action)
	})

	t.Run("pause action", func(t *testing.T) {
		result := NewQueueCleanupResult("/test.*", QueueActionPauseMatching)

		require.NotNil(t, result.QueueCleanup)
		assert.Equal(t, QueueActionPauseMatching, result.QueueCleanup.Action)
	})
}

func TestTaskSpec(t *testing.T) {
	t.Run("observed wordlist with extension", func(t *testing.T) {
		spec := TaskSpec{
			WordlistSource: config.WordlistObservedNames,
			Extension:      "js",
			Priority:       1,
		}

		assert.Equal(t, config.WordlistObservedNames, spec.WordlistSource)
		assert.Equal(t, "js", spec.Extension)
		assert.Equal(t, uint8(1), spec.Priority)
	})

	t.Run("custom wordlist with file", func(t *testing.T) {
		spec := TaskSpec{
			WordlistSource: config.WordlistCustom,
			Extension:      "",
			Priority:       6,
			CustomFile:     "/path/to/wordlist.txt",
		}

		assert.Equal(t, config.WordlistCustom, spec.WordlistSource)
		assert.Empty(t, spec.Extension)
		assert.Equal(t, "/path/to/wordlist.txt", spec.CustomFile)
	})

	t.Run("custom wordlist with inline", func(t *testing.T) {
		spec := TaskSpec{
			WordlistSource: config.WordlistCustom,
			Extension:      "sql",
			Priority:       0,
			CustomInline:   []string{"backup", "dump", "db"},
		}

		assert.Equal(t, config.WordlistCustom, spec.WordlistSource)
		assert.Equal(t, []string{"backup", "dump", "db"}, spec.CustomInline)
	})
}
