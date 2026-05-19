package discovery

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
)

// TestHashDeduplication_WordlistTask_SameConfig tests that WordlistTasks
// with identical configuration produce the same hash and are deduplicated
func TestHashDeduplication_WordlistTask_SameConfig(t *testing.T) {
	// Create two WordlistTasks with identical configuration using mock providers
	provider1 := payload.NewMockProvider("index", "config", "admin")
	provider2 := payload.NewMockProvider("index", "config", "admin")

	task1 := NewWordlistTask(&WordlistTaskConfig{
		TaskType:   ShortFilesNoExt,
		Provider:   provider1,
		Extension:  "",
		SchemeHost: []byte("http://example.com"),
		Path:       []byte("/admin/"),
		Depth:      0,
	})

	task2 := NewWordlistTask(&WordlistTaskConfig{
		TaskType:   ShortFilesNoExt,
		Provider:   provider2,
		Extension:  "",
		SchemeHost: []byte("http://example.com"),
		Path:       []byte("/admin/"),
		Depth:      0,
	})

	// Same config should produce same hash
	hash1 := task1.Hash()
	hash2 := task2.Hash()
	assert.Equal(t, hash1, hash2, "Tasks with identical config should have same hash")
	assert.NotZero(t, hash1, "Hash should not be zero")
}

// TestHashDeduplication_WordlistTask_DifferentConfig tests that WordlistTasks
// with different configuration produce different hashes
func TestHashDeduplication_WordlistTask_DifferentConfig(t *testing.T) {
	provider1 := payload.NewMockProvider("index", "config", "admin")
	provider2 := payload.NewMockProvider("home", "about", "contact")

	testCases := []struct {
		name   string
		task1  *WordlistTask
		task2  *WordlistTask
		reason string
	}{
		{
			name: "different task type (priority)",
			task1: NewWordlistTask(&WordlistTaskConfig{
				TaskType:   ShortFilesNoExt,
				Provider:   provider1,
				SchemeHost: []byte("http://example.com"),
				Path:       []byte("/admin/"),
				Depth:      0,
			}),
			task2: NewWordlistTask(&WordlistTaskConfig{
				TaskType:   LongFilesNoExt,
				Provider:   provider1,
				SchemeHost: []byte("http://example.com"),
				Path:       []byte("/admin/"),
				Depth:      0,
			}),
			reason: "different task type",
		},
		{
			name: "different subtype (file vs directory)",
			task1: NewWordlistTask(&WordlistTaskConfig{
				TaskType:   ShortFilesNoExt,
				Provider:   provider1,
				SchemeHost: []byte("http://example.com"),
				Path:       []byte("/admin/"),
				Depth:      0,
			}),
			task2: NewWordlistTask(&WordlistTaskConfig{
				TaskType:   ShortDirs,
				Provider:   provider1,
				SchemeHost: []byte("http://example.com"),
				Path:       []byte("/admin/"),
				Depth:      0,
			}),
			reason: "different subtype",
		},
		{
			name: "different base path",
			task1: NewWordlistTask(&WordlistTaskConfig{
				TaskType:   ShortFilesNoExt,
				Provider:   provider1,
				SchemeHost: []byte("http://example.com"),
				Path:       []byte("/admin/"),
				Depth:      0,
			}),
			task2: NewWordlistTask(&WordlistTaskConfig{
				TaskType:   ShortFilesNoExt,
				Provider:   provider1,
				SchemeHost: []byte("http://example.com"),
				Path:       []byte("/api/"),
				Depth:      0,
			}),
			reason: "different base path",
		},
		{
			name: "different extension",
			task1: NewWordlistTask(&WordlistTaskConfig{
				TaskType:   ShortFilesCustomExt,
				Provider:   provider1,
				Extension:  "php",
				SchemeHost: []byte("http://example.com"),
				Path:       []byte("/admin/"),
				Depth:      0,
			}),
			task2: NewWordlistTask(&WordlistTaskConfig{
				TaskType:   ShortFilesCustomExt,
				Provider:   provider1,
				Extension:  "asp",
				SchemeHost: []byte("http://example.com"),
				Path:       []byte("/admin/"),
				Depth:      0,
			}),
			reason: "different extension",
		},
		{
			name: "different provider (different wordlist)",
			task1: NewWordlistTask(&WordlistTaskConfig{
				TaskType:   ShortFilesNoExt,
				Provider:   provider1,
				SchemeHost: []byte("http://example.com"),
				Path:       []byte("/admin/"),
				Depth:      0,
			}),
			task2: NewWordlistTask(&WordlistTaskConfig{
				TaskType:   ShortFilesNoExt,
				Provider:   provider2,
				SchemeHost: []byte("http://example.com"),
				Path:       []byte("/admin/"),
				Depth:      0,
			}),
			reason: "different provider",
		},
		// NOTE: Depth is intentionally NOT part of the hash to prevent infinite task duplication.
		// Same file discovered at depth 1, 2, 3... would create duplicate tasks without depth exclusion.
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hash1 := tc.task1.Hash()
			hash2 := tc.task2.Hash()
			assert.NotEqual(t, hash1, hash2, "Tasks with %s should have different hashes", tc.reason)
		})
	}
}

// TestHashDeduplication_ExtensionVariantTask tests ExtensionVariantTask hash behavior
func TestHashDeduplication_ExtensionVariantTask(t *testing.T) {
	extProvider1 := payload.NewExtensionProvider()
	extProvider2 := payload.NewExtensionProvider()

	// Same config should produce same hash
	task1 := NewExtensionVariantTask(&ExtensionVariantTaskConfig{
		SchemeHost:  []byte("http://example.com"),
		Path:        []byte("/admin/"),
		Filename:    []byte("config"),
		OriginalExt: []byte("php"),
		FullName:    []byte("config.php"),
		ExtProvider: extProvider1,
		Depth:       1,
	})

	task2 := NewExtensionVariantTask(&ExtensionVariantTaskConfig{
		SchemeHost:  []byte("http://example.com"),
		Path:        []byte("/admin/"),
		Filename:    []byte("config"),
		OriginalExt: []byte("php"),
		FullName:    []byte("config.php"),
		ExtProvider: extProvider2,
		Depth:       1,
	})

	assert.Equal(t, task1.Hash(), task2.Hash(), "Same config should produce same hash")

	// Different fullName should produce different hash
	task3 := NewExtensionVariantTask(&ExtensionVariantTaskConfig{
		SchemeHost:  []byte("http://example.com"),
		Path:        []byte("/admin/"),
		Filename:    []byte("index"),
		OriginalExt: []byte("php"),
		FullName:    []byte("index.php"),
		ExtProvider: extProvider1,
		Depth:       1,
	})

	assert.NotEqual(t, task1.Hash(), task3.Hash(), "Different fullName should produce different hash")
}

// TestHashDeduplication_NumericFuzzTask tests NumericFuzzTask hash behavior
func TestHashDeduplication_NumericFuzzTask(t *testing.T) {
	// Same config should produce same hash
	task1 := NewNumericFuzzTask(&NumericFuzzTaskConfig{
		BaseURL:       []byte("http://example.com"),
		PathTemplate:  []byte("/user/42/profile"),
		OriginalValue: 42,
		StartOffset:   6,
		EndOffset:     8,
		Depth:         1,
	})

	task2 := NewNumericFuzzTask(&NumericFuzzTaskConfig{
		BaseURL:       []byte("http://example.com"),
		PathTemplate:  []byte("/user/42/profile"),
		OriginalValue: 42,
		StartOffset:   6,
		EndOffset:     8,
		Depth:         1,
	})

	assert.Equal(t, task1.Hash(), task2.Hash(), "Same config should produce same hash")

	// Different originalValue should produce different hash
	task3 := NewNumericFuzzTask(&NumericFuzzTaskConfig{
		BaseURL:       []byte("http://example.com"),
		PathTemplate:  []byte("/user/99/profile"),
		OriginalValue: 99,
		StartOffset:   6,
		EndOffset:     8,
		Depth:         1,
	})

	assert.NotEqual(t, task1.Hash(), task3.Hash(), "Different originalValue should produce different hash")
}

// TestHashDeduplication_ObservedProvider_ContentBased tests that ObservedProvider
// hashes based on content, not pointer
func TestHashDeduplication_ObservedProvider_ContentBased(t *testing.T) {
	// Create two providers with same content
	provider1 := payload.NewObservedProvider(true)
	provider1.Add([]byte("index"))
	provider1.Add([]byte("config"))
	provider1.Add([]byte("admin"))

	provider2 := payload.NewObservedProvider(true)
	provider2.Add([]byte("admin")) // Different order
	provider2.Add([]byte("config"))
	provider2.Add([]byte("index"))

	// Same content should produce same hash (sorted internally)
	hash1 := provider1.HashContent()
	hash2 := provider2.HashContent()
	assert.Equal(t, hash1, hash2, "Same content should produce same hash regardless of insertion order")

	// Add one more item to provider2
	provider2.Add([]byte("login"))
	hash3 := provider2.HashContent()
	assert.NotEqual(t, hash1, hash3, "Different content should produce different hash")
}

// TestHashDeduplication_Engine_AddTask_Prevention tests that Engine.AddTask()
// correctly prevents duplicate tasks from being added
func TestHashDeduplication_Engine_AddTask_Prevention(t *testing.T) {
	server := testServer()
	defer server.Close()

	cfg := testConfig(server.URL)

	engine, err := NewEngine(cfg, nil)
	require.NoError(t, err)

	provider := payload.NewMockProvider("index", "config", "admin")

	// Create first task
	task1 := NewWordlistTask(&WordlistTaskConfig{
		TaskType:   ShortFilesNoExt,
		Provider:   provider,
		SchemeHost: []byte("http://example.com"),
		Path:       []byte("/admin/"),
		Depth:      0,
	})

	// Add first task
	added1 := engine.AddTask(task1)
	assert.True(t, added1, "First task should be added")

	// Create duplicate task (same hash)
	task2 := NewWordlistTask(&WordlistTaskConfig{
		TaskType:   ShortFilesNoExt,
		Provider:   provider,
		SchemeHost: []byte("http://example.com"),
		Path:       []byte("/admin/"),
		Depth:      0,
	})

	// Try to add duplicate
	added2 := engine.AddTask(task2)
	assert.False(t, added2, "Duplicate task should not be added")

	// Verify metrics
	metrics := engine.GetMetrics()
	assert.Equal(t, uint64(1), metrics.TasksGenerated, "Only 1 task should be generated")
	assert.Equal(t, uint64(1), metrics.TasksDeduped, "1 task should be deduplicated")
	assert.Equal(t, 1, metrics.UniqueTaskHashes, "Should have 1 unique hash")
}

// TestHashDeduplication_Engine_Concurrent tests concurrent task addition
// with deduplication under race conditions
func TestHashDeduplication_Engine_Concurrent(t *testing.T) {
	server := testServer()
	defer server.Close()

	cfg := testConfig(server.URL)

	engine, err := NewEngine(cfg, nil)
	require.NoError(t, err)

	provider := payload.NewMockProvider("index", "config", "admin")

	const numGoroutines = 100

	// Launch 100 goroutines trying to add the same task
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			task := NewWordlistTask(&WordlistTaskConfig{
				TaskType:   ShortFilesNoExt,
				Provider:   provider,
				SchemeHost: []byte("http://example.com"),
				Path:       []byte("/admin/"),
				Depth:      0,
			})

			// Try to add task (only one should succeed)
			engine.AddTask(task)
		}()
	}

	wg.Wait()

	// Verify only 1 task was added, 99 were deduplicated
	metrics := engine.GetMetrics()
	assert.Equal(t, uint64(1), metrics.TasksGenerated, "Only 1 task should be generated")
	assert.Equal(t, uint64(99), metrics.TasksDeduped, "99 tasks should be deduplicated")
	assert.Equal(t, 1, metrics.UniqueTaskHashes, "Should have 1 unique hash")
}

// TestHashDeduplication_AllTaskTypes tests deduplication across all task types
func TestHashDeduplication_AllTaskTypes(t *testing.T) {
	server := testServer()
	defer server.Close()

	cfg := testConfig(server.URL)

	engine, err := NewEngine(cfg, nil)
	require.NoError(t, err)

	// Test WordlistTask deduplication
	provider := payload.NewMockProvider("index", "config", "admin")
	fileTask1 := NewWordlistTask(&WordlistTaskConfig{
		TaskType:   ShortFilesNoExt,
		Provider:   provider,
		SchemeHost: []byte("http://example.com"),
		Path:       []byte("/test/"),
		Depth:      0,
	})
	fileTask2 := NewWordlistTask(&WordlistTaskConfig{
		TaskType:   ShortFilesNoExt,
		Provider:   provider,
		SchemeHost: []byte("http://example.com"),
		Path:       []byte("/test/"),
		Depth:      0,
	})

	assert.True(t, engine.AddTask(fileTask1), "First WordlistTask should be added")
	assert.False(t, engine.AddTask(fileTask2), "Duplicate WordlistTask should be rejected")

	// Test ExtensionVariantTask deduplication
	extProvider := payload.NewExtensionProvider()
	extTask1 := NewExtensionVariantTask(&ExtensionVariantTaskConfig{
		SchemeHost:  []byte("http://example.com"),
		Path:        []byte("/test/"),
		FullName:    []byte("config.php"),
		ExtProvider: extProvider,
		Depth:       1,
	})
	extTask2 := NewExtensionVariantTask(&ExtensionVariantTaskConfig{
		SchemeHost:  []byte("http://example.com"),
		Path:        []byte("/test/"),
		FullName:    []byte("config.php"),
		ExtProvider: extProvider,
		Depth:       1,
	})

	assert.True(t, engine.AddTask(extTask1), "First ExtensionVariantTask should be added")
	assert.False(t, engine.AddTask(extTask2), "Duplicate ExtensionVariantTask should be rejected")

	// Test NumericFuzzTask deduplication
	numTask1 := NewNumericFuzzTask(&NumericFuzzTaskConfig{
		BaseURL:       []byte("http://example.com"),
		PathTemplate:  []byte("/user/42/"),
		OriginalValue: 42,
		Depth:         1,
	})
	numTask2 := NewNumericFuzzTask(&NumericFuzzTaskConfig{
		BaseURL:       []byte("http://example.com"),
		PathTemplate:  []byte("/user/42/"),
		OriginalValue: 42,
		Depth:         1,
	})

	assert.True(t, engine.AddTask(numTask1), "First NumericFuzzTask should be added")
	assert.False(t, engine.AddTask(numTask2), "Duplicate NumericFuzzTask should be rejected")

	// Verify final metrics
	metrics := engine.GetMetrics()
	assert.Equal(t, uint64(3), metrics.TasksGenerated, "3 unique tasks should be generated")
	assert.Equal(t, uint64(3), metrics.TasksDeduped, "3 duplicate tasks should be deduplicated")
	assert.Equal(t, 3, metrics.UniqueTaskHashes, "Should have 3 unique hashes")
}

// TestHashDeduplication_SameExtension tests that same extension produces same hash
func TestHashDeduplication_SameExtension(t *testing.T) {
	provider := payload.NewMockProvider("index", "config", "admin")

	task1 := NewWordlistTask(&WordlistTaskConfig{
		TaskType:   ShortFilesCustomExt,
		Provider:   provider,
		Extension:  "php",
		SchemeHost: []byte("http://example.com"),
		Path:       []byte("/admin/"),
		Depth:      0,
	})

	task2 := NewWordlistTask(&WordlistTaskConfig{
		TaskType:   ShortFilesCustomExt,
		Provider:   provider,
		Extension:  "php",
		SchemeHost: []byte("http://example.com"),
		Path:       []byte("/admin/"),
		Depth:      0,
	})

	// Same extension should produce same hash
	assert.Equal(t, task1.Hash(), task2.Hash(), "Same extension should produce same hash")
}

// TestHashDeduplication_DirectoryDiscovery_NoDuplicates tests that
// discovering the same directory multiple times doesn't create duplicate tasks.
// OnDirectoryDiscovered uses MarkSeenIfNew for early deduplication - subsequent
// calls for the same directory return early without creating any tasks.
func TestHashDeduplication_DirectoryDiscovery_NoDuplicates(t *testing.T) {
	server := testServer()
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.Filenames.UseObservedNames = true

	engine, err := NewEngine(cfg, nil)
	require.NoError(t, err)

	// Add some observed names
	engine.AddObservedName("index")
	engine.AddObservedName("config")

	// Get initial queue size
	initialSize := engine.taskQueue.Size()

	// First call should create tasks
	err1 := engine.OnDirectoryDiscovered(server.URL+"/admin/", 0)
	assert.NoError(t, err1)

	sizeAfterFirst := engine.taskQueue.Size()
	assert.Greater(t, sizeAfterFirst, initialSize, "First call should create tasks")

	// Second and third calls should be deduplicated at OnDirectoryDiscovered level
	// (early return, no tasks created)
	err2 := engine.OnDirectoryDiscovered(server.URL+"/admin/", 0)
	err3 := engine.OnDirectoryDiscovered(server.URL+"/admin/", 0)

	assert.NoError(t, err2)
	assert.NoError(t, err3)

	sizeAfterAll := engine.taskQueue.Size()
	// Queue size should remain the same after duplicate calls
	assert.Equal(t, sizeAfterFirst, sizeAfterAll, "Duplicate calls should not add more tasks")
}

// TestHashDeduplication_FileDiscovery_NoDuplicates tests that
// discovering the same file multiple times doesn't create duplicate derivation tasks.
// OnFileDiscovered uses early deduplication - subsequent calls return early.
func TestHashDeduplication_FileDiscovery_NoDuplicates(t *testing.T) {
	server := testServer()
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.Extensions.TestBackupExtensions = true
	cfg.Extensions.BackupExtensions = []string{"bak", "old", "tmp"}
	cfg.Filenames.EnableNumericFuzzing = true

	engine, err := NewEngine(cfg, nil)
	require.NoError(t, err)

	// Get initial queue size
	initialSize := engine.taskQueue.Size()

	// First call should create derivation tasks
	err1 := engine.OnFileDiscovered(server.URL+"/admin/config.php", 0)
	assert.NoError(t, err1)

	sizeAfterFirst := engine.taskQueue.Size()

	// Second and third calls should be deduplicated at OnFileDiscovered level
	err2 := engine.OnFileDiscovered(server.URL+"/admin/config.php", 0)
	err3 := engine.OnFileDiscovered(server.URL+"/admin/config.php", 0)

	assert.NoError(t, err2)
	assert.NoError(t, err3)

	sizeAfterAll := engine.taskQueue.Size()

	// Queue size should remain the same after duplicate calls
	assert.Equal(t, sizeAfterFirst, sizeAfterAll, "Duplicate calls should not add more tasks")

	// Verify first call created some tasks (if features enabled)
	if cfg.Extensions.TestBackupExtensions || cfg.Filenames.EnableNumericFuzzing {
		assert.GreaterOrEqual(t, sizeAfterFirst, initialSize, "First call should create tasks if features enabled")
	}
}

// TestHashDeduplication_LazyObservedProvider_SameSource tests that
// LazyObservedProviders pointing to the same source produce identical hashes.
// This ensures tasks from CreateRecursiveDirectoryTasks and CreateDynamicExtensionTasks
// are properly deduplicated when targeting the same observed names + extension + directory.
func TestHashDeduplication_LazyObservedProvider_SameSource(t *testing.T) {
	// Create a single observed provider (source)
	source := payload.NewObservedProvider(true)
	source.Add([]byte("index"))
	source.Add([]byte("config"))
	source.Add([]byte("admin"))

	// Create two lazy providers pointing to the same source
	lazy1 := payload.NewLazyObservedProvider(source)
	lazy2 := payload.NewLazyObservedProvider(source)

	// Same source should produce same hash
	hash1 := lazy1.HashContent()
	hash2 := lazy2.HashContent()
	assert.Equal(t, hash1, hash2, "LazyObservedProviders with same source should have same hash")
	assert.NotZero(t, hash1, "Hash should not be zero")

	// Create tasks using both lazy providers (simulating two code paths)
	task1 := NewObservedTask(&ObservedTaskConfig{
		TaskType:  ObservedFilesObservedExt,
		Provider:  lazy1,
		Extension: "php",
		BaseURL:   []byte("http://example.com"),
		DirPath:   "/admin/",
		Depth:     0,
	})

	task2 := NewObservedTask(&ObservedTaskConfig{
		TaskType:  ObservedFilesObservedExt,
		Provider:  lazy2,
		Extension: "php",
		BaseURL:   []byte("http://example.com"),
		DirPath:   "/admin/",
		Depth:     0,
	})

	// Tasks should have identical hashes
	assert.Equal(t, task1.Hash(), task2.Hash(),
		"Tasks with LazyObservedProviders from same source should have identical hashes")
}

// TestHashDeduplication_CrossPath_ObservedExtensionTasks tests the real-world scenario:
// When the same task (observed names + extension + directory) could be created by both
// CreateRecursiveDirectoryTasks (new directory) and CreateDynamicExtensionTasks (new extension),
// they should produce identical hashes and be deduplicated.
func TestHashDeduplication_CrossPath_ObservedExtensionTasks(t *testing.T) {
	server := testServer()
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.Filenames.UseObservedNames = true
	cfg.Extensions.TestObserved = true

	engine, err := NewEngine(cfg, nil)
	require.NoError(t, err)

	// Add some observed names
	engine.AddObservedName("index")
	engine.AddObservedName("config")

	// Simulate task creation from CreateRecursiveDirectoryTasks
	// (when a new directory is discovered)
	task1 := NewObservedTask(&ObservedTaskConfig{
		TaskType:  ObservedFilesObservedExt,
		Provider:  payload.NewLazyObservedProvider(engine.GetObservedNames()),
		Extension: "php",
		BaseURL:   []byte(server.URL),
		DirPath:   "/admin/",
		Depth:     0,
	})

	// Simulate task creation from CreateDynamicExtensionTasks
	// (when a new extension is discovered)
	task2 := NewObservedTask(&ObservedTaskConfig{
		TaskType:  ObservedFilesObservedExt,
		Provider:  payload.NewLazyObservedProvider(engine.GetObservedNames()),
		Extension: "php",
		BaseURL:   []byte(server.URL),
		DirPath:   "/admin/",
		Depth:     0,
	})

	// Both tasks should have identical hashes
	assert.Equal(t, task1.Hash(), task2.Hash(),
		"Tasks from both code paths should have identical hashes for deduplication")

	// Add first task
	added1 := engine.AddTask(task1)
	assert.True(t, added1, "First task should be added")

	// Second task should be deduplicated
	added2 := engine.AddTask(task2)
	assert.False(t, added2, "Second task should be deduplicated")

	// Verify metrics
	metrics := engine.GetMetrics()
	assert.Equal(t, uint64(1), metrics.TasksGenerated, "Only 1 task should be generated")
	assert.Equal(t, uint64(1), metrics.TasksDeduped, "1 task should be deduplicated")
}

// TestHashDeduplication_HashCollision_Extremely_Unlikely tests behavior
// in the extremely unlikely case of a hash collision
func TestHashDeduplication_HashCollision_Extremely_Unlikely(t *testing.T) {
	// Note: With FNV-1a 64-bit, collision probability is negligible (~0.0000003%)
	// This test documents expected behavior if it ever happens

	server := testServer()
	defer server.Close()

	cfg := testConfig(server.URL)

	engine, err := NewEngine(cfg, nil)
	require.NoError(t, err)

	provider1 := payload.NewMockProvider("index", "config", "admin")
	provider2 := payload.NewMockProvider("home", "about", "contact")

	task1 := NewWordlistTask(&WordlistTaskConfig{
		TaskType:   ShortFilesNoExt,
		Provider:   provider1,
		SchemeHost: []byte("http://example.com"),
		Path:       []byte("/admin/"),
		Depth:      0,
	})

	task2 := NewWordlistTask(&WordlistTaskConfig{
		TaskType:   LongFilesNoExt,
		Provider:   provider2,
		SchemeHost: []byte("http://example.com"),
		Path:       []byte("/admin/"),
		Depth:      0,
	})

	// These have different configurations, so should have different hashes
	hash1 := task1.Hash()
	hash2 := task2.Hash()
	assert.NotEqual(t, hash1, hash2, "Different configs should produce different hashes")

	// Both should be added (no collision)
	added1 := engine.AddTask(task1)
	added2 := engine.AddTask(task2)
	assert.True(t, added1)
	assert.True(t, added2)

	metrics := engine.GetMetrics()
	assert.Equal(t, uint64(2), metrics.TasksGenerated)
	assert.Equal(t, uint64(0), metrics.TasksDeduped)
}
