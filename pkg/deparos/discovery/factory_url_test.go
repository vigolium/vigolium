package discovery

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/config"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
)

// =============================================================================
// Factory URL Generation Tests
// These tests verify that Factory creates tasks with correct URL generation
// for both root-level and recursive (nested directory) cases.
// =============================================================================

// factoryTestConfig creates a minimal config for Factory URL tests.
func factoryTestConfig() *config.Config {
	return &config.Config{
		Target: config.TargetConfig{
			StartURL: "http://example.com/",
			Mode:     config.ModeFilesAndDirs,
			Recursion: config.RecursionConfig{
				Enabled:  true,
				MaxDepth: 10,
			},
		},
		Filenames: config.FilenameConfig{
			UseObservedNames: true,
			UseObservedPaths: true,
		},
		Extensions: config.ExtensionConfig{
			TestNoExtension: true,
			TestCustom:      true,
			CustomList:      []string{"php", "asp"},
			TestObserved:    true,
		},
	}
}

// =============================================================================
// CreateObservedNameTasks - Root Level
// =============================================================================

func TestFactory_CreateObservedNameTasks_RootLevel(t *testing.T) {
	cfg := factoryTestConfig()
	factory := NewFactory(cfg)

	observedNames := payload.NewObservedProvider(true)
	observedNames.Add([]byte("admin"))
	observedNames.Add([]byte("config"))
	observedNames.Add([]byte("backup"))

	observedExts := payload.NewObservedProvider(true)

	// Root-level: baseURL = "http://example.com/"
	tasks := factory.CreateObservedNameTasks(
		[]byte("http://example.com/"),
		0,
		observedNames,
		observedExts,
	)

	if len(tasks) == 0 {
		t.Fatal("expected tasks to be created")
	}

	// Test ObservedFilesNoExt task
	noExtTask := findObservedTask(tasks, ObservedFilesNoExt)
	if noExtTask == nil {
		t.Fatal("expected ObservedFilesNoExt task")
	}

	urls := collectURLs(t, noExtTask)
	expectedURLs := []string{
		"http://example.com/admin",
		"http://example.com/config",
		"http://example.com/backup",
	}
	assertURLsContainAll(t, urls, expectedURLs)

	// Test ObservedFilesCustomExt tasks (one per extension: php, asp)
	customExtTasks := findAllObservedTasks(tasks, ObservedFilesCustomExt)
	if len(customExtTasks) != 2 {
		t.Fatalf("expected 2 ObservedFilesCustomExt tasks (one per extension), got %d", len(customExtTasks))
	}

	// Collect URLs from ALL custom ext tasks
	var allCustomExtURLs []string
	for _, task := range customExtTasks {
		allCustomExtURLs = append(allCustomExtURLs, collectURLs(t, task)...)
	}
	expectedURLs = []string{
		"http://example.com/admin.php",
		"http://example.com/admin.asp",
		"http://example.com/config.php",
		"http://example.com/config.asp",
		"http://example.com/backup.php",
		"http://example.com/backup.asp",
	}
	assertURLsContainAll(t, allCustomExtURLs, expectedURLs)
}

func TestFactory_CreateObservedNameTasks_RootLevel_NoTrailingSlash(t *testing.T) {
	cfg := factoryTestConfig()
	factory := NewFactory(cfg)

	observedNames := payload.NewObservedProvider(true)
	observedNames.Add([]byte("admin"))

	observedExts := payload.NewObservedProvider(true)

	// Root-level without trailing slash: baseURL = "http://example.com"
	tasks := factory.CreateObservedNameTasks(
		[]byte("http://example.com"),
		0,
		observedNames,
		observedExts,
	)

	noExtTask := findObservedTask(tasks, ObservedFilesNoExt)
	if noExtTask == nil {
		t.Fatal("expected ObservedFilesNoExt task")
	}

	urls := collectURLs(t, noExtTask)
	expectedURLs := []string{
		"http://example.com/admin",
	}
	assertURLsContainAll(t, urls, expectedURLs)
}

// =============================================================================
// CreateRecursiveDirectoryTasks - Nested Directory Level
// =============================================================================

func TestFactory_CreateRecursiveDirectoryTasks_NestedDirectory(t *testing.T) {
	cfg := factoryTestConfig()
	factory := NewFactory(cfg)

	observedNames := payload.NewObservedProvider(true)
	observedNames.Add([]byte("users"))
	observedNames.Add([]byte("products"))

	observedExts := []string{"json", "xml"}

	observedPaths := payload.NewObservedProvider(true)

	// Recursive: dirPath = "http://example.com/api/v1/"
	tasks := factory.CreateRecursiveDirectoryTasks(
		"http://example.com/api/v1/",
		1,
		observedNames,
		observedExts,
		observedPaths,
		nil, // observedFiles
	)

	if len(tasks) == 0 {
		t.Fatal("expected tasks to be created")
	}

	// Test ObservedFilesNoExt task - should combine scheme://host + path + name
	noExtTask := findObservedTask(tasks, ObservedFilesNoExt)
	if noExtTask == nil {
		t.Fatal("expected ObservedFilesNoExt task")
	}

	urls := collectURLs(t, noExtTask)
	expectedURLs := []string{
		"http://example.com/api/v1/users",
		"http://example.com/api/v1/products",
	}
	assertURLsContainAll(t, urls, expectedURLs)

	// Test ObservedFilesCustomExt tasks (one per extension: php, asp)
	customExtTasks := findAllObservedTasks(tasks, ObservedFilesCustomExt)
	if len(customExtTasks) != 2 {
		t.Fatalf("expected 2 ObservedFilesCustomExt tasks (one per extension), got %d", len(customExtTasks))
	}

	// Collect URLs from ALL custom ext tasks
	var allCustomExtURLs []string
	for _, task := range customExtTasks {
		allCustomExtURLs = append(allCustomExtURLs, collectURLs(t, task)...)
	}
	expectedURLs = []string{
		"http://example.com/api/v1/users.php",
		"http://example.com/api/v1/users.asp",
		"http://example.com/api/v1/products.php",
		"http://example.com/api/v1/products.asp",
	}
	assertURLsContainAll(t, allCustomExtURLs, expectedURLs)

	// Test ObservedFilesObservedExt task for "json"
	jsonTask := findObservedTaskWithExt(tasks, ObservedFilesObservedExt, "json")
	if jsonTask == nil {
		t.Fatal("expected ObservedFilesObservedExt task for json")
	}

	urls = collectURLs(t, jsonTask)
	expectedURLs = []string{
		"http://example.com/api/v1/users.json",
		"http://example.com/api/v1/products.json",
	}
	assertURLsContainAll(t, urls, expectedURLs)
}

func TestFactory_CreateRecursiveDirectoryTasks_DeepNested(t *testing.T) {
	cfg := factoryTestConfig()
	factory := NewFactory(cfg)

	observedNames := payload.NewObservedProvider(true)
	observedNames.Add([]byte("list"))
	observedNames.Add([]byte("detail"))

	observedPaths := payload.NewObservedProvider(true)

	// Deep nested: dirPath = "http://example.com/admin/api/v2/users/"
	tasks := factory.CreateRecursiveDirectoryTasks(
		"http://example.com/admin/api/v2/users/",
		3,
		observedNames,
		nil,
		observedPaths,
		nil, // observedFiles
	)

	noExtTask := findObservedTask(tasks, ObservedFilesNoExt)
	if noExtTask == nil {
		t.Fatal("expected ObservedFilesNoExt task")
	}

	urls := collectURLs(t, noExtTask)
	expectedURLs := []string{
		"http://example.com/admin/api/v2/users/list",
		"http://example.com/admin/api/v2/users/detail",
	}
	assertURLsContainAll(t, urls, expectedURLs)
}

// =============================================================================
// CreateObservedDirectoryTasks - Testing names AS directories
// =============================================================================

func TestFactory_CreateObservedDirectoryTasks_RootLevel(t *testing.T) {
	cfg := factoryTestConfig()
	factory := NewFactory(cfg)

	observedNames := payload.NewObservedProvider(true)
	observedNames.Add([]byte("admin"))
	observedNames.Add([]byte("api"))

	// Root-level: baseURL = scheme://host, dirPath = "/"
	tasks := factory.CreateObservedDirectoryTasks(
		[]byte("http://example.com"),
		"/",
		0,
		observedNames,
	)

	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}

	task, ok := tasks[0].(*ObservedTask)
	require.True(t, ok, "expected *ObservedTask")
	if task.TaskType() != ObservedDirs {
		t.Errorf("expected ObservedDirs task type")
	}

	// ObservedDirs adds trailing slash (directories must end with /)
	urls := collectURLs(t, task)
	expectedURLs := []string{
		"http://example.com/admin/",
		"http://example.com/api/",
	}
	assertURLsContainAll(t, urls, expectedURLs)
}

func TestFactory_CreateObservedDirectoryTasks_NestedLevel(t *testing.T) {
	cfg := factoryTestConfig()
	factory := NewFactory(cfg)

	observedNames := payload.NewObservedProvider(true)
	observedNames.Add([]byte("users"))
	observedNames.Add([]byte("products"))

	// Nested: baseURL = scheme://host, dirPath = "/api/v1/"
	tasks := factory.CreateObservedDirectoryTasks(
		[]byte("http://example.com"),
		"/api/v1/",
		1,
		observedNames,
	)

	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}

	// ObservedDirs adds trailing slash (directories must end with /)
	urls := collectURLs(t, tasks[0])
	expectedURLs := []string{
		"http://example.com/api/v1/users/",
		"http://example.com/api/v1/products/",
	}
	assertURLsContainAll(t, urls, expectedURLs)
}

// =============================================================================
// CreateObservedPathTasks - Full path directories
// =============================================================================

func TestFactory_CreateObservedPathTasks_RootLevel(t *testing.T) {
	cfg := factoryTestConfig()
	factory := NewFactory(cfg)

	observedPaths := payload.NewObservedProvider(true)
	observedPaths.Add([]byte("/api/v1/"))
	observedPaths.Add([]byte("/admin/config/"))
	observedPaths.Add([]byte("/docs/"))

	// Root-level: baseURL = "http://example.com/"
	tasks := factory.CreateObservedPathTasks(
		[]byte("http://example.com/"),
		0,
		observedPaths,
	)

	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}

	task, ok := tasks[0].(*ObservedTask)
	require.True(t, ok, "expected *ObservedTask")
	if task.TaskType() != ObservedPaths {
		t.Errorf("expected ObservedPaths task type")
	}

	// ObservedPaths uses buildPathURL which preserves trailing slashes
	urls := collectURLs(t, task)
	expectedURLs := []string{
		"http://example.com/api/v1/",
		"http://example.com/admin/config/",
		"http://example.com/docs/",
	}
	assertURLsContainAll(t, urls, expectedURLs)
}

// =============================================================================
// CreateRecursiveDirectoryTasks - ObservedPaths with LazyMergedPathProvider
// =============================================================================

func TestFactory_CreateRecursiveDirectoryTasks_ObservedPaths_ChildPaths(t *testing.T) {
	cfg := factoryTestConfig()
	factory := NewFactory(cfg)

	observedNames := payload.NewObservedProvider(true)
	observedNames.Add([]byte("test"))

	observedPaths := payload.NewObservedProvider(true)
	// These paths are children of /api/v1/
	observedPaths.Add([]byte("/api/v1/users/"))
	observedPaths.Add([]byte("/api/v1/products/"))

	// Current directory: /api/v1/
	tasks := factory.CreateRecursiveDirectoryTasks(
		"http://example.com/api/v1/",
		1,
		observedNames,
		nil,
		observedPaths,
		nil, // observedFiles
	)

	// Find the ObservedPaths task
	pathTask := findObservedTask(tasks, ObservedPaths)
	if pathTask == nil {
		t.Fatal("expected ObservedPaths task")
	}

	urls := collectURLs(t, pathTask)
	// Child paths should be returned as full paths
	expectedURLs := []string{
		"http://example.com/api/v1/users/",
		"http://example.com/api/v1/products/",
	}
	assertURLsContainAll(t, urls, expectedURLs)
}

func TestFactory_CreateRecursiveDirectoryTasks_ObservedPaths_OverlapMerge(t *testing.T) {
	cfg := factoryTestConfig()
	factory := NewFactory(cfg)

	observedNames := payload.NewObservedProvider(true)
	observedNames.Add([]byte("test"))

	observedPaths := payload.NewObservedProvider(true)
	// Path with suffix-prefix overlap: /v1/admin/users/ + currentDir=/api/v1/admin/
	observedPaths.Add([]byte("/v1/admin/users/"))

	// Current directory: /api/v1/admin/
	tasks := factory.CreateRecursiveDirectoryTasks(
		"http://example.com/api/v1/admin/",
		1,
		observedNames,
		nil,
		observedPaths,
		nil, // observedFiles
	)

	pathTask := findObservedTask(tasks, ObservedPaths)
	if pathTask == nil {
		t.Fatal("expected ObservedPaths task")
	}

	urls := collectURLs(t, pathTask)
	// Suffix-prefix overlap: /api/v1/admin/ + /v1/admin/users/ → /api/v1/admin/users/
	expectedURLs := []string{
		"http://example.com/api/v1/admin/users/",
	}
	assertURLsContainAll(t, urls, expectedURLs)
}

func TestFactory_CreateRecursiveDirectoryTasks_ObservedPaths_CommonPrefixReturnAsIs(t *testing.T) {
	cfg := factoryTestConfig()
	factory := NewFactory(cfg)

	observedNames := payload.NewObservedProvider(true)
	observedNames.Add([]byte("test"))

	observedPaths := payload.NewObservedProvider(true)
	// Paths sharing common prefix: /api/v2/ shares "api" with /api/v1/
	observedPaths.Add([]byte("/api/v2/"))

	// Current directory: /api/v1/
	tasks := factory.CreateRecursiveDirectoryTasks(
		"http://example.com/api/v1/",
		1,
		observedNames,
		nil,
		observedPaths,
		nil, // observedFiles
	)

	pathTask := findObservedTask(tasks, ObservedPaths)
	if pathTask == nil {
		t.Fatal("expected ObservedPaths task")
	}

	urls := collectURLs(t, pathTask)
	// Paths with common prefix should be returned as-is
	expectedURLs := []string{
		"http://example.com/api/v2/",
	}
	assertURLsContainAll(t, urls, expectedURLs)
}

func TestFactory_CreateRecursiveDirectoryTasks_ObservedPaths_ParentFiltered(t *testing.T) {
	cfg := factoryTestConfig()
	factory := NewFactory(cfg)

	observedNames := payload.NewObservedProvider(true)
	observedNames.Add([]byte("test"))

	observedPaths := payload.NewObservedProvider(true)
	// Parent path: /api/ is parent of /api/v1/
	observedPaths.Add([]byte("/api/"))

	// Current directory: /api/v1/
	tasks := factory.CreateRecursiveDirectoryTasks(
		"http://example.com/api/v1/",
		1,
		observedNames,
		nil,
		observedPaths,
		nil, // observedFiles
	)

	pathTask := findObservedTask(tasks, ObservedPaths)
	if pathTask == nil {
		t.Fatal("expected ObservedPaths task")
	}

	urls := collectURLs(t, pathTask)
	// Parent paths should be filtered (empty result)
	if len(urls) != 0 {
		t.Errorf("expected parent paths to be filtered, got: %v", urls)
	}
}

func TestFactory_CreateRecursiveDirectoryTasks_ObservedPaths_UnrelatedAppended(t *testing.T) {
	cfg := factoryTestConfig()
	factory := NewFactory(cfg)

	observedNames := payload.NewObservedProvider(true)
	observedNames.Add([]byte("test"))

	observedPaths := payload.NewObservedProvider(true)
	// Unrelated path: /other/ has no relationship with /api/v1/
	observedPaths.Add([]byte("/other/"))

	// Current directory: /api/v1/
	tasks := factory.CreateRecursiveDirectoryTasks(
		"http://example.com/api/v1/",
		1,
		observedNames,
		nil,
		observedPaths,
		nil, // observedFiles
	)

	pathTask := findObservedTask(tasks, ObservedPaths)
	if pathTask == nil {
		t.Fatal("expected ObservedPaths task")
	}

	urls := collectURLs(t, pathTask)
	// Unrelated paths should be appended to currentDir
	expectedURLs := []string{
		"http://example.com/api/v1/other/",
	}
	assertURLsContainAll(t, urls, expectedURLs)
}

// =============================================================================
// CreateDynamicExtensionTasks - Extension tasks for all directories
// =============================================================================

func TestFactory_CreateDynamicExtensionTasks_MultipleDirectories(t *testing.T) {
	cfg := factoryTestConfig()
	factory := NewFactory(cfg)

	observedNames := payload.NewObservedProvider(true)
	observedNames.Add([]byte("config"))
	observedNames.Add([]byte("settings"))

	directoryURLs := []string{
		"http://example.com/",
		"http://example.com/api/v1/",
		"http://example.com/admin/",
	}

	tasks := factory.CreateDynamicExtensionTasks(
		"json",
		directoryURLs,
		observedNames,
		1,
	)

	// Should have 3 tasks (one for each directory with ObservedFilesObservedExt)
	observedExtTasks := findAllObservedTasks(tasks, ObservedFilesObservedExt)
	if len(observedExtTasks) != 3 {
		t.Fatalf("expected 3 ObservedFilesObservedExt tasks, got %d", len(observedExtTasks))
	}

	// Verify URLs for each directory
	expectedByDir := map[string][]string{
		"/": {
			"http://example.com/config.json",
			"http://example.com/settings.json",
		},
		"/api/v1/": {
			"http://example.com/api/v1/config.json",
			"http://example.com/api/v1/settings.json",
		},
		"/admin/": {
			"http://example.com/admin/config.json",
			"http://example.com/admin/settings.json",
		},
	}

	for _, task := range observedExtTasks {
		urls := collectURLs(t, task)
		found := false
		for _, expectedURLs := range expectedByDir {
			if urlsMatch(urls, expectedURLs) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("unexpected URLs generated: %v", urls)
		}
	}
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestFactory_EdgeCase_NameWithLeadingSlash(t *testing.T) {
	cfg := factoryTestConfig()
	factory := NewFactory(cfg)

	observedNames := payload.NewObservedProvider(true)
	observedNames.Add([]byte("/admin"))

	observedExts := payload.NewObservedProvider(true)

	tasks := factory.CreateObservedNameTasks(
		[]byte("http://example.com/"),
		0,
		observedNames,
		observedExts,
	)

	noExtTask := findObservedTask(tasks, ObservedFilesNoExt)
	urls := collectURLs(t, noExtTask)
	// Leading slash should be trimmed from name
	expectedURLs := []string{
		"http://example.com/admin",
	}
	assertURLsContainAll(t, urls, expectedURLs)
}

func TestFactory_EdgeCase_NameWithTrailingSlash(t *testing.T) {
	cfg := factoryTestConfig()
	factory := NewFactory(cfg)

	observedNames := payload.NewObservedProvider(true)
	observedNames.Add([]byte("admin/"))

	observedExts := payload.NewObservedProvider(true)

	tasks := factory.CreateObservedNameTasks(
		[]byte("http://example.com/"),
		0,
		observedNames,
		observedExts,
	)

	noExtTask := findObservedTask(tasks, ObservedFilesNoExt)
	urls := collectURLs(t, noExtTask)
	// Trailing slash should be trimmed from name
	expectedURLs := []string{
		"http://example.com/admin",
	}
	assertURLsContainAll(t, urls, expectedURLs)
}

func TestFactory_EdgeCase_BaseURLWithPath(t *testing.T) {
	cfg := factoryTestConfig()
	factory := NewFactory(cfg)

	observedNames := payload.NewObservedProvider(true)
	observedNames.Add([]byte("users"))

	observedExts := payload.NewObservedProvider(true)

	// BaseURL includes path component
	tasks := factory.CreateObservedNameTasks(
		[]byte("http://example.com/api/v1/"),
		0,
		observedNames,
		observedExts,
	)

	noExtTask := findObservedTask(tasks, ObservedFilesNoExt)
	urls := collectURLs(t, noExtTask)
	// Should properly combine scheme://host + path + name
	expectedURLs := []string{
		"http://example.com/api/v1/users",
	}
	assertURLsContainAll(t, urls, expectedURLs)
}

func TestFactory_EdgeCase_EmptyObservedNames(t *testing.T) {
	cfg := factoryTestConfig()
	factory := NewFactory(cfg)

	observedNames := payload.NewObservedProvider(true)
	// No names added

	observedPaths := payload.NewObservedProvider(true)

	tasks := factory.CreateRecursiveDirectoryTasks(
		"http://example.com/api/",
		1,
		observedNames,
		nil,
		observedPaths,
		nil, // observedFiles
	)

	// Should return nil when no observed names
	if len(tasks) != 0 {
		t.Errorf("expected no tasks with empty observed names, got %d", len(tasks))
	}
}

func TestFactory_EdgeCase_SpecialCharactersInName(t *testing.T) {
	cfg := factoryTestConfig()
	factory := NewFactory(cfg)

	observedNames := payload.NewObservedProvider(true)
	observedNames.Add([]byte("config-backup"))
	observedNames.Add([]byte("api_v2"))
	observedNames.Add([]byte("file.bak"))

	observedExts := payload.NewObservedProvider(true)

	tasks := factory.CreateObservedNameTasks(
		[]byte("http://example.com/"),
		0,
		observedNames,
		observedExts,
	)

	noExtTask := findObservedTask(tasks, ObservedFilesNoExt)
	urls := collectURLs(t, noExtTask)
	expectedURLs := []string{
		"http://example.com/config-backup",
		"http://example.com/api_v2",
		"http://example.com/file.bak",
	}
	assertURLsContainAll(t, urls, expectedURLs)
}

// =============================================================================
// Real-world Bug Scenarios
// =============================================================================

func TestFactory_BugScenario_VulnwebURLNesting(t *testing.T) {
	// This test verifies the fix for the URL duplication bug.
	// Before fix: /Mod_Rewrite_Shop/Details/web-camera-a4tech/Mod_Rewrite_Shop/Details/network-attached-storage-dlink/1/
	// After fix: /Mod_Rewrite_Shop/Details/network-attached-storage-dlink/1/ (return as-is, same site structure)

	cfg := factoryTestConfig()
	factory := NewFactory(cfg)

	observedNames := payload.NewObservedProvider(true)
	observedNames.Add([]byte("network-attached-storage-dlink"))

	observedPaths := payload.NewObservedProvider(true)
	// Path with common prefix: shares "Mod_Rewrite_Shop/Details" with currentDir
	observedPaths.Add([]byte("/Mod_Rewrite_Shop/Details/network-attached-storage-dlink/1/"))

	// Current directory: /Mod_Rewrite_Shop/Details/web-camera-a4tech/
	tasks := factory.CreateRecursiveDirectoryTasks(
		"http://testphp.vulnweb.com/Mod_Rewrite_Shop/Details/web-camera-a4tech/",
		2,
		observedNames,
		nil,
		observedPaths,
		nil, // observedFiles
	)

	pathTask := findObservedTask(tasks, ObservedPaths)
	if pathTask == nil {
		t.Fatal("expected ObservedPaths task")
	}

	urls := collectURLs(t, pathTask)
	// Paths with common prefix return as-is (no nesting)
	expectedURLs := []string{
		"http://testphp.vulnweb.com/Mod_Rewrite_Shop/Details/network-attached-storage-dlink/1/",
	}
	assertURLsContainAll(t, urls, expectedURLs)
}

func TestFactory_BugScenario_ParentPathDuplication(t *testing.T) {
	// This test verifies parent paths don't cause infinite recursion

	cfg := factoryTestConfig()
	factory := NewFactory(cfg)

	observedNames := payload.NewObservedProvider(true)
	observedNames.Add([]byte("test"))

	observedPaths := payload.NewObservedProvider(true)
	// Parent paths should be filtered
	observedPaths.Add([]byte("/site/"))
	observedPaths.Add([]byte("/site/hc/"))

	// Current directory: /site/hc/static/
	tasks := factory.CreateRecursiveDirectoryTasks(
		"http://example.com/site/hc/static/",
		2,
		observedNames,
		nil,
		observedPaths,
		nil, // observedFiles
	)

	pathTask := findObservedTask(tasks, ObservedPaths)
	if pathTask == nil {
		t.Fatal("expected ObservedPaths task")
	}

	urls := collectURLs(t, pathTask)
	// Parent paths should be filtered
	if len(urls) != 0 {
		t.Errorf("parent paths should be filtered, got: %v", urls)
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func findObservedTask(tasks []Task, taskType ObservedTaskType) *ObservedTask {
	for _, task := range tasks {
		if ot, ok := task.(*ObservedTask); ok && ot.TaskType() == taskType {
			return ot
		}
	}
	return nil
}

func findObservedTaskWithExt(tasks []Task, taskType ObservedTaskType, ext string) *ObservedTask {
	for _, task := range tasks {
		if ot, ok := task.(*ObservedTask); ok && ot.TaskType() == taskType && ot.Extension() == ext {
			return ot
		}
	}
	return nil
}

func findAllObservedTasks(tasks []Task, taskType ObservedTaskType) []*ObservedTask {
	var result []*ObservedTask
	for _, task := range tasks {
		if ot, ok := task.(*ObservedTask); ok && ot.TaskType() == taskType {
			result = append(result, ot)
		}
	}
	return result
}

func urlsMatch(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// assertURLsContainAll checks that got contains all expected URLs (order-independent).
func assertURLsContainAll(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("got %d URLs, want %d\ngot: %v\nwant: %v", len(got), len(want), got, want)
		return
	}

	// Sort both for comparison
	gotSorted := make([]string, len(got))
	copy(gotSorted, got)
	sort.Strings(gotSorted)

	wantSorted := make([]string, len(want))
	copy(wantSorted, want)
	sort.Strings(wantSorted)

	for i := range wantSorted {
		if gotSorted[i] != wantSorted[i] {
			t.Errorf("URL mismatch after sorting:\ngot:  %v\nwant: %v", gotSorted, wantSorted)
			return
		}
	}
}
