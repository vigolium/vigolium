package jsext

import (
	"context"
	"testing"

	"github.com/grafana/sobek"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/output"
)

func setupScanTestVM(t *testing.T, opts APIOptions) *sobek.Runtime {
	t.Helper()
	vm := sobek.New()
	vigolium := vm.NewObject()
	_ = vm.Set("vigolium", vigolium)
	registerFuncs(vm, opts, scanFuncDefs())
	return vm
}

func TestListModules(t *testing.T) {
	vm := setupScanTestVM(t, APIOptions{})

	val, err := vm.RunString(`vigolium.scan.listModules()`)
	require.NoError(t, err)

	arr := val.ToObject(vm)
	length := arr.Get("length").ToInteger()
	// Should have at least some modules from the default registry
	assert.Greater(t, length, int64(0))

	// Check first element has expected fields
	first := arr.Get("0").ToObject(vm)
	assert.NotNil(t, first.Get("id"))
	assert.NotNil(t, first.Get("name"))
	assert.NotNil(t, first.Get("type"))
	assert.NotNil(t, first.Get("severity"))
}

func TestIsInScopeNoMatcher(t *testing.T) {
	// No scope matcher = everything in scope
	vm := setupScanTestVM(t, APIOptions{})

	val, err := vm.RunString(`vigolium.scan.isInScope("example.com", "/test")`)
	require.NoError(t, err)
	assert.True(t, val.ToBoolean())
}

func TestIsInScopeWithMatcher(t *testing.T) {
	scopeCfg := config.ScopeConfig{
		Host: config.ScopeRule{
			Include: []string{"*.example.com"},
		},
	}
	matcher := config.NewScopeMatcher(scopeCfg)

	vm := setupScanTestVM(t, APIOptions{ScopeMatcher: matcher})

	// In scope
	val, err := vm.RunString(`vigolium.scan.isInScope("api.example.com", "/test")`)
	require.NoError(t, err)
	assert.True(t, val.ToBoolean())

	// Out of scope
	val, err = vm.RunString(`vigolium.scan.isInScope("evil.com", "/test")`)
	require.NoError(t, err)
	assert.False(t, val.ToBoolean())
}

func TestGetScope(t *testing.T) {
	scopeCfg := config.ScopeConfig{
		Host: config.ScopeRule{
			Include: []string{"*.example.com"},
			Exclude: []string{"admin.example.com"},
		},
	}

	vm := setupScanTestVM(t, APIOptions{ScopeConfig: &scopeCfg})

	val, err := vm.RunString(`JSON.stringify(vigolium.scan.getScope().host)`)
	require.NoError(t, err)
	result := val.String()
	assert.Contains(t, result, "*.example.com")
	assert.Contains(t, result, "admin.example.com")
}

func TestGetScopeNoConfig(t *testing.T) {
	vm := setupScanTestVM(t, APIOptions{})

	val, err := vm.RunString(`JSON.stringify(vigolium.scan.getScope())`)
	require.NoError(t, err)
	assert.Equal(t, "{}", val.String())
}

func TestSetScope(t *testing.T) {
	scopeCfg := config.ScopeConfig{}
	matcher := config.NewScopeMatcher(scopeCfg)

	opts := APIOptions{ScopeMatcher: matcher, ScopeConfig: &scopeCfg}
	vm := setupScanTestVM(t, opts)

	// Before setScope: everything in scope
	val, err := vm.RunString(`vigolium.scan.isInScope("anything.com", "/")`)
	require.NoError(t, err)
	assert.True(t, val.ToBoolean())

	// setScope to restrict
	val, err = vm.RunString(`vigolium.scan.setScope({host: {include: ["*.example.com"]}})`)
	require.NoError(t, err)
	assert.True(t, val.ToBoolean())
}

func TestCreateFindingWithEmitter(t *testing.T) {
	var emitted *output.ResultEvent
	opts := APIOptions{
		ScriptID: "test-ext",
		FindingEmitter: func(re *output.ResultEvent) {
			emitted = re
		},
	}

	vm := setupScanTestVM(t, opts)

	val, err := vm.RunString(`vigolium.scan.createFinding({
		url: "https://example.com/vuln",
		matched: "https://example.com/vuln?id=1",
		name: "Test Finding",
		severity: "high",
		description: "A test vulnerability"
	})`)
	require.NoError(t, err)
	assert.True(t, val.ToBoolean())

	require.NotNil(t, emitted)
	assert.Equal(t, "https://example.com/vuln", emitted.URL)
	assert.Equal(t, "https://example.com/vuln?id=1", emitted.Matched)
	assert.Equal(t, "Test Finding", emitted.Info.Name)
	assert.Equal(t, "A test vulnerability", emitted.Info.Description)
}

func TestCreateFindingNoEmitter(t *testing.T) {
	vm := setupScanTestVM(t, APIOptions{})

	val, err := vm.RunString(`vigolium.scan.createFinding({url: "http://example.com"})`)
	require.NoError(t, err)
	assert.False(t, val.ToBoolean()) // no emitter = returns false
}

func TestGetCurrentScan(t *testing.T) {
	vm := setupScanTestVM(t, APIOptions{ScanUUID: "test-uuid-123"})

	val, err := vm.RunString(`vigolium.scan.getCurrentScan().uuid`)
	require.NoError(t, err)
	assert.Equal(t, "test-uuid-123", val.String())
}

func TestStartNewScanBasic(t *testing.T) {
	repo := newTestRepo(t)
	vm := setupScanTestVM(t, APIOptions{Repository: repo})

	val, err := vm.RunString(`vigolium.scan.startNewScan({
		targets: ["https://example.com/api/v1", "https://example.com/api/v2"],
		modules: ["xss", "sqli"],
		name: "my-scan"
	})`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(2), obj.Get("queued").ToInteger())
	assert.NotEmpty(t, obj.Get("scan_uuid").String())

	errArr := obj.Get("errors").ToObject(vm)
	assert.Equal(t, int64(0), errArr.Get("length").ToInteger())

	// Verify scan record was created
	scans, _, err := repo.ListScans(context.Background(), "", 10, 0)
	require.NoError(t, err)
	require.Len(t, scans, 1)
	assert.Equal(t, "my-scan", scans[0].Name)
	assert.Equal(t, "pending", scans[0].Status)
	assert.Equal(t, "xss,sqli", scans[0].Modules)
	assert.Equal(t, extensionScanSource, scans[0].ScanSource)
}

func TestStartNewScanNoTargets(t *testing.T) {
	repo := newTestRepo(t)
	vm := setupScanTestVM(t, APIOptions{Repository: repo})

	val, err := vm.RunString(`vigolium.scan.startNewScan({targets: []})`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(0), obj.Get("queued").ToInteger())
	assert.Equal(t, "", obj.Get("scan_uuid").String())

	errArr := obj.Get("errors").ToObject(vm)
	assert.Greater(t, errArr.Get("length").ToInteger(), int64(0))
}

func TestStartNewScanNoRepo(t *testing.T) {
	vm := setupScanTestVM(t, APIOptions{})

	val, err := vm.RunString(`vigolium.scan.startNewScan({targets: ["https://example.com"]})`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(0), obj.Get("queued").ToInteger())
	assert.Equal(t, "", obj.Get("scan_uuid").String())

	errArr := obj.Get("errors").ToObject(vm)
	assert.Greater(t, errArr.Get("length").ToInteger(), int64(0))
}

func TestStartNewScanDefaults(t *testing.T) {
	repo := newTestRepo(t)
	vm := setupScanTestVM(t, APIOptions{Repository: repo})

	// Only targets provided — modules and name should use defaults
	val, err := vm.RunString(`vigolium.scan.startNewScan({targets: ["https://example.com/test"]})`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(1), obj.Get("queued").ToInteger())
	assert.NotEmpty(t, obj.Get("scan_uuid").String())

	scans, _, err := repo.ListScans(context.Background(), "", 10, 0)
	require.NoError(t, err)
	require.Len(t, scans, 1)
	assert.Equal(t, "extension-scan", scans[0].Name)
	assert.Equal(t, "all", scans[0].Modules)
}

func TestStartNewScanScopeFiltering(t *testing.T) {
	repo := newTestRepo(t)
	scopeCfg := config.ScopeConfig{
		Host: config.ScopeRule{
			Include: []string{"*.example.com"},
		},
	}
	matcher := config.NewScopeMatcher(scopeCfg)

	vm := setupScanTestVM(t, APIOptions{
		Repository:   repo,
		ScopeMatcher: matcher,
	})

	val, err := vm.RunString(`vigolium.scan.startNewScan({
		targets: ["https://api.example.com/ok", "https://evil.com/bad"]
	})`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(1), obj.Get("queued").ToInteger())

	// evil.com should be in errors as out of scope
	errArr := obj.Get("errors").ToObject(vm)
	assert.Greater(t, errArr.Get("length").ToInteger(), int64(0))
}

func TestStartNewScanNoArgument(t *testing.T) {
	repo := newTestRepo(t)
	vm := setupScanTestVM(t, APIOptions{Repository: repo})

	val, err := vm.RunString(`vigolium.scan.startNewScan()`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(0), obj.Get("queued").ToInteger())

	errArr := obj.Get("errors").ToObject(vm)
	assert.Greater(t, errArr.Get("length").ToInteger(), int64(0))
}

func TestStartNewScanNullArgument(t *testing.T) {
	repo := newTestRepo(t)
	vm := setupScanTestVM(t, APIOptions{Repository: repo})

	val, err := vm.RunString(`vigolium.scan.startNewScan(null)`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(0), obj.Get("queued").ToInteger())
}
