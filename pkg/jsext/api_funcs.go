package jsext

import (
	"strings"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/jsext/api/parse"
)

// The namespace constants, JSFuncDef, HandlerFactory, APIOptions, and
// APIFunction types live in the leaf package pkg/jsext/api and are re-exported
// from this package via aliases in api_aliases.go.

// ─── Collection ─────────────────────────────────────────────────────────────

// allFuncDefs returns every JS API function definition.
// The returned slice is the single source of truth for both VM registration
// and the documentation catalog.
func allFuncDefs() []JSFuncDef {
	var all []JSFuncDef
	all = append(all, logFuncDefs()...)
	all = append(all, utilsFuncDefs()...)
	all = append(all, parse.FuncDefs()...)
	all = append(all, httpCoreFuncDefs()...)
	all = append(all, httpSessionFuncDefs()...)
	all = append(all, httpAuthTestFuncDefs()...)
	all = append(all, httpSessionPoolFuncDefs()...)
	all = append(all, httpHelperFuncDefs()...)
	all = append(all, httpGraphQLFuncDefs()...)
	all = append(all, httpCacheFuncDefs()...)
	all = append(all, scanFuncDefs()...)
	all = append(all, ingestFuncDefs()...)
	all = append(all, agentFuncDefs()...)
	all = append(all, dbFuncDefs()...)
	all = append(all, oastFuncDefs()...)
	all = append(all, payloadsFuncDefs()...)
	all = append(all, recordFuncDefs()...)
	all = append(all, configFuncDefs()...)
	all = append(all, mcpFuncDefs()...)
	return all
}

// ─── Registration ───────────────────────────────────────────────────────────

// registerFuncs iterates over all JSFuncDefs, creates namespace objects as
// needed, calls each MakeHandler, and registers the resulting function on
// the appropriate namespace object. Namespaces are skipped when their
// required dependencies are not available (see shouldRegisterNS).
func registerFuncs(vm *sobek.Runtime, opts APIOptions, defs []JSFuncDef) {
	nsCache := make(map[string]*sobek.Object)
	nsCache[NsRoot] = vm.Get(NsRoot).ToObject(vm)

	for _, def := range defs {
		if def.MakeHandler == nil {
			continue // metadata-only
		}
		if !shouldRegisterNS(def.Namespace, opts) {
			continue
		}
		obj := getOrCreateNS(vm, nsCache, def.Namespace)
		handler := def.MakeHandler(vm, opts)
		_ = obj.Set(def.Name, handler)
	}
}

// registerFuncsUnchecked is like registerFuncs but skips the namespace
// dependency check. Used in tests to register handlers even when optional
// dependencies (e.g. Repository) are nil.
func registerFuncsUnchecked(vm *sobek.Runtime, opts APIOptions, defs []JSFuncDef) {
	nsCache := make(map[string]*sobek.Object)
	nsCache[NsRoot] = vm.Get(NsRoot).ToObject(vm)

	for _, def := range defs {
		if def.MakeHandler == nil {
			continue
		}
		obj := getOrCreateNS(vm, nsCache, def.Namespace)
		handler := def.MakeHandler(vm, opts)
		_ = obj.Set(def.Name, handler)
	}
}

// shouldRegisterNS returns false when the required dependencies for a
// namespace are not available, matching the conditional logic that was
// previously in SetupAPI.
func shouldRegisterNS(ns string, opts APIOptions) bool {
	switch {
	case ns == NsHTTP || strings.HasPrefix(ns, NsHTTP+"."):
		return opts.HTTPClient != nil
	case ns == NsMCP || strings.HasPrefix(ns, NsMCP+"."):
		return opts.HTTPClient != nil
	case ns == NsIngest || strings.HasPrefix(ns, NsIngest+"."):
		return opts.Repository != nil
	case ns == NsDB || strings.HasPrefix(ns, NsDB+"."):
		return opts.Repository != nil
	case ns == NsAgent || strings.HasPrefix(ns, NsAgent+"."):
		return opts.LLMClient != nil
	case ns == NsOAST || strings.HasPrefix(ns, NsOAST+"."):
		return opts.OASTService != nil
	default:
		return true
	}
}

// getOrCreateNS returns the *sobek.Object for a dot-separated namespace,
// creating intermediate objects as needed.
func getOrCreateNS(vm *sobek.Runtime, cache map[string]*sobek.Object, ns string) *sobek.Object {
	if obj, ok := cache[ns]; ok {
		return obj
	}

	parts := strings.Split(ns, ".")
	parentNS := strings.Join(parts[:len(parts)-1], ".")
	leafName := parts[len(parts)-1]

	parent := getOrCreateNS(vm, cache, parentNS)

	// Reuse existing object if the namespace was already set on the parent.
	if existing := parent.Get(leafName); existing != nil && !sobek.IsUndefined(existing) && !sobek.IsNull(existing) {
		obj := existing.ToObject(vm)
		cache[ns] = obj
		return obj
	}

	obj := vm.NewObject()
	_ = parent.Set(leafName, obj)
	cache[ns] = obj
	return obj
}
