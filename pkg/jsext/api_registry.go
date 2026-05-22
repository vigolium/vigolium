package jsext

// APIFunction lives in pkg/jsext/api; it is re-exported here via an alias in
// api_aliases.go.

// APIRegistry returns all registered JS API functions, derived from APICatalog.
func APIRegistry() []APIFunction {
	catalog := APICatalog()
	funcs := make([]APIFunction, len(catalog))
	for i, e := range catalog {
		funcs[i] = e.APIFunction
		funcs[i].Category = e.Category
	}
	return funcs
}

// APINamespaces returns the ordered list of unique namespaces,
// derived from allFuncDefs() to stay in sync automatically.
func APINamespaces() []string {
	defs := allFuncDefs()
	seen := make(map[string]bool)
	var namespaces []string
	for _, d := range defs {
		if d.Namespace != NsRoot && !seen[d.Namespace] {
			seen[d.Namespace] = true
			namespaces = append(namespaces, d.Namespace)
		}
	}
	return namespaces
}
