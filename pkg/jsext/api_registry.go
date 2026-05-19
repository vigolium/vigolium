package jsext

// APIFunction describes a single JS API function for documentation.
type APIFunction struct {
	Category    string // display category, e.g. "Encoding & Decoding"
	Namespace   string // e.g. "vigolium.log"
	Name        string // e.g. "info"
	Signature   string // e.g. ".info(msg: string)"
	Returns     string // e.g. "void"
	Description string // e.g. "Log an informational message."
	Example     string // e.g. `vigolium.log.info("scanning " + ctx.request.url)`
}

// FullName returns the fully-qualified function name (e.g. "vigolium.utils.base64Encode").
func (f APIFunction) FullName() string {
	return f.Namespace + "." + f.Name
}

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
