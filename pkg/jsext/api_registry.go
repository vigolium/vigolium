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

// APINamespaces returns the ordered list of unique namespaces.
func APINamespaces() []string { return apiNamespaces }

var apiNamespaces = []string{
	"vigolium.log",
	"vigolium.utils",
	"vigolium.http",
	"vigolium.scan",
	"vigolium.ingest",
	"vigolium.source",
	"vigolium.db",
	"vigolium.db.records",
	"vigolium.db.findings",
	"vigolium.record",
	"vigolium.config",
}
