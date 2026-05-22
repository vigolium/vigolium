package api

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
