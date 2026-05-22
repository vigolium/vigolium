// Package api holds the shared types for the vigolium.* JavaScript API surface:
// the namespace constants, the JSFuncDef declaration + handler factory, the
// APIOptions dependency bundle, and the APIFunction documentation record.
//
// It is a leaf package: the jsext engine and each per-domain function package
// (api/parse, …) import it, but it imports nothing from jsext. This lets API
// domains live in their own subpackages while sharing one source of truth for
// the registry types.
package api

import "github.com/grafana/sobek"

// Namespace constants for the vigolium.* JS API.
const (
	NsRoot       = "vigolium"
	NsLog        = "vigolium.log"
	NsUtils      = "vigolium.utils"
	NsParse      = "vigolium.parse"
	NsHTTP       = "vigolium.http"
	NsScan       = "vigolium.scan"
	NsIngest     = "vigolium.ingest"
	NsAgent      = "vigolium.agent"
	NsDB         = "vigolium.db"
	NsDBRecords  = "vigolium.db.records"
	NsDBFindings = "vigolium.db.findings"
	NsOAST       = "vigolium.oast"
	NsRecord     = "vigolium.record"
	NsConfig     = "vigolium.config"
	NsMCP        = "vigolium.mcp"
)

// HandlerFactory creates a JS function handler given runtime dependencies.
// It is called once per VM setup, not per invocation.
type HandlerFactory func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value

// JSFuncDef declares a JS API function with metadata and an optional handler factory.
// When MakeHandler is nil, the entry is metadata-only (e.g., dynamic config keys,
// per-request properties like vigolium.record.uuid).
type JSFuncDef struct {
	Namespace   string
	Name        string
	Category    string
	Signature   string
	Returns     string
	Description string
	Example     string
	MakeHandler HandlerFactory // nil for metadata-only entries
}

// FullName returns the fully-qualified function name (e.g. "vigolium.utils.sha256").
func (d JSFuncDef) FullName() string {
	return d.Namespace + "." + d.Name
}
