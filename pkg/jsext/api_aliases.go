package jsext

import "github.com/vigolium/vigolium/pkg/jsext/api"

// The vigolium.* JS API registry types live in the leaf package
// pkg/jsext/api so per-domain function packages (api/parse, …) can share them
// without importing jsext. These aliases preserve the historical jsext.* names
// used throughout this package and by external callers.
type (
	JSFuncDef      = api.JSFuncDef
	HandlerFactory = api.HandlerFactory
	APIOptions     = api.APIOptions
	APIFunction    = api.APIFunction
)

// Namespace constants, re-exported from pkg/jsext/api.
const (
	NsRoot  = api.NsRoot
	NsLog   = api.NsLog
	NsUtils = api.NsUtils
	// NsParse intentionally omitted: the parse domain moved to pkg/jsext/api/parse,
	// which references api.NsParse directly, so jsext no longer needs the alias.
	NsHTTP       = api.NsHTTP
	NsScan       = api.NsScan
	NsIngest     = api.NsIngest
	NsAgent      = api.NsAgent
	NsDB         = api.NsDB
	NsDBRecords  = api.NsDBRecords
	NsDBFindings = api.NsDBFindings
	NsOAST       = api.NsOAST
	NsRecord     = api.NsRecord
	NsConfig     = api.NsConfig
	NsMCP        = api.NsMCP
)
