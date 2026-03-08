package modules

import "github.com/vigolium/vigolium/pkg/modules/modkit"

// Re-export types from modkit package for convenience.
// Modules should import modkit directly to avoid import cycles.

type ScanScope = modkit.ScanScope

const (
	ScanScopeInsertionPoint = modkit.ScanScopeInsertionPoint
	ScanScopeRequest        = modkit.ScanScopeRequest
	ScanScopeHost           = modkit.ScanScopeHost
)

type InsertionPointTypeSet = modkit.InsertionPointTypeSet

const AllInsertionPointTypes = modkit.AllInsertionPointTypes

var (
	URLParamTypes  = modkit.URLParamTypes
	BodyParamTypes = modkit.BodyParamTypes
	CookieTypes    = modkit.CookieTypes
	HeaderTypes    = modkit.HeaderTypes
	AllParamTypes  = modkit.AllParamTypes
)

var NewInsertionPointTypeSet = modkit.NewInsertionPointTypeSet

type PassiveScanScope = modkit.PassiveScanScope

const (
	PassiveScanScopeRequest  = modkit.PassiveScanScopeRequest
	PassiveScanScopeResponse = modkit.PassiveScanScopeResponse
	PassiveScanScopeBoth     = modkit.PassiveScanScopeBoth
)

// Re-export base types
type BaseModule = modkit.BaseModule
type BaseActiveModule = modkit.BaseActiveModule
type BasePassiveModule = modkit.BasePassiveModule

var NewBaseModule = modkit.NewBaseModule
var NewBaseActiveModule = modkit.NewBaseActiveModule
var NewBasePassiveModule = modkit.NewBasePassiveModule

// Re-export ScanContext
type ScanContext = modkit.ScanContext
