package modkit

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

func validateModuleID(id string) {
	if id == "" {
		panic("module ID cannot be empty")
	}
	if strings.Contains(id, "_") {
		panic(fmt.Sprintf("invalid module ID %q: must use kebab-case (no underscores)", id))
	}
	if id != strings.ToLower(id) {
		panic(fmt.Sprintf("invalid module ID %q: must be lowercase", id))
	}
}

// DefaultModulePriority is the priority assigned to modules that don't implement
// the Prioritized interface. Lower values = higher priority.
const DefaultModulePriority = 100

// BaseModule provides default implementations for common Module methods.
type BaseModule struct {
	ModuleID           string
	ModuleName         string
	ModuleDescription  string
	ModuleShortDesc    string
	ModuleConfirmation string
	ModuleSeverity     severity.Severity
	ModuleConfidence   severity.Confidence
	ModuleScanTypes    ScanScope
	ModuleTags         []string
}

func NewBaseModule(
	id, name, description, shortDesc, confirmationCriteria string,
	s severity.Severity,
	c severity.Confidence,
	scanTypes ScanScope,
) BaseModule {
	return BaseModule{
		ModuleID:           id,
		ModuleName:         name,
		ModuleDescription:  description,
		ModuleShortDesc:    shortDesc,
		ModuleConfirmation: confirmationCriteria,
		ModuleSeverity:     s,
		ModuleConfidence:   c,
		ModuleScanTypes:    scanTypes,
	}
}

func (b BaseModule) ID() string                      { return b.ModuleID }
func (b BaseModule) Name() string                    { return b.ModuleName }
func (b BaseModule) Description() string             { return b.ModuleDescription }
func (b BaseModule) ShortDescription() string        { return b.ModuleShortDesc }
func (b BaseModule) ConfirmationCriteria() string    { return b.ModuleConfirmation }
func (b BaseModule) Severity() severity.Severity     { return b.ModuleSeverity }
func (b BaseModule) Confidence() severity.Confidence { return b.ModuleConfidence }
func (b BaseModule) ScanScopes() ScanScope           { return b.ModuleScanTypes }
func (b BaseModule) Tags() []string                  { return b.ModuleTags }

// BaseActiveModule provides default implementations for ActiveModule.
type BaseActiveModule struct {
	BaseModule
	AllowedIPTypes InsertionPointTypeSet
}

func NewBaseActiveModule(
	id, name, description, shortDesc, confirmationCriteria string,
	s severity.Severity,
	c severity.Confidence,
	scanTypes ScanScope,
	allowedIPTypes InsertionPointTypeSet,
) BaseActiveModule {
	validateModuleID(id)
	return BaseActiveModule{
		BaseModule:     NewBaseModule(id, name, description, shortDesc, confirmationCriteria, s, c, scanTypes),
		AllowedIPTypes: allowedIPTypes,
	}
}

// IncludesBaseCanProcess returns true to indicate this module's CanProcess includes
// standard base eligibility checks (URL parse, media filter, method filter).
// Modules with fully custom CanProcess should override this to return false.
func (b BaseActiveModule) IncludesBaseCanProcess() bool { return true }

func (b BaseActiveModule) AllowedInsertionPointTypes() InsertionPointTypeSet {
	if b.AllowedIPTypes == 0 {
		return AllInsertionPointTypes
	}
	return b.AllowedIPTypes
}

// CanProcess returns true if this module can process the given request.
// Default: skip media/JS files and OPTIONS, CONNECT, HEAD, TRACE methods.
func (b BaseActiveModule) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}

	urlx, err := ctx.URL()
	if err != nil {
		return false
	}

	// Default: skip media/JS extensions
	if utils.IsMediaAndJSURL(urlx.Path) {
		return false
	}

	// Default: skip OPTIONS, CONNECT, HEAD, TRACE
	method := ctx.Request().Method()
	switch method {
	case "OPTIONS", "CONNECT", "HEAD", "TRACE":
		return false
	}

	return true
}

func (b BaseActiveModule) ScanPerInsertionPoint(
	_ *httpmsg.HttpRequestResponse,
	_ httpmsg.InsertionPoint,
	_ *http.Requester,
	_ *ScanContext,
) ([]*output.ResultEvent, error) {
	panic(fmt.Sprintf("module %q declares ScanScopeInsertionPoint but does not implement ScanPerInsertionPoint", b.ModuleID))
}

func (b BaseActiveModule) ScanPerRequest(
	_ *httpmsg.HttpRequestResponse,
	_ *http.Requester,
	_ *ScanContext,
) ([]*output.ResultEvent, error) {
	panic(fmt.Sprintf("module %q declares ScanScopeRequest but does not implement ScanPerRequest", b.ModuleID))
}

func (b BaseActiveModule) ScanPerHost(
	_ *httpmsg.HttpRequestResponse,
	_ *http.Requester,
	_ *ScanContext,
) ([]*output.ResultEvent, error) {
	panic(fmt.Sprintf("module %q declares ScanScopeHost but does not implement ScanPerHost", b.ModuleID))
}

// BasePassiveModule provides default implementations for PassiveModule.
type BasePassiveModule struct {
	BaseModule
	ModuleScope PassiveScanScope
}

func NewBasePassiveModule(
	id, name, description, shortDesc, confirmationCriteria string,
	s severity.Severity,
	c severity.Confidence,
	scanTypes ScanScope,
	scope PassiveScanScope,
) BasePassiveModule {
	validateModuleID(id)
	return BasePassiveModule{
		BaseModule:  NewBaseModule(id, name, description, shortDesc, confirmationCriteria, s, c, scanTypes),
		ModuleScope: scope,
	}
}

func (b BasePassiveModule) Scope() PassiveScanScope {
	if b.ModuleScope == 0 {
		return PassiveScanScopeBoth
	}
	return b.ModuleScope
}

// CanProcess returns true if this module can process the given request.
// Passive modules process all responses including media files.
// Only checks scope compatibility (request/response availability).
func (b BasePassiveModule) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil {
		return false
	}
	scope := b.Scope()
	if scope.HasRequest() && ctx.Request() == nil {
		return false
	}
	if scope.HasResponse() && ctx.Response() == nil {
		return false
	}
	return true
}

func (b BasePassiveModule) ScanPerRequest(_ *httpmsg.HttpRequestResponse, _ *ScanContext) ([]*output.ResultEvent, error) {
	panic(fmt.Sprintf("module %q declares ScanScopeRequest but does not implement ScanPerRequest", b.ModuleID))
}

func (b BasePassiveModule) ScanPerHost(_ *httpmsg.HttpRequestResponse, _ *ScanContext) ([]*output.ResultEvent, error) {
	panic(fmt.Sprintf("module %q declares ScanScopeHost but does not implement ScanPerHost", b.ModuleID))
}
