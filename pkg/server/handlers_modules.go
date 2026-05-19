package server

import (
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// HandleListModules handles GET /api/modules?search=xss&tag=spring
func (h *Handlers) HandleListModules(c fiber.Ctx) error {
	search := strings.ToLower(c.Query("search"))
	tagFilter := strings.ToLower(c.Query("tag"))

	var result []ModuleInfo

	for _, m := range modules.GetActiveModules() {
		if search != "" && !moduleMatches(m, search) {
			continue
		}
		if tagFilter != "" && !moduleHasTag(m, tagFilter) {
			continue
		}
		result = append(result, buildModuleInfo(m, "active"))
	}

	for _, m := range modules.GetPassiveModules() {
		if search != "" && !moduleMatches(m, search) {
			continue
		}
		if tagFilter != "" && !moduleHasTag(m, tagFilter) {
			continue
		}
		result = append(result, buildModuleInfo(m, "passive"))
	}

	return c.JSON(fiber.Map{
		"modules": result,
		"total":   len(result),
	})
}

func buildModuleInfo(m modules.Module, moduleType string) ModuleInfo {
	tags := m.Tags()
	if tags == nil {
		tags = []string{}
	}
	return ModuleInfo{
		ID:                   m.ID(),
		Name:                 m.Name(),
		Description:          m.Description(),
		ShortDescription:     m.ShortDescription(),
		ConfirmationCriteria: m.ConfirmationCriteria(),
		Severity:             m.Severity().String(),
		Confidence:           m.Confidence().String(),
		ScanScope:            scanScopeNames(m.ScanScopes()),
		Tags:                 tags,
		Type:                 moduleType,
	}
}

// scanScopeNames converts a ScanScope bitmask to a list of human-readable names.
func scanScopeNames(s modkit.ScanScope) []string {
	var names []string
	if s.Has(modkit.ScanScopeInsertionPoint) {
		names = append(names, "PER_INSERTION_POINT")
	}
	if s.Has(modkit.ScanScopeRequest) {
		names = append(names, "PER_REQUEST")
	}
	if s.Has(modkit.ScanScopeHost) {
		names = append(names, "PER_HOST")
	}
	return names
}

func moduleMatches(m modules.Module, search string) bool {
	if strings.Contains(strings.ToLower(m.ID()), search) ||
		strings.Contains(strings.ToLower(m.Name()), search) ||
		strings.Contains(strings.ToLower(m.ShortDescription()), search) {
		return true
	}
	for _, tag := range m.Tags() {
		if strings.Contains(strings.ToLower(tag), search) {
			return true
		}
	}
	return false
}

func moduleHasTag(m modules.Module, tag string) bool {
	for _, t := range m.Tags() {
		if strings.ToLower(t) == tag {
			return true
		}
	}
	return false
}
