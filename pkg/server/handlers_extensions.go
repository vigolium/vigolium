package server

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/yamlext"
)

// HandleListExtensions handles GET /api/extensions
// Optional query params: ?type=active|passive|pre_hook|post_hook, ?search=<text>
func (h *Handlers) HandleListExtensions(c fiber.Ctx) error {
	if h.settings == nil {
		return c.JSON(fiber.Map{
			"extensions":         []ExtensionInfo{},
			"total":              0,
			"extensions_enabled": false,
		})
	}

	cfg := &h.settings.Audit.Extensions
	typeFilter := c.Query("type")
	search := strings.ToLower(c.Query("search"))

	var result []ExtensionInfo

	scripts, _ := jsext.LoadScripts(cfg)
	for _, script := range scripts {
		info := extensionInfoFromScript(script)
		if !extensionMatchesFilter(info, typeFilter, search) {
			continue
		}
		result = append(result, info)
	}

	defs, _ := yamlext.LoadFromConfig(cfg)
	for _, def := range defs {
		info := extensionInfoFromDef(def)
		if !extensionMatchesFilter(info, typeFilter, search) {
			continue
		}
		result = append(result, info)
	}

	if result == nil {
		result = []ExtensionInfo{}
	}

	return c.JSON(fiber.Map{
		"extensions":         result,
		"total":              len(result),
		"extensions_enabled": cfg.Enabled,
	})
}

// HandleGetExtension handles GET /api/extensions/:name
// Returns full extension metadata plus raw file content.
func (h *Handlers) HandleGetExtension(c fiber.Ctx) error {
	name := c.Params("name")

	if h.settings == nil {
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: ErrExtensionNotFound.Error(),
		})
	}

	cfg := &h.settings.Audit.Extensions

	scripts, _ := jsext.LoadScripts(cfg)
	for _, script := range scripts {
		if filepath.Base(script.Path) == name {
			raw, err := os.ReadFile(script.Path)
			if err != nil {
				raw = []byte(script.Source)
			}
			return c.JSON(ExtensionDetail{
				ExtensionInfo: extensionInfoFromScript(script),
				RawContent:    string(raw),
			})
		}
	}

	defs, _ := yamlext.LoadFromConfig(cfg)
	for _, def := range defs {
		if filepath.Base(def.SourcePath()) == name {
			raw, err := os.ReadFile(def.SourcePath())
			if err != nil {
				raw = []byte{}
			}
			return c.JSON(ExtensionDetail{
				ExtensionInfo: extensionInfoFromDef(def),
				RawContent:    string(raw),
			})
		}
	}

	return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
		Error: ErrExtensionNotFound.Error(),
	})
}

// HandleEditExtension handles PUT /api/extensions/:name
func (h *Handlers) HandleEditExtension(c fiber.Ctx) error {
	name := c.Params("name")
	if !strings.HasSuffix(name, ".js") && !strings.HasSuffix(name, ".vgm.yaml") {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "extension name must end with .js or .vgm.yaml",
		})
	}

	var req ExtensionEditRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid request body",
		})
	}

	if h.settings == nil {
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: ErrExtensionNotFound.Error(),
		})
	}

	cfg := &h.settings.Audit.Extensions

	// Search JS scripts
	scripts, _ := jsext.LoadScripts(cfg)
	for _, script := range scripts {
		if filepath.Base(script.Path) == name {
			if err := os.WriteFile(script.Path, []byte(req.Content), 0644); err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
					Error: "failed to write extension file: " + err.Error(),
				})
			}
			return c.JSON(fiber.Map{
				"message":   "extension updated",
				"file":      script.Path,
				"file_name": name,
			})
		}
	}

	// Search YAML extensions
	defs, _ := yamlext.LoadFromConfig(cfg)
	for _, def := range defs {
		if filepath.Base(def.SourcePath()) == name {
			if err := os.WriteFile(def.SourcePath(), []byte(req.Content), 0644); err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
					Error: "failed to write extension file: " + err.Error(),
				})
			}
			return c.JSON(fiber.Map{
				"message":   "extension updated",
				"file":      def.SourcePath(),
				"file_name": name,
			})
		}
	}

	return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
		Error: ErrExtensionNotFound.Error(),
	})
}

// HandleListExtensionAPI handles GET /api/extensions/docs
// Optional query params: ?search=<text>
func (h *Handlers) HandleListExtensionAPI(c fiber.Ctx) error {
	search := strings.ToLower(c.Query("search"))

	funcs := jsext.APIRegistry()
	var result []ExtensionAPIFunction
	for _, fn := range funcs {
		if search != "" && !apiFunctionMatchesSearch(fn, search) {
			continue
		}
		result = append(result, ExtensionAPIFunction{
			Category:    fn.Category,
			Namespace:   fn.Namespace,
			Name:        fn.Name,
			FullName:    fn.FullName(),
			Signature:   fn.Signature,
			Returns:     fn.Returns,
			Description: fn.Description,
			Example:     fn.Example,
		})
	}

	if result == nil {
		result = []ExtensionAPIFunction{}
	}

	return c.JSON(fiber.Map{
		"functions":  result,
		"total":      len(result),
		"namespaces": jsext.APINamespaces(),
	})
}

func extensionInfoFromScript(script *jsext.LoadedScript) ExtensionInfo {
	return ExtensionInfo{
		ID:                   script.Metadata.ID,
		Name:                 script.Metadata.Name,
		Language:             "js",
		Type:                 string(script.Metadata.Type),
		Severity:             script.Metadata.Severity,
		Confidence:           script.Metadata.Confidence,
		ScanTypes:            script.Metadata.ScanTypes,
		Tags:                 script.Metadata.Tags,
		Scope:                script.Metadata.Scope,
		Description:          script.Metadata.Description,
		ConfirmationCriteria: script.Metadata.ConfirmationCriteria,
		File:                 script.Path,
		FileName:             filepath.Base(script.Path),
	}
}

func extensionInfoFromDef(def *yamlext.ExtensionDef) ExtensionInfo {
	return ExtensionInfo{
		ID:                   def.ID,
		Name:                 def.Name,
		Language:             "yaml",
		Type:                 def.Type,
		Severity:             def.Severity,
		Confidence:           def.Confidence,
		ScanTypes:            def.ScanTypes,
		Tags:                 def.Tags,
		Scope:                def.Scope,
		Description:          def.Description,
		ConfirmationCriteria: def.ConfirmationCriteria,
		File:                 def.SourcePath(),
		FileName:             filepath.Base(def.SourcePath()),
	}
}

func extensionMatchesFilter(info ExtensionInfo, typeFilter, search string) bool {
	if typeFilter != "" && typeFilter != "all" && info.Type != typeFilter {
		return false
	}
	if search != "" {
		lower := strings.ToLower
		if strings.Contains(lower(info.ID), search) ||
			strings.Contains(lower(info.Name), search) ||
			strings.Contains(lower(info.Description), search) {
			return true
		}
		for _, tag := range info.Tags {
			if strings.Contains(lower(tag), search) {
				return true
			}
		}
		return false
	}
	return true
}

func apiFunctionMatchesSearch(fn jsext.APIFunction, search string) bool {
	return strings.Contains(strings.ToLower(fn.Name), search) ||
		strings.Contains(strings.ToLower(fn.Namespace), search) ||
		strings.Contains(strings.ToLower(fn.Description), search)
}
