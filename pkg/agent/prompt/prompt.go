package prompt

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/public"
	"gopkg.in/yaml.v3"
)

// templateCacheEntry holds a cached parsed template with its file modification time.
type templateCacheEntry struct {
	tmpl    *agenttypes.PromptTemplate
	modTime time.Time // zero for embedded templates
	path    string    // resolved file path, empty for embedded
}

var (
	TmplCacheMu sync.RWMutex
	TmplCache   = make(map[string]*templateCacheEntry)
)

// ParseFrontmatter splits a markdown file into YAML frontmatter and body.
// The frontmatter is delimited by "---" lines at the top of the file.
func ParseFrontmatter(content string) (frontmatter string, body string, err error) {
	content = strings.TrimSpace(content)
	if !strings.HasPrefix(content, "---") {
		return "", content, nil
	}

	// Find the closing "---"
	rest := content[3:] // skip opening "---"
	idx := strings.Index(rest, "\n---")
	if idx < 0 {
		return "", content, fmt.Errorf("unclosed frontmatter: no closing '---' found")
	}

	frontmatter = strings.TrimSpace(rest[:idx])
	body = strings.TrimSpace(rest[idx+4:]) // skip "\n---"
	return frontmatter, body, nil
}

// ParseTemplate parses a raw template file content into a PromptTemplate.
func ParseTemplate(raw string) (*agenttypes.PromptTemplate, error) {
	fm, body, err := ParseFrontmatter(raw)
	if err != nil {
		return nil, err
	}

	tmpl := &agenttypes.PromptTemplate{}
	if fm != "" {
		if err := yaml.Unmarshal([]byte(fm), tmpl); err != nil {
			return nil, fmt.Errorf("failed to parse template frontmatter: %w", err)
		}
	}
	tmpl.Body = body
	return tmpl, nil
}

// LoadTemplate searches for a template by ID in the following order:
// 1. Config-specified templates_dir
// 2. ~/.vigolium/prompts/
// 3. Embedded prompts.PromptsFS
//
// Results are cached by (templateID, templatesDir). For file-based templates,
// the cache is invalidated when the file's modification time changes.
func LoadTemplate(templateID string, templatesDir string) (*agenttypes.PromptTemplate, error) {
	cacheKey := templateID + "|" + templatesDir

	// Fast path: check cache under read lock
	if cached := getTemplateCacheEntry(cacheKey); cached != nil {
		return cached, nil
	}

	// Slow path: resolve template and populate cache
	filename := templateID + ".md"

	// 1. Config-specified templates dir
	if templatesDir != "" {
		path := filepath.Join(config.ExpandPath(templatesDir), filename)
		if tmpl, mtime, err := loadAndStatTemplate(path); err == nil {
			tmpl.Source = "config"
			putTemplateCacheEntry(cacheKey, tmpl, path, mtime)
			return tmpl, nil
		}
	}

	// 2. ~/.vigolium/prompts/
	home, err := os.UserHomeDir()
	if err == nil {
		path := filepath.Join(home, ".vigolium", "prompts", filename)
		if tmpl, mtime, err := loadAndStatTemplate(path); err == nil {
			tmpl.Source = "user"
			putTemplateCacheEntry(cacheKey, tmpl, path, mtime)
			return tmpl, nil
		}
	}

	// 3. Embedded (search root and subdirectories)
	if data, readErr := ReadEmbeddedTemplate(filename); readErr == nil {
		tmpl, parseErr := ParseTemplate(string(data))
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse embedded template %q: %w", templateID, parseErr)
		}
		tmpl.Source = "embedded"
		putTemplateCacheEntry(cacheKey, tmpl, "", time.Time{})
		return tmpl, nil
	}

	return nil, fmt.Errorf("template %q not found in any search path", templateID)
}

// ResolveTemplatePath returns a display-friendly path for a template ID.
// It checks the same search order as LoadTemplate and returns the resolved path
// (with ~ for home dir) or "(embedded)" if only the built-in copy exists.
func ResolveTemplatePath(templateID string, templatesDir string) string {
	filename := templateID + ".md"

	// 1. Config-specified templates dir
	if templatesDir != "" {
		path := filepath.Join(config.ExpandPath(templatesDir), filename)
		if _, err := os.Stat(path); err == nil {
			return terminal.ShortenHome(path)
		}
	}

	// 2. ~/.vigolium/prompts/ (flat and subdirs)
	home, err := os.UserHomeDir()
	if err == nil {
		baseDir := filepath.Join(home, ".vigolium", "prompts")
		// Check flat
		path := filepath.Join(baseDir, filename)
		if _, err := os.Stat(path); err == nil {
			return "~/.vigolium/prompts/" + filename
		}
		// Check known subdirectories
		for _, sub := range []string{"sast", "analysis", "autopilot", "pipeline", "swarm"} {
			path := filepath.Join(baseDir, sub, filename)
			if _, err := os.Stat(path); err == nil {
				return "~/.vigolium/prompts/" + sub + "/" + filename
			}
		}
	}

	// 3. Embedded — determine which subdir
	subdirs := []string{"sast", "analysis", "autopilot", "pipeline", "swarm"}
	if _, readErr := public.StaticFS.ReadFile("presets/prompts/" + filename); readErr == nil {
		return "(embedded)"
	}
	for _, sub := range subdirs {
		if _, readErr := public.StaticFS.ReadFile("presets/prompts/" + sub + "/" + filename); readErr == nil {
			return "(embedded: " + sub + "/" + filename + ")"
		}
	}

	return ""
}

// loadAndStatTemplate loads a template from a file and returns its modification time.
func loadAndStatTemplate(path string) (*agenttypes.PromptTemplate, time.Time, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	tmpl, err := LoadTemplateFromFile(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	return tmpl, info.ModTime(), nil
}

// getTemplateCacheEntry returns a cached template if it's still valid, or nil.
func getTemplateCacheEntry(key string) *agenttypes.PromptTemplate {
	TmplCacheMu.RLock()
	entry, ok := TmplCache[key]
	TmplCacheMu.RUnlock()
	if !ok {
		return nil
	}

	// Embedded templates never change
	if entry.path == "" {
		return entry.tmpl
	}

	// File-based: check mtime
	info, err := os.Stat(entry.path)
	if err != nil {
		// File gone — invalidate cache
		TmplCacheMu.Lock()
		delete(TmplCache, key)
		TmplCacheMu.Unlock()
		return nil
	}
	if !info.ModTime().Equal(entry.modTime) {
		// File changed — invalidate cache
		TmplCacheMu.Lock()
		delete(TmplCache, key)
		TmplCacheMu.Unlock()
		return nil
	}

	return entry.tmpl
}

// putTemplateCacheEntry stores a parsed template in the cache.
func putTemplateCacheEntry(key string, tmpl *agenttypes.PromptTemplate, path string, modTime time.Time) {
	TmplCacheMu.Lock()
	TmplCache[key] = &templateCacheEntry{
		tmpl:    tmpl,
		modTime: modTime,
		path:    path,
	}
	TmplCacheMu.Unlock()
}

// LoadTemplateFromFile loads a template from an explicit file path.
func LoadTemplateFromFile(path string) (*agenttypes.PromptTemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tmpl, err := ParseTemplate(string(data))
	if err != nil {
		return nil, fmt.Errorf("failed to parse template %s: %w", path, err)
	}
	return tmpl, nil
}

// RenderTemplate renders a prompt template with the given data.
// Missing optional variables are replaced with empty strings.
func RenderTemplate(tmpl *agenttypes.PromptTemplate, data agenttypes.TemplateData) (string, error) {
	t, err := template.New(tmpl.ID).Option("missingkey=zero").Parse(tmpl.Body)
	if err != nil {
		return "", fmt.Errorf("failed to parse template body: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to render template: %w", err)
	}
	return buf.String(), nil
}

// ListTemplates returns all available templates, merging from all sources.
// User templates override embedded ones by ID.
func ListTemplates(templatesDir string) ([]agenttypes.PromptTemplate, error) {
	seen := make(map[string]*agenttypes.PromptTemplate)

	// 1. Embedded templates (lowest priority, recurse subdirectories)
	LoadEmbeddedTemplates("presets/prompts", seen)

	// 2. User templates (~/.vigolium/prompts/)
	home, _ := os.UserHomeDir()
	if home != "" {
		userDir := filepath.Join(home, ".vigolium", "prompts")
		LoadDirTemplates(userDir, "user", seen)
	}

	// 3. Config-specified templates dir (highest priority)
	if templatesDir != "" {
		LoadDirTemplates(config.ExpandPath(templatesDir), "config", seen)
	}

	result := make([]agenttypes.PromptTemplate, 0, len(seen))
	for _, tmpl := range seen {
		result = append(result, *tmpl)
	}
	return result, nil
}

// ReadEmbeddedTemplate searches for a template file in the embedded FS,
// checking the root presets/prompts/ directory and all subdirectories.
func ReadEmbeddedTemplate(filename string) ([]byte, error) {
	// Try root first
	if data, err := public.StaticFS.ReadFile("presets/prompts/" + filename); err == nil {
		return data, nil
	}
	// Search subdirectories
	subdirs := []string{"sast", "analysis", "autopilot", "pipeline", "swarm"}
	for _, sub := range subdirs {
		if data, err := public.StaticFS.ReadFile("presets/prompts/" + sub + "/" + filename); err == nil {
			return data, nil
		}
	}
	return nil, fmt.Errorf("embedded template %q not found", filename)
}

// LoadEmbeddedTemplates recursively loads all .md templates from the embedded FS directory.
func LoadEmbeddedTemplates(dir string, seen map[string]*agenttypes.PromptTemplate) {
	entries, err := public.StaticFS.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			LoadEmbeddedTemplates(dir+"/"+entry.Name(), seen)
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		data, err := public.StaticFS.ReadFile(dir + "/" + entry.Name())
		if err != nil {
			continue
		}
		tmpl, err := ParseTemplate(string(data))
		if err != nil {
			continue
		}
		tmpl.Source = "embedded"
		if tmpl.ID != "" {
			seen[tmpl.ID] = tmpl
		}
	}
}

// LoadDirTemplates loads all .md templates from a directory into the seen map.
func LoadDirTemplates(dir string, source string, seen map[string]*agenttypes.PromptTemplate) {
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".md") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		tmpl, err := ParseTemplate(string(data))
		if err != nil {
			return nil
		}
		tmpl.Source = source
		if tmpl.ID != "" {
			seen[tmpl.ID] = tmpl
		}
		return nil
	})
}
