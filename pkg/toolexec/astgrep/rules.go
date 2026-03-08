package astgrep

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/public"
)

// SupportedFrameworks lists all frameworks with embedded rules.
var SupportedFrameworks = []string{"gin", "nextjs", "fastapi", "express", "django", "flask", "gohttp"}

// AvailableFrameworks returns the list of supported frameworks.
func AvailableFrameworks() []string {
	return SupportedFrameworks
}

// ExtractRules extracts embedded rules for a framework to a temporary directory.
// If destDir is empty, a temp directory is created.
// Returns the path to the directory containing the YAML rule files.
func ExtractRules(framework, destDir string) (string, error) {
	framework = strings.ToLower(framework)

	// Validate framework
	valid := false
	for _, f := range SupportedFrameworks {
		if f == framework {
			valid = true
			break
		}
	}
	if !valid {
		return "", fmt.Errorf("unsupported framework %q; valid: %v", framework, SupportedFrameworks)
	}

	if destDir == "" {
		var err error
		destDir, err = os.MkdirTemp("", "astgrep-rules-*")
		if err != nil {
			return "", fmt.Errorf("create temp dir: %w", err)
		}
	}

	rulesFS, _ := fs.Sub(public.StaticFS, "presets/sast-rules")
	err := fs.WalkDir(rulesFS, framework, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		data, readErr := fs.ReadFile(rulesFS, path)
		if readErr != nil {
			return fmt.Errorf("read embedded %s: %w", path, readErr)
		}

		// Write to destDir with just the filename (flat directory)
		destFile := filepath.Join(destDir, d.Name())
		if writeErr := os.WriteFile(destFile, data, 0644); writeErr != nil {
			return fmt.Errorf("write %s: %w", destFile, writeErr)
		}

		return nil
	})
	if err != nil {
		return "", fmt.Errorf("extract rules for %s: %w", framework, err)
	}

	return destDir, nil
}

// DetectFramework attempts to detect the web framework used in the given repository path.
// Returns the framework name or empty string if detection fails.
func DetectFramework(repoPath string) string {
	// Go / Gin
	if fileContains(filepath.Join(repoPath, "go.mod"), "github.com/gin-gonic/gin") {
		return "gin"
	}

	// Next.js
	if fileContains(filepath.Join(repoPath, "package.json"), "next") {
		return "nextjs"
	}

	// FastAPI
	if fileContains(filepath.Join(repoPath, "requirements.txt"), "fastapi") {
		return "fastapi"
	}
	if fileContains(filepath.Join(repoPath, "pyproject.toml"), "fastapi") {
		return "fastapi"
	}
	if fileContains(filepath.Join(repoPath, "Pipfile"), "fastapi") {
		return "fastapi"
	}

	// Express
	if fileContains(filepath.Join(repoPath, "package.json"), "express") {
		return "express"
	}

	// Django
	if fileContains(filepath.Join(repoPath, "manage.py"), "django") {
		return "django"
	}
	if fileContains(filepath.Join(repoPath, "requirements.txt"), "django") {
		return "django"
	}

	// Flask
	if fileContains(filepath.Join(repoPath, "requirements.txt"), "flask") {
		return "flask"
	}
	if fileContains(filepath.Join(repoPath, "pyproject.toml"), "flask") {
		return "flask"
	}
	if fileContains(filepath.Join(repoPath, "Pipfile"), "flask") {
		return "flask"
	}

	return ""
}

// ExtractAllRules extracts all embedded rules (all frameworks) to destDir.
// Files are named "{framework}-{filename}" to avoid collisions.
// If destDir is empty, a temp directory is created.
func ExtractAllRules(destDir string) (string, error) {
	if destDir == "" {
		var err error
		destDir, err = os.MkdirTemp("", "astgrep-rules-*")
		if err != nil {
			return "", fmt.Errorf("create temp dir: %w", err)
		}
	}

	rulesFS, _ := fs.Sub(public.StaticFS, "presets/sast-rules")
	err := fs.WalkDir(rulesFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		// path is like "gin/route-handler.yaml"
		parts := strings.SplitN(path, "/", 2)
		if len(parts) != 2 {
			return nil
		}
		framework := parts[0]
		filename := parts[1]

		data, readErr := fs.ReadFile(rulesFS, path)
		if readErr != nil {
			return fmt.Errorf("read embedded %s: %w", path, readErr)
		}

		destFile := filepath.Join(destDir, framework+"-"+filename)
		if writeErr := os.WriteFile(destFile, data, 0644); writeErr != nil {
			return fmt.Errorf("write %s: %w", destFile, writeErr)
		}

		return nil
	})
	if err != nil {
		return "", fmt.Errorf("extract all rules: %w", err)
	}

	return destDir, nil
}

// ExtractMatchingRules extracts rules whose relative path (e.g. "gin/route-handler.yaml")
// contains the given pattern (case-insensitive). Falls back to ExtractAllRules if pattern is empty.
// If destDir is empty, a temp directory is created.
func ExtractMatchingRules(pattern, destDir string) (string, error) {
	if pattern == "" {
		return ExtractAllRules(destDir)
	}

	if destDir == "" {
		var err error
		destDir, err = os.MkdirTemp("", "astgrep-rules-*")
		if err != nil {
			return "", fmt.Errorf("create temp dir: %w", err)
		}
	}

	lowerPattern := strings.ToLower(pattern)
	var matched int

	rulesFS, _ := fs.Sub(public.StaticFS, "presets/sast-rules")
	err := fs.WalkDir(rulesFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		if !strings.Contains(strings.ToLower(path), lowerPattern) {
			return nil
		}

		parts := strings.SplitN(path, "/", 2)
		if len(parts) != 2 {
			return nil
		}
		framework := parts[0]
		filename := parts[1]

		data, readErr := fs.ReadFile(rulesFS, path)
		if readErr != nil {
			return fmt.Errorf("read embedded %s: %w", path, readErr)
		}

		destFile := filepath.Join(destDir, framework+"-"+filename)
		if writeErr := os.WriteFile(destFile, data, 0644); writeErr != nil {
			return fmt.Errorf("write %s: %w", destFile, writeErr)
		}

		matched++
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("extract matching rules: %w", err)
	}

	if matched == 0 {
		return "", fmt.Errorf("no rules matching pattern %q", pattern)
	}

	return destDir, nil
}

// fileContains returns true if the file at path exists and contains substr.
func fileContains(path, substr string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), substr)
}
