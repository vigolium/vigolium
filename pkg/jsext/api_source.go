package jsext

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// setupSourceAPI registers vigolium.source.* functions on the VM.
func setupSourceAPI(vm *sobek.Runtime, opts APIOptions) {
	sourceObj := vm.NewObject()

	repo := opts.Repository

	// vigolium.source.list(hostname?) -> [{id, hostname, name, root_path, ...}]
	_ = sourceObj.Set("list", func(call sobek.FunctionCall) sobek.Value {
		if repo == nil {
			return vm.NewArray()
		}

		ctx := context.Background()
		hostnameArg := call.Argument(0)

		if !sobek.IsUndefined(hostnameArg) && !sobek.IsNull(hostnameArg) {
			hostname := strings.TrimSpace(hostnameArg.String())
			if hostname != "" {
				repos, err := repo.GetSourceReposByHostname(ctx, opts.ProjectUUID, hostname)
				if err != nil {
					zap.L().Debug("source.list failed", zap.Error(err))
					return vm.NewArray()
				}
				return sourceReposToJSValue(vm, repos)
			}
		}

		repos, _, err := repo.ListSourceRepos(ctx, opts.ProjectUUID, 100, 0)
		if err != nil {
			zap.L().Debug("source.list failed", zap.Error(err))
			return vm.NewArray()
		}
		return sourceReposToJSValue(vm, repos)
	})

	// vigolium.source.get(id) -> {id, hostname, name, root_path, ...}
	_ = sourceObj.Set("get", func(call sobek.FunctionCall) sobek.Value {
		if repo == nil {
			return sobek.Null()
		}

		id := call.Argument(0).ToInteger()
		sr, err := repo.GetSourceRepoByID(context.Background(), id)
		if err != nil {
			return sobek.Null()
		}
		return sourceRepoToJSValue(vm, sr)
	})

	// vigolium.source.getByHostname(hostname) -> [{...}]
	_ = sourceObj.Set("getByHostname", func(call sobek.FunctionCall) sobek.Value {
		if repo == nil {
			return vm.NewArray()
		}

		hostname := strings.TrimSpace(call.Argument(0).String())
		if hostname == "" {
			return vm.NewArray()
		}

		repos, err := repo.GetSourceReposByHostname(context.Background(), opts.ProjectUUID, hostname)
		if err != nil {
			zap.L().Debug("source.getByHostname failed", zap.Error(err))
			return vm.NewArray()
		}
		return sourceReposToJSValue(vm, repos)
	})

	// vigolium.source.readFile(hostname, relativePath) -> string
	_ = sourceObj.Set("readFile", func(call sobek.FunctionCall) sobek.Value {
		if repo == nil {
			return vm.ToValue("")
		}

		hostname := strings.TrimSpace(call.Argument(0).String())
		relPath := call.Argument(1).String()

		sr, err := resolveSourceRepoByHostname(repo, opts.ProjectUUID, hostname)
		if err != nil {
			return vm.ToValue("")
		}

		absPath, err := safeResolvePath(sr.RootPath, relPath)
		if err != nil {
			zap.L().Debug("source.readFile path traversal blocked", zap.String("path", relPath))
			return vm.ToValue("")
		}

		data, err := os.ReadFile(absPath)
		if err != nil {
			return vm.ToValue("")
		}
		return vm.ToValue(string(data))
	})

	// vigolium.source.listFiles(hostname, glob?) -> string[]
	_ = sourceObj.Set("listFiles", func(call sobek.FunctionCall) sobek.Value {
		if repo == nil {
			return vm.NewArray()
		}

		hostname := strings.TrimSpace(call.Argument(0).String())
		sr, err := resolveSourceRepoByHostname(repo, opts.ProjectUUID, hostname)
		if err != nil {
			return vm.NewArray()
		}

		globPattern := ""
		globArg := call.Argument(1)
		if !sobek.IsUndefined(globArg) && !sobek.IsNull(globArg) {
			globPattern = strings.TrimSpace(globArg.String())
		}

		var files []interface{}
		root := sr.RootPath
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return nil
			}
			if globPattern != "" {
				matched, matchErr := filepath.Match(globPattern, filepath.Base(rel))
				if matchErr != nil || !matched {
					return nil
				}
			}
			files = append(files, rel)
			return nil
		})

		return vm.ToValue(files)
	})

	// vigolium.source.searchFiles(hostname, pattern) -> [{path, line, match}]
	_ = sourceObj.Set("searchFiles", func(call sobek.FunctionCall) sobek.Value {
		if repo == nil {
			return vm.NewArray()
		}

		hostname := strings.TrimSpace(call.Argument(0).String())
		pattern := call.Argument(1).String()

		sr, err := resolveSourceRepoByHostname(repo, opts.ProjectUUID, hostname)
		if err != nil {
			return vm.NewArray()
		}

		re, err := regexp.Compile(pattern)
		if err != nil {
			zap.L().Debug("source.searchFiles invalid regex", zap.String("pattern", pattern), zap.Error(err))
			return vm.NewArray()
		}

		var results []interface{}
		root := sr.RootPath
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() {
				return nil
			}
			if isBinaryExt(filepath.Ext(path)) {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return nil
			}
			f, fErr := os.Open(path)
			if fErr != nil {
				return nil
			}
			defer func() { _ = f.Close() }()

			scanner := bufio.NewScanner(f)
			lineNum := 0
			for scanner.Scan() {
				lineNum++
				line := scanner.Text()
				if re.MatchString(line) {
					results = append(results, map[string]interface{}{
						"path":  rel,
						"line":  lineNum,
						"match": strings.TrimSpace(line),
					})
				}
				if len(results) >= 1000 {
					return fmt.Errorf("result limit reached")
				}
			}
			return nil
		})

		return vm.ToValue(results)
	})

	vigolium := vm.Get("vigolium").ToObject(vm)
	_ = vigolium.Set("source", sourceObj)
}

// resolveSourceRepoByHostname looks up the most recent source repo for a hostname.
func resolveSourceRepoByHostname(repo *database.Repository, projectUUID, hostname string) (*database.SourceRepo, error) {
	if hostname == "" {
		return nil, fmt.Errorf("hostname is required")
	}
	repos, err := repo.GetSourceReposByHostname(context.Background(), projectUUID, hostname)
	if err != nil {
		return nil, err
	}
	if len(repos) == 0 {
		return nil, fmt.Errorf("no source repo found for hostname: %s", hostname)
	}
	// GetSourceReposByHostname returns ordered by created_at DESC, so first is most recent
	return repos[0], nil
}

// sourceRepoToJSValue converts a SourceRepo to a JS-friendly map.
func sourceRepoToJSValue(vm *sobek.Runtime, sr *database.SourceRepo) sobek.Value {
	return vm.ToValue(sourceRepoToMap(sr))
}

// sourceReposToJSValue converts a slice of SourceRepos to a JS array.
func sourceReposToJSValue(vm *sobek.Runtime, repos []*database.SourceRepo) sobek.Value {
	arr := make([]interface{}, len(repos))
	for i, sr := range repos {
		arr[i] = sourceRepoToMap(sr)
	}
	return vm.ToValue(arr)
}

// sourceRepoToMap converts a SourceRepo to a map for JS consumption.
func sourceRepoToMap(sr *database.SourceRepo) map[string]interface{} {
	m := map[string]interface{}{
		"id":        sr.ID,
		"hostname":  sr.Hostname,
		"name":      sr.Name,
		"root_path": sr.RootPath,
		"repo_type": sr.RepoType,
	}
	if sr.Language != "" {
		m["language"] = sr.Language
	}
	if sr.Framework != "" {
		m["framework"] = sr.Framework
	}
	if sr.ScanUUID != "" {
		m["scan_uuid"] = sr.ScanUUID
	}
	if len(sr.Endpoints) > 0 {
		m["endpoints"] = sr.Endpoints
	}
	if len(sr.RouteParams) > 0 {
		m["route_params"] = sr.RouteParams
	}
	if len(sr.Sinks) > 0 {
		m["sinks"] = sr.Sinks
	}
	if len(sr.Tags) > 0 {
		m["tags"] = sr.Tags
	}
	return m
}

// safeResolvePath resolves a relative path within a root directory,
// preventing path traversal attacks.
func safeResolvePath(root, relPath string) (string, error) {
	absPath := filepath.Join(root, filepath.Clean("/"+relPath))
	absPath, err := filepath.Abs(absPath)
	if err != nil {
		return "", err
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(absPath, absRoot+string(filepath.Separator)) && absPath != absRoot {
		return "", fmt.Errorf("path traversal detected: %s", relPath)
	}
	return absPath, nil
}

// isBinaryExt returns true for common binary file extensions.
func isBinaryExt(ext string) bool {
	switch strings.ToLower(ext) {
	case ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
		".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
		".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
		".mp3", ".mp4", ".avi", ".mov", ".wav",
		".pdf", ".doc", ".docx", ".xls", ".xlsx",
		".woff", ".woff2", ".ttf", ".eot",
		".class", ".pyc", ".pyo":
		return true
	}
	return false
}
