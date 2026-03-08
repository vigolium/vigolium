package lfi_path_traversal

import (
	"regexp"
	"strings"
)

// fileParamNames are parameter names that commonly reference file paths.
var fileParamNames = []string{
	"file", "path", "page", "include", "dir", "doc", "document",
	"folder", "root", "pg", "style", "pdf", "template", "php_path",
	"basepath", "filepath", "filename", "download", "content", "site",
	"view", "cat", "action", "board", "prefix", "inc", "locate",
	"show", "conf", "layout", "mod", "url", "img", "image",
	"load", "read", "open", "source", "src",
}

var fileParamRegexes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)file`),
	regexp.MustCompile(`(?i)path`),
	regexp.MustCompile(`(?i)dir`),
	regexp.MustCompile(`(?i)download`),
	regexp.MustCompile(`(?i)page`),
	regexp.MustCompile(`(?i)template`),
	regexp.MustCompile(`(?i)include`),
}

// matchFileParams checks if a parameter name suggests file handling.
func matchFileParams(name string) bool {
	lower := strings.ToLower(name)
	for _, fp := range fileParamNames {
		if strings.Contains(lower, fp) {
			return true
		}
	}
	for _, rx := range fileParamRegexes {
		if rx.MatchString(name) {
			return true
		}
	}
	return false
}

var pathValueRegex = regexp.MustCompile(
	`(?i)(^(\.{0,2}/)|(\.(html|htm|xml|conf|cfg|log|txt|pdf|doc|ini|php|asp|jsp|py|rb|pl|sh)$))`,
)

// looksLikeFilePath checks if a parameter value resembles a file path.
func looksLikeFilePath(value string) bool {
	return pathValueRegex.MatchString(value)
}
