package agent

// This file holds the result-ingestion and HTTP-record conversion helpers used
// by Engine after an agent run produces structured output. Split out of
// engine.go to keep that file focused on the run lifecycle (prompt build →
// dispatch → result assembly).

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/pkg/agent/parsing"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

// ingestFindings saves parsed findings to the database.
func (e *Engine) ingestFindings(ctx context.Context, findings []AgentFinding, opts Options) (saved int, skipped int, err error) {
	moduleID := "agent-" + opts.AgentName
	if opts.PromptTemplate != "" {
		moduleID = "agent-" + opts.PromptTemplate
	}

	for _, af := range findings {
		dbFinding := parsing.ToDBFinding(af, moduleID, opts.ScanUUID, opts.ProjectUUID)
		if saveErr := e.repo.SaveFindingDirect(ctx, dbFinding); saveErr != nil {
			zap.L().Debug("Failed to save finding",
				zap.String("title", af.Title),
				zap.Error(saveErr))
			skipped++
			continue
		}
		saved++
	}
	return saved, skipped, nil
}

// ingestHTTPRecords saves parsed HTTP records to the database.
// Notes from agent records are preserved as remarks via AppendRemarks.
func (e *Engine) ingestHTTPRecords(ctx context.Context, records []AgentHTTPRecord, opts Options) (int, error) {
	saved := 0
	source := "agent"
	if opts.Source != "" {
		source = opts.Source
	}

	remarksMap := make(map[string][]string)

	for _, rec := range records {
		httpRR, err := ToHTTPRequestResponse(rec)
		if err != nil {
			zap.L().Warn("Skipping invalid HTTP record",
				zap.String("url", rec.URL),
				zap.Error(err))
			continue
		}
		savedUUID, saveErr := e.repo.SaveRecord(ctx, httpRR, source, opts.ProjectUUID)
		if saveErr != nil {
			zap.L().Warn("Failed to save HTTP record",
				zap.String("url", rec.URL),
				zap.Error(saveErr))
			continue
		}
		saved++
		if rec.Notes != "" && savedUUID != "" {
			remarksMap[savedUUID] = []string{rec.Notes}
		}
	}

	// Batch-append notes as remarks
	if len(remarksMap) > 0 {
		if err := e.repo.AppendRemarks(ctx, remarksMap); err != nil {
			zap.L().Warn("Failed to append remarks from agent notes", zap.Error(err))
		}
	}

	return saved, nil
}

// ToHTTPRequestResponse converts an AgentHTTPRecord to an httpmsg.HttpRequestResponse.
func ToHTTPRequestResponse(rec AgentHTTPRecord) (*httpmsg.HttpRequestResponse, error) {
	if rec.URL == "" {
		return nil, fmt.Errorf("URL is required")
	}
	if rec.Method == "" {
		rec.Method = "GET"
	}

	parsedURL, parseErr := url.Parse(rec.URL)
	if parseErr != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", rec.URL, parseErr)
	}

	// Use the relative path in the request line (standard HTTP/1.1 origin-form).
	reqPath := parsedURL.RequestURI()
	if reqPath == "" {
		reqPath = "/"
	}

	rawReq := fmt.Sprintf("%s %s HTTP/1.1\r\n", rec.Method, reqPath)

	// Auto-detect Content-Type from body when not explicitly set.
	if rec.Body != "" {
		hasContentType := false
		for k := range rec.Headers {
			if strings.EqualFold(k, "Content-Type") {
				hasContentType = true
				break
			}
		}
		if !hasContentType {
			if ct := inferContentType(rec.Body); ct != "" {
				if rec.Headers == nil {
					rec.Headers = make(map[string]string)
				}
				rec.Headers["Content-Type"] = ct
			}
		}
	}

	// Ensure a Host header is present (required by HTTP/1.1).
	hasHost := false
	for k, v := range rec.Headers {
		rawReq += fmt.Sprintf("%s: %s\r\n", k, v)
		if strings.EqualFold(k, "Host") {
			hasHost = true
		}
	}
	if !hasHost && parsedURL.Host != "" {
		rawReq += fmt.Sprintf("Host: %s\r\n", parsedURL.Host)
	}

	rawReq += "\r\n"
	if rec.Body != "" {
		rawReq += rec.Body
	}

	return httpmsg.ParseRawRequestWithURL(rawReq, rec.URL)
}

// inferContentType detects the content type from a request body string.
// Returns empty string if the format is unrecognizable.
func inferContentType(body string) string {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return ""
	}

	// JSON: starts with { or [
	if (trimmed[0] == '{' || trimmed[0] == '[') && parsing.IsJSON(trimmed) {
		return "application/json"
	}

	// XML/HTML: starts with < and has a closing tag
	if trimmed[0] == '<' {
		lower := strings.ToLower(trimmed)
		if strings.Contains(lower, "<?xml") || strings.Contains(lower, "<soap") {
			return "application/xml"
		}
		if strings.Contains(lower, "<html") {
			return "text/html"
		}
		return "application/xml"
	}

	// URL-encoded form: key=value pairs
	if strings.Contains(trimmed, "=") && !strings.Contains(trimmed, "\n") {
		// Heuristic: looks like key=value&key2=value2
		parts := strings.Split(trimmed, "&")
		if len(parts) > 0 {
			allKV := true
			for _, p := range parts {
				if !strings.Contains(p, "=") {
					allKV = false
					break
				}
			}
			if allKV {
				return "application/x-www-form-urlencoded"
			}
		}
	}

	return ""
}

// collectSourceFiles walks a directory and returns paths to common source files.
// The walk is bounded by ctx so that a hung or very large directory tree does not
// block the caller indefinitely. Symlinks are skipped to avoid cycles.
func collectSourceFiles(ctx context.Context, dir string) ([]string, error) {
	sourceExts := map[string]bool{
		".go": true, ".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
		".java": true, ".rb": true, ".php": true, ".rs": true, ".c": true, ".cpp": true,
		".cs": true, ".swift": true, ".kt": true, ".scala": true, ".vue": true, ".svelte": true,
	}

	type walkResult struct {
		files []string
		err   error
	}
	ch := make(chan walkResult, 1)

	go func() {
		var files []string
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			// Bail out early if the context has been cancelled.
			select {
			case <-ctx.Done():
				return filepath.SkipAll
			default:
			}
			// Skip symlinks to avoid cycles
			if d.Type()&os.ModeSymlink != 0 {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			// Skip non-source directories (dependencies, build output, etc.)
			if d.IsDir() {
				if shouldSkipDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			ext := filepath.Ext(d.Name())
			if sourceExts[ext] && !shouldSkipFile(d.Name()) {
				files = append(files, path)
			}
			return nil
		})
		ch <- walkResult{files, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-ch:
		return result.files, result.err
	}
}

// detectLanguage guesses the primary language from file extensions.
func detectLanguage(files []string) string {
	counts := make(map[string]int)
	extLang := map[string]string{
		".go": "Go", ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
		".jsx": "JavaScript", ".tsx": "TypeScript", ".java": "Java", ".rb": "Ruby",
		".php": "PHP", ".rs": "Rust", ".c": "C", ".cpp": "C++",
		".cs": "C#", ".swift": "Swift", ".kt": "Kotlin", ".scala": "Scala",
		".vue": "Vue", ".svelte": "Svelte",
	}
	for _, f := range files {
		ext := filepath.Ext(f)
		if lang, ok := extLang[ext]; ok {
			counts[lang]++
		}
	}
	best := ""
	bestCount := 0
	for lang, count := range counts {
		if count > bestCount {
			best = lang
			bestCount = count
		}
	}
	return best
}
