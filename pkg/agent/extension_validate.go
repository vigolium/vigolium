package agent

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/grafana/sobek"
	"go.uber.org/zap"
)

// ValidateExtensionSyntax compiles each extension's JavaScript code for
// parse-only validation and returns only the extensions that parse
// successfully. Invalid or empty extensions are logged and dropped.
// For multiple extensions, validation runs in parallel with bounded
// concurrency (runtime.NumCPU goroutines).
func ValidateExtensionSyntax(extensions []GeneratedExtension) (valid []GeneratedExtension, invalid []InvalidExtension) {
	if len(extensions) <= 1 {
		// Fast path: no parallelism needed.
		valid = make([]GeneratedExtension, 0, len(extensions))
		for _, ext := range extensions {
			if strings.TrimSpace(ext.Code) == "" {
				logDroppedExtension(ext, fmt.Errorf("empty code"))
				invalid = append(invalid, InvalidExtension{Extension: ext, Err: fmt.Errorf("empty code")})
				continue
			}
			_, err := sobek.Compile(ext.Filename, ext.Code, false)
			if err != nil {
				logDroppedExtension(ext, err)
				invalid = append(invalid, InvalidExtension{Extension: ext, Err: err})
				continue
			}
			valid = append(valid, ext)
		}
		return valid, invalid
	}

	// Parallel path: validate concurrently with a semaphore.
	type result struct {
		ok  bool
		err error
	}
	results := make([]result, len(extensions))

	sem := make(chan struct{}, runtime.NumCPU())
	var wg sync.WaitGroup

	for i, ext := range extensions {
		wg.Add(1)
		go func(idx int, e GeneratedExtension) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if strings.TrimSpace(e.Code) == "" {
				results[idx] = result{ok: false, err: fmt.Errorf("empty code")}
				return
			}
			_, compileErr := sobek.Compile(e.Filename, e.Code, false)
			if compileErr != nil {
				results[idx] = result{ok: false, err: compileErr}
				return
			}
			results[idx] = result{ok: true}
		}(i, ext)
	}
	wg.Wait()

	// Collect valid extensions preserving original order.
	valid = make([]GeneratedExtension, 0, len(extensions))
	for i, r := range results {
		if !r.ok {
			logDroppedExtension(extensions[i], r.err)
			invalid = append(invalid, InvalidExtension{Extension: extensions[i], Err: r.err})
			continue
		}
		valid = append(valid, extensions[i])
	}
	return valid, invalid
}

// InvalidExtension holds an extension that failed syntax validation along with
// the compile error, so it can be passed to the LLM for repair.
type InvalidExtension struct {
	Extension GeneratedExtension
	Err       error
}

// logDroppedExtension logs a warning with the error and source context around the
// error line so it's easier to diagnose in logs.
func logDroppedExtension(ext GeneratedExtension, err error) {
	fields := []zap.Field{
		zap.String("filename", ext.Filename),
		zap.Error(err),
	}

	// Extract source context around the error line for better diagnostics
	if ctx := extractErrorContext(ext.Code, err); ctx != "" {
		fields = append(fields, zap.String("context", ctx))
	}

	zap.L().Warn("Dropping invalid extension", fields...)
}

// extractErrorContext parses a sobek compile error for a line number and returns
// the offending line with 2 lines of surrounding context.
func extractErrorContext(code string, err error) string {
	if code == "" || err == nil {
		return ""
	}

	// sobek errors look like: "filename: Line 5:12 Unexpected token )"
	msg := err.Error()
	lineNum := 0
	// Find "Line N:" pattern
	if idx := strings.Index(msg, "Line "); idx >= 0 {
		rest := msg[idx+5:]
		for i, ch := range rest {
			if ch >= '0' && ch <= '9' {
				lineNum = lineNum*10 + int(ch-'0')
			} else {
				_ = i
				break
			}
		}
	}
	if lineNum <= 0 {
		return ""
	}

	lines := strings.Split(code, "\n")
	total := len(lines)
	const contextSize = 2
	start := lineNum - contextSize
	if start < 1 {
		start = 1
	}
	end := lineNum + contextSize
	if end > total {
		end = total
	}

	var sb strings.Builder
	gutterWidth := len(fmt.Sprintf("%d", end))
	for ln := start; ln <= end; ln++ {
		marker := " "
		if ln == lineNum {
			marker = ">"
		}
		fmt.Fprintf(&sb, "  %s %*d │ %s\n", marker, gutterWidth, ln, lines[ln-1])
	}
	return sb.String()
}

// maxRepairConcurrency is the maximum number of parallel LLM repair calls.
// Each call is an independent API request, so we bound concurrency to avoid
// overwhelming the LLM backend while still getting significant speedup.
const maxRepairConcurrency = 5

// RepairExtensionsWithLLM attempts to fix invalid extensions by sending each one
// to the configured LLM agent with the error context. Repairs run in parallel
// with bounded concurrency. Extensions that compile after repair are returned;
// those that still fail are dropped.
func RepairExtensionsWithLLM(ctx context.Context, engine *Engine, invalids []InvalidExtension, cfg repairConfig) []GeneratedExtension {
	if len(invalids) == 0 || engine == nil {
		return nil
	}

	zap.L().Info("Attempting LLM repair for invalid extensions",
		zap.Int("count", len(invalids)),
		zap.Int("concurrency", maxRepairConcurrency))

	results := make([]*GeneratedExtension, len(invalids))

	sem := make(chan struct{}, maxRepairConcurrency)
	var wg sync.WaitGroup

	for i, inv := range invalids {
		wg.Add(1)
		go func(idx int, inv InvalidExtension) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fixed, err := repairSingleExtension(ctx, engine, inv, cfg)
			if err != nil {
				zap.L().Warn("LLM repair failed for extension",
					zap.String("filename", inv.Extension.Filename),
					zap.Error(err))
				return
			}

			// Validate the repaired code
			_, compileErr := sobek.Compile(inv.Extension.Filename, fixed, false)
			if compileErr != nil {
				zap.L().Warn("LLM-repaired extension still has syntax errors",
					zap.String("filename", inv.Extension.Filename),
					zap.Error(compileErr))
				return
			}

			zap.L().Info("LLM successfully repaired extension",
				zap.String("filename", inv.Extension.Filename))

			results[idx] = &GeneratedExtension{
				Filename: inv.Extension.Filename,
				Code:     fixed,
				Reason:   inv.Extension.Reason,
			}
		}(i, inv)
	}
	wg.Wait()

	// Collect successful repairs preserving original order.
	var repaired []GeneratedExtension
	for _, ext := range results {
		if ext != nil {
			repaired = append(repaired, *ext)
		}
	}
	return repaired
}

// repairConfig holds agent settings for the repair LLM call.
type repairConfig struct {
	AgentName    string
	AgentACPCmd  string
	ShowPrompt   bool
	TargetURL    string   // target URL for regeneration context
	FocusAreas   []string // focus areas from the swarm plan
	ModuleTags   []string // module tags from the swarm plan
	ExploreNotes string   // session explore notes for context-aware session repair (optional)
}

// repairSingleExtension sends the broken extension code and its error to the LLM
// and extracts the fixed JavaScript from the response. For severely garbled code
// it uses a regeneration prompt with plan context instead of trying to fix syntax.
func repairSingleExtension(ctx context.Context, engine *Engine, inv InvalidExtension, cfg repairConfig) (string, error) {
	var prompt string
	if isGarbled(inv.Extension.Code) {
		prompt = buildRegeneratePrompt(inv, cfg)
		zap.L().Info("Extension classified as garbled, using regeneration prompt",
			zap.String("filename", inv.Extension.Filename))
	} else {
		prompt = buildRepairPrompt(inv)
	}

	result, err := engine.Run(ctx, Options{
		AgentName:    cfg.AgentName,
		AgentACPCmd:  cfg.AgentACPCmd,
		PromptInline: prompt,
		ShowPrompt:   cfg.ShowPrompt,
		SessionKey:   "ext-repair-" + inv.Extension.Filename,
	})
	if err != nil {
		return "", fmt.Errorf("agent run failed: %w", err)
	}

	// Extract the JavaScript code from the response — look for fenced code block first
	code := extractCodeFromResponse(result.RawOutput)
	if strings.TrimSpace(code) == "" {
		return "", fmt.Errorf("no code found in agent response")
	}
	return code, nil
}

// buildRepairPrompt constructs the prompt for the extension repair agent call.
func buildRepairPrompt(inv InvalidExtension) string {
	var sb strings.Builder
	sb.WriteString("The following vigolium JavaScript extension has syntax errors and cannot be loaded.\n")
	sb.WriteString("Fix the syntax errors and return ONLY the corrected JavaScript code in a single ```javascript fenced code block.\n")
	sb.WriteString("Do NOT change the extension's logic, intent, or structure — only fix syntax errors.\n")
	sb.WriteString("Do NOT add explanations outside the code block.\n\n")

	sb.WriteString("## Error\n\n")
	sb.WriteString("```\n")
	sb.WriteString(inv.Err.Error())
	sb.WriteString("\n```\n\n")

	// Add source context around the error
	if ctx := extractErrorContext(inv.Extension.Code, inv.Err); ctx != "" {
		sb.WriteString("## Error Context\n\n")
		sb.WriteString("```\n")
		sb.WriteString(ctx)
		sb.WriteString("```\n\n")
	}

	sb.WriteString("## Full Extension Code\n\n")
	sb.WriteString("```javascript\n")
	sb.WriteString(inv.Extension.Code)
	sb.WriteString("\n```\n")
	return sb.String()
}

// isGarbled detects if extension code is severely corrupted (interleaved text,
// not just minor syntax errors). Garbled code can't be repaired by fixing syntax —
// it needs to be regenerated from intent.
//
// Detection heuristics:
//   - Multiple tokens on a single line that look like field interleaving (e.g. "module..pubexports")
//   - Fields with values from other fields mixed in (e.g. "id:easure-bypass")
//   - High density of parse errors in the first few lines
func isGarbled(code string) bool {
	if code == "" {
		return true
	}

	lines := strings.Split(code, "\n")

	// Limit analysis to the first 10 lines (module header area)
	maxLines := 10
	if len(lines) < maxLines {
		maxLines = len(lines)
	}

	garbledLines := 0
	for i := 0; i < maxLines; i++ {
		line := lines[i]
		if isGarbledLine(line) {
			garbledLines++
		}
	}

	// If any garbled lines are detected, also check for structural corruption signals.
	if garbledLines > 0 {
		// Additional check: module.exports line itself is garbled
		firstNonEmpty := ""
		for _, l := range lines {
			if t := strings.TrimSpace(l); t != "" {
				firstNonEmpty = t
				break
			}
		}
		if firstNonEmpty != "" && strings.Contains(firstNonEmpty, "module") &&
			firstNonEmpty != "module.exports = {" && !strings.HasPrefix(firstNonEmpty, "module.exports") {
			garbledLines++
		}
	}

	// Threshold: 2+ garbled lines, or 1 garbled line if the code is short (≤6 lines)
	if garbledLines >= 3 {
		return true
	}
	if garbledLines >= 2 {
		return true
	}
	// For short code snippets, even 1 garbled line in the header is significant
	if garbledLines >= 1 && maxLines <= 6 {
		return true
	}
	return false
}

// isGarbledLine checks if a single line shows signs of streaming corruption.
func isGarbledLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || trimmed == "{" || trimmed == "}" || trimmed == "]," ||
		trimmed == "}," || trimmed == "};" || trimmed == "module.exports = {" {
		return false
	}

	// Double dots in identifiers: "module..pubexports"
	if strings.Contains(trimmed, "..") && !strings.Contains(trimmed, "...") {
		return true
	}

	// Detect key with spaces or garbled content before the colon.
	if idx := strings.Index(trimmed, ":"); idx > 0 {
		key := strings.TrimSpace(trimmed[:idx])

		// Check for quoted keys: must have matching quotes and no spaces inside
		if len(key) > 0 && (key[0] == '"' || key[0] == '\'') {
			q := key[0]
			closingIdx := strings.IndexByte(key[1:], q)
			if closingIdx < 0 {
				// Unmatched quote before colon — garbled
				return true
			}
		} else {
			// Unquoted key with spaces = garbled (value merged into key)
			// e.g. 'type Prometheus metrics endpoint: "active"'
			if strings.Contains(key, " ") {
				return true
			}
			// Keys with mixed content (not a simple identifier) and too long
			if len(key) > 20 && !isSimpleJSIdentifier(key) {
				return true
			}
		}
	}

	// Line that looks like a truncated key without colon but has quote-comma:
	// e.g. '  id-pubkey",' — this is an id value that lost its key prefix
	if !strings.Contains(trimmed, ":") && strings.Contains(trimmed, "\",") {
		// A line in a JS object without a colon but with a quoted-comma pattern
		// is likely a garbled field (the key: part got eaten)
		if len(trimmed) > 3 && trimmed[0] != '/' && trimmed[0] != '*' && trimmed[0] != '}' {
			return true
		}
	}

	// Multiple colons on a single property line (fields merged together).
	// e.g. 'name: "agent-disclosure-jwt public key exposed: "RS256 JWT...'
	// Count unquoted colons: in a normal line like 'key: "value with: inside"'
	// there's only 1 colon outside quotes. If there are 2+, fields are merged.
	unquotedColons := countUnquotedColons(trimmed)
	if unquotedColons >= 3 {
		return true
	}

	// Stray single uppercase letter at end of line after quote:
	// e.g. 'id: "agent-disclosure-ftp-listing",U'
	if len(trimmed) > 2 {
		last := trimmed[len(trimmed)-1]
		if last >= 'A' && last <= 'Z' {
			prev := trimmed[len(trimmed)-2]
			if prev == ',' || prev == '"' || prev == '\'' {
				return true
			}
		}
	}

	return false
}

// countUnquotedColons counts colon characters that appear outside of quoted strings.
func countUnquotedColons(s string) int {
	count := 0
	inQuote := false
	var quoteChar byte
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inQuote {
			if ch == quoteChar && (i == 0 || s[i-1] != '\\') {
				inQuote = false
			}
		} else {
			if ch == '"' || ch == '\'' {
				inQuote = true
				quoteChar = ch
			} else if ch == ':' {
				count++
			}
		}
	}
	return count
}

// isSimpleJSIdentifier returns true if s looks like a valid JS identifier (letters, digits, _, $, -).
func isSimpleJSIdentifier(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '$' || r == '-') {
			return false
		}
	}
	return true
}

// buildRegeneratePrompt constructs a prompt for regenerating a garbled extension
// from scratch, using intent extracted from the garbled code and plan context.
func buildRegeneratePrompt(inv InvalidExtension, cfg repairConfig) string {
	var sb strings.Builder
	sb.WriteString("The following vigolium JavaScript scanner extension was severely corrupted during generation.\n")
	sb.WriteString("The code is garbled beyond repair — fields are interleaved and text is mixed together.\n")
	sb.WriteString("You must REGENERATE the extension from scratch based on the intent described below.\n")
	sb.WriteString("Return ONLY the corrected JavaScript code in a single ```javascript fenced code block.\n")
	sb.WriteString("Do NOT add explanations outside the code block.\n\n")

	// Extract whatever intent we can from the garbled code
	intent := extractIntentFromGarbled(inv.Extension.Code, inv.Extension.Filename, inv.Extension.Reason)
	sb.WriteString("## Extracted Intent\n\n")
	sb.WriteString(intent)
	sb.WriteString("\n\n")

	// Add plan context if available
	if cfg.TargetURL != "" || len(cfg.FocusAreas) > 0 || len(cfg.ModuleTags) > 0 {
		sb.WriteString("## Scan Context\n\n")
		if cfg.TargetURL != "" {
			sb.WriteString("- Target URL: " + cfg.TargetURL + "\n")
		}
		if len(cfg.FocusAreas) > 0 {
			sb.WriteString("- Focus areas: " + strings.Join(cfg.FocusAreas, ", ") + "\n")
		}
		if len(cfg.ModuleTags) > 0 {
			sb.WriteString("- Module tags: " + strings.Join(cfg.ModuleTags, ", ") + "\n")
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## Extension Template\n\n")
	sb.WriteString("Generate a vigolium active scanner extension with this structure:\n\n")
	sb.WriteString("```javascript\n")
	sb.WriteString("module.exports = {\n")
	sb.WriteString("  id: \"extension-id\",\n")
	sb.WriteString("  name: \"Human-readable description of the check\",\n")
	sb.WriteString("  type: \"active\",\n")
	sb.WriteString("  severity: \"high\",  // critical, high, medium, low, info\n")
	sb.WriteString("  scanTypes: [\"per_request\"],  // per_insertion_point, per_request, per_host\n")
	sb.WriteString("  tags: [\"agent-generated\"],\n")
	sb.WriteString("  scanPerRequest: function(ctx) {\n")
	sb.WriteString("    // Send test request and analyze response\n")
	sb.WriteString("    var resp = vigolium.http.sendRequest(ctx.request);\n")
	sb.WriteString("    // Check for vulnerability indicators\n")
	sb.WriteString("  }\n")
	sb.WriteString("};\n")
	sb.WriteString("```\n\n")

	sb.WriteString("## Garbled Source (for reference only — do NOT try to fix this, rewrite from scratch)\n\n")
	sb.WriteString("```\n")
	// Truncate garbled code to avoid confusing the LLM
	garbled := inv.Extension.Code
	if len(garbled) > 2000 {
		garbled = garbled[:2000] + "\n... (truncated)"
	}
	sb.WriteString(garbled)
	sb.WriteString("\n```\n")
	return sb.String()
}

// extractIntentFromGarbled tries to extract meaningful fragments from garbled code
// to determine what the extension was supposed to do.
func extractIntentFromGarbled(code, filename, reason string) string {
	var parts []string

	if reason != "" {
		parts = append(parts, "- Reason: "+reason)
	}

	if filename != "" && filename != "extension.js" {
		parts = append(parts, "- Original filename: "+filename)
	}

	// Try to extract the id field value
	if id := extractGarbledField(code, "id"); id != "" {
		parts = append(parts, "- Extension ID: "+id)
	}

	// Try to extract the name/description field
	if name := extractGarbledField(code, "name"); name != "" {
		parts = append(parts, "- Description: "+name)
	}

	// Try to extract severity
	if sev := extractGarbledField(code, "severity"); sev != "" {
		parts = append(parts, "- Severity: "+sev)
	}

	// Try to extract type
	if typ := extractGarbledField(code, "type"); typ != "" {
		parts = append(parts, "- Type: "+typ)
	}

	if len(parts) == 0 {
		return "Could not extract intent from garbled code. Generate a security scanner extension based on the filename."
	}

	return strings.Join(parts, "\n")
}

// extractGarbledField tries to extract a field value from garbled JS code.
// It looks for patterns like 'field: "value"' or 'field: "value...' even if truncated.
func extractGarbledField(code, field string) string {
	// Look for field: "value" pattern
	patterns := []string{
		field + `: "`,
		field + `:"`,
		field + `: '`,
		field + `:'`,
	}

	for _, pat := range patterns {
		idx := strings.Index(code, pat)
		if idx < 0 {
			continue
		}
		start := idx + len(pat)
		quote := code[start-1]
		end := strings.IndexByte(code[start:], quote)
		if end > 0 && end < 200 {
			return code[start : start+end]
		}
		// No closing quote — take up to 100 chars
		remaining := code[start:]
		if len(remaining) > 100 {
			remaining = remaining[:100]
		}
		// Take up to first newline
		if nl := strings.IndexByte(remaining, '\n'); nl > 0 {
			remaining = remaining[:nl]
		}
		return strings.TrimSpace(remaining) + " (garbled)"
	}
	return ""
}

// extractCodeFromResponse pulls JavaScript code from the agent's response.
// It looks for fenced code blocks first, then falls back to the raw response.
func extractCodeFromResponse(output string) string {
	blocks := extractFencedBlocks(output)
	if len(blocks) > 0 {
		// Return the first non-empty block (typically the JS code)
		for _, b := range blocks {
			if trimmed := strings.TrimSpace(b); trimmed != "" {
				return trimmed
			}
		}
	}
	// Fallback: return trimmed output
	return strings.TrimSpace(output)
}

// deduplicateExtensionFilename returns a filename that does not collide with
// any key already present in existing. On collision it strips the .js suffix,
// appends -2, -3, … until a unique name is found, and re-adds .js.
func deduplicateExtensionFilename(name string, existing map[string]bool) string {
	if !existing[name] {
		return name
	}
	base := strings.TrimSuffix(name, ".js")
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s-%d.js", base, i)
		if !existing[candidate] {
			return candidate
		}
	}
}
