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

// RepairExtensionsWithLLM attempts to fix invalid extensions by sending each one
// to the configured LLM agent with the error context. Extensions that compile
// after repair are returned; those that still fail are dropped.
func RepairExtensionsWithLLM(ctx context.Context, engine *Engine, invalids []InvalidExtension, cfg repairConfig) []GeneratedExtension {
	if len(invalids) == 0 || engine == nil {
		return nil
	}

	zap.L().Info("Attempting LLM repair for invalid extensions", zap.Int("count", len(invalids)))

	var repaired []GeneratedExtension
	for _, inv := range invalids {
		fixed, err := repairSingleExtension(ctx, engine, inv, cfg)
		if err != nil {
			zap.L().Warn("LLM repair failed for extension",
				zap.String("filename", inv.Extension.Filename),
				zap.Error(err))
			continue
		}

		// Validate the repaired code
		_, compileErr := sobek.Compile(inv.Extension.Filename, fixed, false)
		if compileErr != nil {
			zap.L().Warn("LLM-repaired extension still has syntax errors",
				zap.String("filename", inv.Extension.Filename),
				zap.Error(compileErr))
			continue
		}

		zap.L().Info("LLM successfully repaired extension",
			zap.String("filename", inv.Extension.Filename))

		repaired = append(repaired, GeneratedExtension{
			Filename: inv.Extension.Filename,
			Code:     fixed,
			Reason:   inv.Extension.Reason,
		})
	}
	return repaired
}

// repairConfig holds agent settings for the repair LLM call.
type repairConfig struct {
	AgentName   string
	AgentACPCmd string
	ShowPrompt  bool
}

// repairSingleExtension sends the broken extension code and its error to the LLM
// and extracts the fixed JavaScript from the response.
func repairSingleExtension(ctx context.Context, engine *Engine, inv InvalidExtension, cfg repairConfig) (string, error) {
	prompt := buildRepairPrompt(inv)

	result, err := engine.Run(ctx, Options{
		AgentName:   cfg.AgentName,
		AgentACPCmd: cfg.AgentACPCmd,
		PromptInline: prompt,
		ShowPrompt:  cfg.ShowPrompt,
		SessionKey:  "ext-repair-" + inv.Extension.Filename,
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
