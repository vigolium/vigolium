package extensions

import (
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"go.uber.org/zap"
)

// ValidateExtensionSyntax compiles each extension's JavaScript code for
// parse-only validation and returns only the extensions that parse
// successfully. Invalid or empty extensions are logged and dropped.
// For multiple extensions, validation runs in parallel with bounded
// concurrency (runtime.NumCPU goroutines).
func ValidateExtensionSyntax(extensions []agenttypes.GeneratedExtension) (valid []agenttypes.GeneratedExtension, invalid []agenttypes.InvalidExtension) {
	if len(extensions) <= 1 {
		// Fast path: no parallelism needed.
		valid = make([]agenttypes.GeneratedExtension, 0, len(extensions))
		for _, ext := range extensions {
			if strings.TrimSpace(ext.Code) == "" {
				LogDroppedExtension(ext, fmt.Errorf("empty code"))
				invalid = append(invalid, agenttypes.InvalidExtension{Extension: ext, Err: fmt.Errorf("empty code")})
				continue
			}
			_, err := sobek.Compile(ext.Filename, ext.Code, false)
			if err != nil {
				LogDroppedExtension(ext, err)
				invalid = append(invalid, agenttypes.InvalidExtension{Extension: ext, Err: err})
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
		go func(idx int, e agenttypes.GeneratedExtension) {
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
	valid = make([]agenttypes.GeneratedExtension, 0, len(extensions))
	for i, r := range results {
		if !r.ok {
			LogDroppedExtension(extensions[i], r.err)
			invalid = append(invalid, agenttypes.InvalidExtension{Extension: extensions[i], Err: r.err})
			continue
		}
		valid = append(valid, extensions[i])
	}
	return valid, invalid
}

// LogDroppedExtension logs a warning with the error and source context around the
// error line so it's easier to diagnose in logs.
func LogDroppedExtension(ext agenttypes.GeneratedExtension, err error) {
	fields := []zap.Field{
		zap.String("filename", ext.Filename),
		zap.Error(err),
	}

	// Extract source context around the error line for better diagnostics
	if ctx := ExtractErrorContext(ext.Code, err); ctx != "" {
		fields = append(fields, zap.String("context", ctx))
	}

	zap.L().Warn("Dropping invalid extension", fields...)
}

// ExtractErrorContext parses a sobek compile error for a line number and returns
// the offending line with 2 lines of surrounding context.
func ExtractErrorContext(code string, err error) string {
	if code == "" || err == nil {
		return ""
	}

	// sobek errors look like: "filename: Line 5:12 Unexpected token )"
	msg := err.Error()
	lineNum := 0
	// Find "Line N:" pattern
	if idx := strings.Index(msg, "Line "); idx >= 0 {
		rest := msg[idx+5:]
		for _, ch := range rest {
			if ch >= '0' && ch <= '9' {
				lineNum = lineNum*10 + int(ch-'0')
			} else {
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
