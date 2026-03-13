package agent

import (
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
func ValidateExtensionSyntax(extensions []GeneratedExtension) []GeneratedExtension {
	if len(extensions) <= 1 {
		// Fast path: no parallelism needed.
		valid := make([]GeneratedExtension, 0, len(extensions))
		for _, ext := range extensions {
			if strings.TrimSpace(ext.Code) == "" {
				zap.L().Warn("Dropping invalid extension",
					zap.String("filename", ext.Filename),
					zap.Error(fmt.Errorf("empty code")))
				continue
			}
			_, err := sobek.Compile(ext.Filename, ext.Code, false)
			if err != nil {
				zap.L().Warn("Dropping invalid extension",
					zap.String("filename", ext.Filename),
					zap.Error(err))
				continue
			}
			valid = append(valid, ext)
		}
		return valid
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
	valid := make([]GeneratedExtension, 0, len(extensions))
	for i, r := range results {
		if !r.ok {
			zap.L().Warn("Dropping invalid extension",
				zap.String("filename", extensions[i].Filename),
				zap.Error(r.err))
			continue
		}
		valid = append(valid, extensions[i])
	}
	return valid
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
