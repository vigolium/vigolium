package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/grafana/sobek"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/types"
)

var jsOpts struct {
	code     string
	codeFile string
	target   string
	timeout  time.Duration
}

var jsCmd = &cobra.Command{
	Use:   "js",
	Short: "Execute JavaScript with the full vigolium.* API",
	Long: `Run JavaScript code with access to the full vigolium.* API surface.
Reads from stdin by default, or use --code / --code-file for inline / file input.

Without -j the script's return value is printed as JSON; --format text prints a
string result unquoted (--format is the global flag: json, the default, or
text). -j wraps the value in the envelope as items:[{"value": …}].`,
	RunE: runJsCmd,
}

func init() {
	rootCmd.AddCommand(jsCmd)

	flags := jsCmd.Flags()
	flags.StringVar(&jsOpts.code, "code", "", "Inline JavaScript code to execute")
	flags.StringVar(&jsOpts.codeFile, "code-file", "", "Path to JavaScript/TypeScript file to execute")
	flags.StringVar(&jsOpts.target, "target", "", "Set TARGET variable in JS scope (URL)")
	flags.DurationVar(&jsOpts.timeout, "timeout", 30*time.Second, "Execution timeout")
}

func runJsCmd(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	format, err := jsOutputFormat(cmd)
	if err != nil {
		return err
	}

	// Resolve JS source
	source, err := resolveJsSource()
	if err != nil {
		return err
	}

	// Load settings
	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return err
	}

	// Build the API surface (DB, scope, HTTP stack) shared with
	// `vigolium extensions eval`.
	opts, cleanup, err := buildJSEvalOptions("js", settings)
	if err != nil {
		return err
	}
	defer cleanup()

	// Create VM and execute with timeout
	result := evalWithTimeout(source, opts, jsOpts.target, jsOpts.timeout)
	if result.Error != nil {
		return fmt.Errorf("js error: %w", result.Error)
	}

	if globalJSON {
		return emitJSEvalResult(cmd, result.Value)
	}

	if result.Value != "" {
		if format == "text" {
			// Try to print as raw string (strip surrounding quotes for simple strings)
			v := result.Value
			if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
				// Unescape JSON string
				fmt.Println(v[1 : len(v)-1])
			} else {
				fmt.Println(v)
			}
		} else {
			fmt.Println(result.Value)
		}
	}

	return nil
}

// jsOutputFormat reads the global --format for `js`: json (the default, also
// when the flag is not typed — its global default is a scan format) or text. A
// local --format would shadow the global flag, which the machine contract
// forbids outside stream commands.
func jsOutputFormat(cmd *cobra.Command) (string, error) {
	if !flagChanged(cmd, "format") {
		return "json", nil
	}
	switch f := strings.ToLower(strings.TrimSpace(globalFormat)); f {
	case "json", "text":
		return f, nil
	default:
		return "", usageErrorf("js supports --format json (default) or text, not %q", strings.TrimSpace(globalFormat))
	}
}

// jsEvalItem is the -j result of `vigolium js`: the script's return value as
// JSON (null when it returned undefined or null).
type jsEvalItem struct {
	Value json.RawMessage `json:"value"`
}

// emitJSEvalResult wraps the script's JSON-stringified return value as
// items:[{"value": …}]. --format is the human/raw-pipe switch; under -j the
// envelope is the contract, so the value is embedded as JSON, not as a string.
func emitJSEvalResult(cmd *cobra.Command, value string) error {
	raw := json.RawMessage("null")
	if value != "" {
		if json.Valid([]byte(value)) {
			raw = json.RawMessage(value)
		} else {
			// JSON.stringify failed and the VM fell back to String(): keep it, as
			// a string.
			quoted, err := json.Marshal(value)
			if err != nil {
				return err
			}
			raw = quoted
		}
	}
	return emitObject(cmd, "", jsEvalItem{Value: raw})
}

// resolveJsSource determines the JS source from --code, --code-file, or stdin (default).
func resolveJsSource() (string, error) {
	hasCode := jsOpts.code != ""
	hasFile := jsOpts.codeFile != ""

	// Check for conflicting inputs
	if hasCode && hasFile {
		return "", usageErrorf("--code and --code-file are mutually exclusive")
	}

	// --code: inline
	if hasCode {
		return jsOpts.code, nil
	}

	// --code-file: read from file
	if hasFile {
		data, err := os.ReadFile(jsOpts.codeFile)
		if err != nil {
			return "", fmt.Errorf("failed to read file %s: %w", jsOpts.codeFile, err)
		}
		source := string(data)

		// Transpile TypeScript if needed
		if strings.EqualFold(filepath.Ext(jsOpts.codeFile), ".ts") {
			source, err = jsext.TranspileTS(source, jsOpts.codeFile)
			if err != nil {
				return "", fmt.Errorf("TypeScript transpilation failed: %w", err)
			}
		}
		return source, nil
	}

	// Default: read from stdin
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return "", usageErrorf("no input provided; use --code, --code-file, or pipe JS via stdin")
	}

	data, err := readStdin()
	if err != nil {
		return "", fmt.Errorf("failed to read stdin: %w", err)
	}
	if len(data) == 0 {
		return "", fmt.Errorf("empty input from stdin")
	}
	return string(data), nil
}

// setupJsHTTPStack creates a lightweight HTTP requester for the JS command.
func setupJsHTTPStack(settings *config.Settings) (*http.Requester, func(), error) {
	httpOpts := types.DefaultOptions()
	httpOpts.Timeout = globalTimeout
	httpOpts.ProxyURL = globalProxy
	httpOpts.Verbose = globalVerbose
	httpOpts.Debug = globalDebug
	httpOpts.DumpTraffic = globalDumpTraffic

	if err := network.Init(httpOpts); err != nil {
		return nil, nil, fmt.Errorf("failed to initialize network: %w", err)
	}

	dedupMgr := dedup.NewManager()
	svc := &services.Services{
		Options:      httpOpts,
		DedupManager: dedupMgr,
	}

	hostLimiter := hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{
		MaxPerHost:    httpOpts.MaxPerHost,
		MaxEntries:    1000,
		EvictAfter:    30 * time.Second,
		EvictInterval: 10 * time.Second,
	})
	svc.HostLimiter = hostLimiter

	requester, err := http.NewRequester(httpOpts, svc)
	if err != nil {
		dedupMgr.Close()
		_ = hostLimiter.Close()
		return nil, nil, fmt.Errorf("failed to create HTTP requester: %w", err)
	}

	cleanup := func() {
		dedupMgr.Close()
		_ = hostLimiter.Close()
	}

	return requester, cleanup, nil
}

// evalWithTimeout runs JS code with a timeout and optional TARGET variable.
func evalWithTimeout(source string, opts jsext.APIOptions, target string, timeout time.Duration) jsext.EvalResult {
	type result struct {
		res jsext.EvalResult
	}

	done := make(chan result, 1)
	vm := sobek.New()

	go func() {
		// Set up module.exports (CommonJS compat)
		exports := vm.NewObject()
		module := vm.NewObject()
		_ = module.Set("exports", exports)
		_ = vm.Set("module", module)
		_ = vm.Set("exports", exports)

		// Set TARGET variable if provided
		if target != "" {
			_ = vm.Set("TARGET", target)
		}

		// Install vigolium.* APIs
		jsext.SetupAPI(vm, opts)

		// Execute the script
		val, err := vm.RunString(source)
		if err != nil {
			done <- result{jsext.EvalResult{Error: err}}
			return
		}

		// If result is undefined or null, return empty value
		if val == nil || sobek.IsUndefined(val) || sobek.IsNull(val) {
			done <- result{jsext.EvalResult{}}
			return
		}

		// JSON.stringify the return value
		stringify, err := vm.RunString("JSON.stringify")
		if err != nil {
			done <- result{jsext.EvalResult{Error: err}}
			return
		}

		fn, ok := sobek.AssertFunction(stringify)
		if !ok {
			done <- result{jsext.EvalResult{Value: val.String()}}
			return
		}

		jsonVal, err := fn(sobek.Undefined(), val)
		if err != nil {
			done <- result{jsext.EvalResult{Value: val.String()}}
			return
		}

		done <- result{jsext.EvalResult{Value: jsonVal.String()}}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	select {
	case r := <-done:
		return r.res
	case <-ctx.Done():
		// Interrupt the VM to stop execution
		vm.Interrupt("execution timeout exceeded")
		return jsext.EvalResult{Error: fmt.Errorf("execution timed out after %s", timeout)}
	}
}
