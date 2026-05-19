package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/grafana/sobek"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
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
	format   string
}

var jsCmd = &cobra.Command{
	Use:   "js",
	Short: "Execute JavaScript with the full vigolium.* API",
	Long: `Run JavaScript code with access to the full vigolium.* API surface.
Reads from stdin by default, or use --code / --code-file for inline / file input.`,
	RunE: runJsCmd,
}

func init() {
	rootCmd.AddCommand(jsCmd)

	flags := jsCmd.Flags()
	flags.StringVar(&jsOpts.code, "code", "", "Inline JavaScript code to execute")
	flags.StringVar(&jsOpts.codeFile, "code-file", "", "Path to JavaScript/TypeScript file to execute")
	flags.StringVar(&jsOpts.target, "target", "", "Set TARGET variable in JS scope (URL)")
	flags.DurationVar(&jsOpts.timeout, "timeout", 30*time.Second, "Execution timeout")
	flags.StringVar(&jsOpts.format, "format", "json", "Output format: json or text")
}

func runJsCmd(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	// Resolve JS source
	source, err := resolveJsSource()
	if err != nil {
		return err
	}

	// Load settings
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		settings = config.DefaultSettings()
	}

	// Build API options
	opts := jsext.APIOptions{
		ScriptID:    "js",
		ConfigVars:  settings.DynamicAssessment.Extensions.Variables,
		AllowExec:   settings.DynamicAssessment.Extensions.AllowExec,
		SandboxDir:  config.ExpandPath(settings.DynamicAssessment.Extensions.SandboxDir),
		ExecTimeout: settings.DynamicAssessment.Extensions.ExecTimeout(),
	}

	// Set up optional database
	db, err := getDB()
	if err == nil && db != nil {
		defer closeDatabaseOnExit()
		repo := database.NewRepository(db)
		opts.Repository = repo

		// Set project UUID
		projUUID, projErr := resolveProjectUUID()
		if projErr == nil {
			opts.ProjectUUID = projUUID
		}
	}

	// Set up scope if configured
	if settings.Scope.Host.Include != nil || settings.Scope.Path.Include != nil {
		matcher := config.NewScopeMatcher(settings.Scope)
		opts.ScopeMatcher = matcher
		opts.ScopeConfig = &settings.Scope
	}

	// Set up HTTP client
	httpRequester, cleanup, err := setupJsHTTPStack(settings)
	if err == nil {
		defer cleanup()
		opts.HTTPClient = httpRequester
	}

	// Create VM and execute with timeout
	result := evalWithTimeout(source, opts, jsOpts.target, jsOpts.timeout)
	if result.Error != nil {
		return fmt.Errorf("js error: %w", result.Error)
	}

	if result.Value != "" {
		if jsOpts.format == "text" {
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

// resolveJsSource determines the JS source from --code, --code-file, or stdin (default).
func resolveJsSource() (string, error) {
	hasCode := jsOpts.code != ""
	hasFile := jsOpts.codeFile != ""

	// Check for conflicting inputs
	if hasCode && hasFile {
		return "", fmt.Errorf("--code and --code-file are mutually exclusive")
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
		return "", fmt.Errorf("no input provided; use --code, --code-file, or pipe JS via stdin")
	}

	data, err := io.ReadAll(os.Stdin)
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
