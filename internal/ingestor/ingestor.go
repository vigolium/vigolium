package ingestor

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sourcegraph/conc"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"go.uber.org/zap"
)

// Options holds ingestor configuration.
type Options struct {
	// Server
	ServerURL string
	APIKey    string

	// Input
	Input       string
	InputFormat string
	// TargetFiles are additional URL-list files (-T/--target-file, repeatable).
	// Their lines are read and submitted alongside Input/stdin for the urls and
	// nuclei formats.
	TargetFiles []string

	// Spec Target
	TargetURL      string
	UseSpecServers bool

	// Spec Options
	Headers      []string
	Variables    []string
	DefaultParam string

	// Submission
	Concurrency int
	RateLimit   int

	// Modules
	EnableModules []string
	WebhookURL    string
}

// DefaultOptions returns default ingestor options.
func DefaultOptions() *Options {
	return &Options{
		Concurrency:  10,
		RateLimit:    100,
		Input:        "-",
		InputFormat:  "urls",
		DefaultParam: "1",
	}
}

// RunStats contains execution statistics.
type RunStats struct {
	Submitted int64
	Errors    int64
	Elapsed   time.Duration
}

// Run executes the ingestor with given options.
func Run(ctx context.Context, opts *Options) (RunStats, error) {
	// Validate required fields
	if opts.ServerURL == "" {
		return RunStats{}, fmt.Errorf("server URL is required")
	}

	// Validate server URL has scheme
	if !strings.HasPrefix(opts.ServerURL, "http://") && !strings.HasPrefix(opts.ServerURL, "https://") {
		return RunStats{}, fmt.Errorf("server URL must include scheme (http:// or https://)")
	}

	if opts.APIKey == "" {
		return RunStats{}, fmt.Errorf("API key is required")
	}

	// Create client
	client := NewClient(opts.ServerURL, opts.APIKey, opts.RateLimit)

	startTime := time.Now()
	var submitted, failed atomic.Int64

	// At least one worker: inputs are read on this goroutine, which would block
	// forever on a full request channel with nobody draining it.
	workers := max(opts.Concurrency, 1)

	// Create request channel
	reqChan := make(chan *IngestRequest, 100)

	// Start workers
	var wg conc.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Go(func() {
			for req := range reqChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				_, err := client.Submit(ctx, req)
				if err != nil {
					failed.Add(1)
					zap.L().Debug("Submit failed", zap.String("url", req.URL), zap.Error(err))
				} else {
					submitted.Add(1)
					zap.L().Debug("Submitted", zap.String("url", req.URL))
				}
			}
		})
	}

	// Input failures are not fatal: the readable sources are still submitted,
	// and the caller is told afterwards.
	inputErr := readInputs(ctx, reqChan, opts)
	close(reqChan)
	wg.Wait()

	stats := RunStats{
		Submitted: submitted.Load(),
		Errors:    failed.Load(),
		Elapsed:   time.Since(startTime),
	}
	if inputErr != nil {
		return stats, fmt.Errorf("ingest input: %w", inputErr)
	}
	return stats, nil
}

// readInputs parses every input source into reqChan and returns the joined
// errors of the sources that could not be read in full. Every parser selects
// on ctx.Done() when sending, so this returns even if the workers stopped.
func readInputs(ctx context.Context, reqChan chan<- *IngestRequest, opts *Options) error {
	if opts.InputFormat == "openapi" || opts.InputFormat == "swagger" {
		// OpenAPI/Swagger handles its own input loading (file or URL)
		return parseSpecInput(ctx, reqChan, opts)
	}
	parse := parseURLsInput
	if opts.InputFormat == "nuclei" {
		parse = parseNucleiInput
	}
	var errs []error
	for _, in := range opts.inputSources() {
		if err := readSource(ctx, in, parse, reqChan, opts); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// readSource opens one input source and runs parse over it.
func readSource(ctx context.Context, in string, parse func(context.Context, io.Reader, chan<- *IngestRequest, *Options) error, reqChan chan<- *IngestRequest, opts *Options) error {
	reader, closer, err := openInput(in)
	if err != nil {
		return fmt.Errorf("open input %s: %w", in, err)
	}
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}
	if err := parse(ctx, reader, reqChan, opts); err != nil {
		return fmt.Errorf("read input %s: %w", in, err)
	}
	return nil
}

// inputSources returns the ordered list of inputs to read for plain URL /
// nuclei ingestion: the primary -i/stdin input (when set) followed by each
// -T/--target-file. An empty Input means "no primary input" (e.g. only -T was
// given with no piped stdin) and is skipped so the run never blocks on a TTY.
func (opts *Options) inputSources() []string {
	srcs := make([]string, 0, len(opts.TargetFiles)+1)
	if opts.Input != "" {
		srcs = append(srcs, opts.Input)
	}
	for _, tf := range opts.TargetFiles {
		if tf != "" {
			srcs = append(srcs, tf)
		}
	}
	return srcs
}

func openInput(input string) (io.Reader, io.Closer, error) {
	if input == "-" {
		return os.Stdin, nil, nil
	}

	file, err := os.Open(input)
	if err != nil {
		return nil, nil, err
	}

	if strings.HasSuffix(input, ".gz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			_ = file.Close()
			return nil, nil, err
		}
		return gzReader, &multiCloser{closers: []io.Closer{gzReader, file}}, nil
	}

	return file, file, nil
}

type multiCloser struct {
	closers []io.Closer
}

func (m *multiCloser) Close() error {
	var lastErr error
	for _, c := range m.closers {
		if err := c.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func parseURLsInput(ctx context.Context, reader io.Reader, reqChan chan<- *IngestRequest, opts *Options) error {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		scanReq := &IngestRequest{
			URL:           line,
			EnableModules: opts.EnableModules,
			WebhookURL:    opts.WebhookURL,
		}

		select {
		case reqChan <- scanReq:
		case <-ctx.Done():
			return nil
		}
	}
	return scanner.Err()
}

// nucleiOutput matches nuclei JSON output format.
type nucleiOutput struct {
	URL     string       `json:"url"`
	Request *requestData `json:"request,omitempty"`
}

type requestData struct {
	Raw string `json:"raw"`
}

// parseNucleiInput forwards nuclei JSON output (a stream of JSON objects).
// It returns the error that ended the read early, if any.
func parseNucleiInput(ctx context.Context, reader io.Reader, reqChan chan<- *IngestRequest, opts *Options) error {
	dec := json.NewDecoder(reader)
	for dec.More() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		var result nucleiOutput
		if err := dec.Decode(&result); err != nil {
			// A value of the wrong type leaves the decoder positioned after
			// that value, so the stream can continue. Anything else (a syntax
			// error, a truncated object) is sticky: Decode returns it forever
			// while More() stays true, so continuing would loop without end.
			var typeErr *json.UnmarshalTypeError
			if errors.As(err, &typeErr) {
				zap.L().Debug("Skipping nuclei record with an unexpected field type", zap.Error(err))
				continue
			}
			return fmt.Errorf("malformed nuclei JSON: %w", err)
		}

		if result.URL == "" {
			continue
		}

		scanReq := &IngestRequest{
			URL:           result.URL,
			EnableModules: opts.EnableModules,
			WebhookURL:    opts.WebhookURL,
		}

		if result.Request != nil && result.Request.Raw != "" {
			scanReq.Request = &IngestRawRequest{Raw: result.Request.Raw}
		}

		select {
		case reqChan <- scanReq:
		case <-ctx.Done():
			return nil
		}
	}
	return nil
}

func parseSpecInput(ctx context.Context, reqChan chan<- *IngestRequest, opts *Options) error {
	// Load spec from file or URL
	data, ext, err := openapi.LoadSpec(opts.Input)
	if err != nil {
		return fmt.Errorf("load spec %s: %w", opts.Input, err)
	}

	// Parse headers
	headers := make(map[string]string)
	for _, h := range opts.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Parse variables
	variables := make(map[string]string)
	for _, v := range opts.Variables {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) == 2 {
			variables[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	serverOpts := openapi.ServerOptions{
		Options: openapi.Options{
			BaseURL:              opts.TargetURL,
			UseSpecServers:       opts.UseSpecServers,
			Headers:              headers,
			Variables:            variables,
			DefaultFallbackValue: opts.DefaultParam,
		},
		EnableModules: opts.EnableModules,
		WebhookURL:    opts.WebhookURL,
	}

	// Callback to send requests — convert ServerScanRequest to IngestRequest
	callback := func(req *openapi.ServerScanRequest) {
		scanReq := &IngestRequest{
			URL:           req.URL,
			Request:       &IngestRawRequest{Raw: req.RawRequest},
			EnableModules: req.EnableModules,
			WebhookURL:    req.WebhookURL,
		}
		select {
		case reqChan <- scanReq:
		case <-ctx.Done():
		}
	}

	// Parse based on format - ParseSwaggerForServer auto-detects version
	if err := openapi.ParseSwaggerForServer(data, ext, serverOpts, callback); err != nil {
		return fmt.Errorf("parse spec %s: %w", opts.Input, err)
	}
	return nil
}
