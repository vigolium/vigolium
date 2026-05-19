package ingestor

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
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
	var submitted, errors atomic.Int64

	// Create request channel
	reqChan := make(chan *IngestRequest, 100)

	// Start workers
	var wg conc.WaitGroup
	for i := 0; i < opts.Concurrency; i++ {
		wg.Go(func() {
			for req := range reqChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				_, err := client.Submit(ctx, req)
				if err != nil {
					errors.Add(1)
					zap.L().Debug("Submit failed", zap.String("url", req.URL), zap.Error(err))
				} else {
					submitted.Add(1)
					zap.L().Debug("Submitted", zap.String("url", req.URL))
				}
			}
		})
	}

	// Parse and send requests
	go func() {
		defer close(reqChan)
		switch opts.InputFormat {
		case "openapi", "swagger":
			// OpenAPI/Swagger handles its own input loading (file or URL)
			parseSpecInput(ctx, reqChan, opts)
		case "nuclei":
			reader, closer, err := openInput(opts.Input)
			if err != nil {
				zap.L().Error("Failed to open input", zap.Error(err))
				return
			}
			if closer != nil {
				defer func() { _ = closer.Close() }()
			}
			parseNucleiInput(ctx, reader, reqChan, opts)
		default: // "urls"
			reader, closer, err := openInput(opts.Input)
			if err != nil {
				zap.L().Error("Failed to open input", zap.Error(err))
				return
			}
			if closer != nil {
				defer func() { _ = closer.Close() }()
			}
			parseURLsInput(ctx, reader, reqChan, opts)
		}
	}()

	// Wait for workers
	wg.Wait()

	return RunStats{
		Submitted: submitted.Load(),
		Errors:    errors.Load(),
		Elapsed:   time.Since(startTime),
	}, nil
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

func parseURLsInput(ctx context.Context, reader io.Reader, reqChan chan<- *IngestRequest, opts *Options) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
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
			return
		}
	}
}

// nucleiOutput matches nuclei JSON output format.
type nucleiOutput struct {
	URL     string       `json:"url"`
	Request *requestData `json:"request,omitempty"`
}

type requestData struct {
	Raw string `json:"raw"`
}

func parseNucleiInput(ctx context.Context, reader io.Reader, reqChan chan<- *IngestRequest, opts *Options) {
	dec := json.NewDecoder(reader)
	for dec.More() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		var result nucleiOutput
		if err := dec.Decode(&result); err != nil {
			zap.L().Debug("Failed to decode JSON", zap.Error(err))
			continue
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
			return
		}
	}
}

func parseSpecInput(ctx context.Context, reqChan chan<- *IngestRequest, opts *Options) {
	// Load spec from file or URL
	data, ext, err := openapi.LoadSpec(opts.Input)
	if err != nil {
		zap.L().Error("Failed to load spec", zap.String("input", opts.Input), zap.Error(err))
		return
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
		zap.L().Error("Failed to parse spec", zap.Error(err))
	}
}
