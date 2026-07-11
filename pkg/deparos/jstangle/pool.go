package jstangle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultWorkerMaxJobs   = 100
	defaultWorkerMaxRSS    = int64(1024 * 1024 * 1024)
	defaultWorkerStartTime = 20 * time.Second
	workerResponseOverhead = int64(2 * 1024 * 1024)
)

type workerPoolConfig struct {
	Count        int
	MaxJobs      int
	MaxRSSBytes  int64
	StartTimeout time.Duration
}

type workerHelloRecord struct {
	Type         string       `json:"type"`
	WorkerID     string       `json:"workerId"`
	PID          int          `json:"pid"`
	Capabilities Capabilities `json:"capabilities"`
}

type workerLimits struct {
	MaxRequests      int   `json:"maxRequests"`
	MaxASTNodes      int   `json:"maxAstNodes"`
	MaxOutputBytes   int64 `json:"maxOutputBytes"`
	MaxArtifactBytes int64 `json:"maxArtifactBytes"`
	DeadlineMS       int64 `json:"deadlineMs"`
}

type workerAnalyzeRequest struct {
	Type          string          `json:"type"`
	ID            string          `json:"id"`
	Profile       AnalysisProfile `json:"profile"`
	SourceURL     string          `json:"sourceUrl,omitempty"`
	Filename      string          `json:"filename,omitempty"`
	MediaType     string          `json:"mediaType,omitempty"`
	ArtifactDir   string          `json:"artifactDir"`
	Beautify      bool            `json:"beautify,omitempty"`
	ContentLength int             `json:"contentLength"`
	Limits        workerLimits    `json:"limits"`
}

type workerResultRecord struct {
	Type       string            `json:"type"`
	ID         string            `json:"id"`
	Result     *AnalysisResultV2 `json:"result,omitempty"`
	Completion ScanCompletion    `json:"completion"`
	Error      *Diagnostic       `json:"error,omitempty"`
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	original := len(p)
	remaining := b.max - b.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.buf.Write(p)
	}
	return original, nil
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type framedWorker struct {
	id       string
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	stdout   io.ReadCloser
	stderr   *lockedBuffer
	done     chan struct{}
	waitErr  error
	jobs     atomic.Int64
	mu       sync.Mutex
	stopOnce sync.Once
}

func (w *framedWorker) exited() bool {
	select {
	case <-w.done:
		return true
	default:
		return false
	}
}

func (w *framedWorker) stop(graceful bool) {
	w.stopOnce.Do(func() {
		if !graceful {
			if w.cmd.Process != nil {
				_ = w.cmd.Process.Kill()
			}
			select {
			case <-w.done:
			case <-time.After(2 * time.Second):
			}
			return
		}
		w.mu.Lock()
		if !w.exited() {
			payload, _ := json.Marshal(map[string]string{"type": "shutdown"})
			_ = writeLengthFrame(w.stdin, payload, maxControlFrameBytes)
			_ = w.stdin.Close()
		}
		w.mu.Unlock()

		select {
		case <-w.done:
			return
		case <-time.After(2 * time.Second):
		}
		if w.cmd.Process != nil {
			_ = w.cmd.Process.Kill()
		}
		select {
		case <-w.done:
		case <-time.After(2 * time.Second):
		}
	})
}

type WorkerPool struct {
	scanner *Scanner
	config  workerPoolConfig

	ctx    context.Context
	cancel context.CancelFunc

	startOnce sync.Once
	startErr  error
	available chan *framedWorker

	mu      sync.Mutex
	workers map[*framedWorker]struct{}
	closed  bool
	seq     atomic.Uint64

	restarts atomic.Int64
	retries  atomic.Int64
	active   atomic.Int64
	started  atomic.Int64
}

type WorkerPoolStats struct {
	Workers     int
	Jobs        int
	JobsStarted int64
	ActiveJobs  int64
	Restarts    int64
	Retries     int64
	RSSBytes    int64
}

func newWorkerPool(scanner *Scanner, config workerPoolConfig) *WorkerPool {
	if config.Count <= 0 {
		config.Count = 1
	}
	if config.MaxJobs <= 0 {
		config.MaxJobs = defaultWorkerMaxJobs
	}
	if config.MaxRSSBytes <= 0 {
		config.MaxRSSBytes = defaultWorkerMaxRSS
	}
	if config.StartTimeout <= 0 {
		config.StartTimeout = defaultWorkerStartTime
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &WorkerPool{
		scanner: scanner, config: config, ctx: ctx, cancel: cancel,
		available: make(chan *framedWorker, config.Count), workers: make(map[*framedWorker]struct{}),
	}
}

func (p *WorkerPool) ensureStarted() error {
	p.startOnce.Do(func() {
		for i := 0; i < p.config.Count; i++ {
			worker, err := p.startWorker()
			if err != nil {
				p.startErr = err
				p.stopAll(false)
				return
			}
			p.available <- worker
		}
	})
	return p.startErr
}

func (p *WorkerPool) startWorker() (*framedWorker, error) {
	binary, err := p.scanner.getBinary()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(p.ctx, binary.Path, "--worker")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("create jstangle worker stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("create jstangle worker stdout: %w", err)
	}
	stderr := &lockedBuffer{max: 64 * 1024}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, fmt.Errorf("start jstangle worker: %w", err)
	}
	worker := &framedWorker{cmd: cmd, stdin: stdin, stdout: stdout, stderr: stderr, done: make(chan struct{})}
	go func() {
		worker.waitErr = cmd.Wait()
		close(worker.done)
	}()

	type helloOutcome struct {
		hello workerHelloRecord
		err   error
	}
	helloCh := make(chan helloOutcome, 1)
	go func() {
		payload, readErr := readLengthFrame(stdout, maxControlFrameBytes)
		if readErr != nil {
			helloCh <- helloOutcome{err: readErr}
			return
		}
		var hello workerHelloRecord
		if unmarshalErr := json.Unmarshal(payload, &hello); unmarshalErr != nil {
			helloCh <- helloOutcome{err: unmarshalErr}
			return
		}
		helloCh <- helloOutcome{hello: hello}
	}()

	select {
	case outcome := <-helloCh:
		if outcome.err != nil {
			worker.stop(false)
			return nil, fmt.Errorf("%w: worker hello: %w", ErrIncompleteOutput, outcome.err)
		}
		caps := outcome.hello.Capabilities
		if outcome.hello.Type != "workerHello" || outcome.hello.WorkerID == "" ||
			caps.ProtocolVersion != ProtocolVersion || caps.SourceHash == "" {
			worker.stop(false)
			return nil, fmt.Errorf("%w: invalid worker hello", ErrIncompatibleProtocol)
		}
		expected, capsErr := p.scanner.Capabilities()
		if capsErr != nil || expected.SourceHash != caps.SourceHash {
			worker.stop(false)
			return nil, fmt.Errorf("%w: worker source hash mismatch", ErrIncompatibleProtocol)
		}
		worker.id = outcome.hello.WorkerID
	case <-time.After(p.config.StartTimeout):
		worker.stop(false)
		return nil, fmt.Errorf("%w: worker startup timeout", ErrScanFailed)
	case <-p.ctx.Done():
		worker.stop(false)
		return nil, ErrServiceClosed
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		worker.stop(false)
		return nil, ErrServiceClosed
	}
	p.workers[worker] = struct{}{}
	p.mu.Unlock()
	return worker, nil
}

func (p *WorkerPool) Capabilities() (*Capabilities, error) {
	return p.scanner.Capabilities()
}

func (p *WorkerPool) Checksum() string { return p.scanner.Checksum() }

func (p *WorkerPool) Stats() WorkerPoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	stats := WorkerPoolStats{
		Workers: len(p.workers), JobsStarted: p.started.Load(), ActiveJobs: p.active.Load(),
		Restarts: p.restarts.Load(), Retries: p.retries.Load(),
	}
	for worker := range p.workers {
		stats.Jobs += int(worker.jobs.Load())
		if worker.cmd != nil && worker.cmd.Process != nil && !worker.exited() {
			stats.RSSBytes += workerRSSBytes(worker.cmd.Process.Pid)
		}
	}
	return stats
}

func (p *WorkerPool) ScanWithOptions(ctx context.Context, content []byte, options ScanOptions) (*ScanResult, error) {
	if err := p.ensureStarted(); err != nil {
		return nil, err
	}
	options = normalizeScanOptions(options)
	if len(content) > options.MaxInputBytes {
		return nil, fmt.Errorf("%w: input=%d limit=%d", ErrInputTooLarge, len(content), options.MaxInputBytes)
	}
	for attempt := 0; attempt < 2; attempt++ {
		worker, err := p.acquire(ctx)
		if err != nil {
			return nil, err
		}
		result, completed, runErr := p.runCancelable(ctx, worker, content, options)
		if completed && !worker.exited() {
			p.release(worker)
			return result, runErr
		}
		p.retire(worker, false)
		replaceErr := p.replaceWorker()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if replaceErr != nil {
			return nil, fmt.Errorf("%w: %w; replacement: %w", ErrScanFailed, runErr, replaceErr)
		}
		if attempt == 0 {
			p.retries.Add(1)
			continue
		}
		return nil, runErr
	}
	return nil, ErrScanFailed
}

type workerRunOutcome struct {
	result    *ScanResult
	completed bool
	err       error
}

func (p *WorkerPool) runCancelable(ctx context.Context, worker *framedWorker, content []byte, options ScanOptions) (*ScanResult, bool, error) {
	p.started.Add(1)
	p.active.Add(1)
	defer p.active.Add(-1)
	done := make(chan workerRunOutcome, 1)
	go func() {
		result, completed, err := p.runJob(worker, content, options)
		done <- workerRunOutcome{result: result, completed: completed, err: err}
	}()
	select {
	case outcome := <-done:
		return outcome.result, outcome.completed, outcome.err
	case <-ctx.Done():
		worker.stop(false)
		<-done
		return nil, false, ctx.Err()
	case <-p.ctx.Done():
		worker.stop(false)
		<-done
		return nil, false, ErrServiceClosed
	}
}

func (p *WorkerPool) runJob(worker *framedWorker, content []byte, options ScanOptions) (*ScanResult, bool, error) {
	started := time.Now()
	jobDir, err := os.MkdirTemp("", "jstangle-job-*")
	if err != nil {
		return nil, false, fmt.Errorf("create jstangle job directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(jobDir) }()

	id := fmt.Sprintf("job-%d", p.seq.Add(1))
	request := workerAnalyzeRequest{
		Type: "analyze", ID: id, Profile: options.Profile, SourceURL: options.SourceURL,
		Filename: options.Filename, MediaType: options.MediaType, ArtifactDir: jobDir,
		Beautify: options.Beautify, ContentLength: len(content),
		Limits: workerLimits{
			MaxRequests: options.MaxRequests, MaxASTNodes: options.MaxASTNodes, MaxOutputBytes: options.MaxOutputBytes,
			MaxArtifactBytes: options.MaxArtifactBytes, DeadlineMS: options.Deadline.Milliseconds(),
		},
	}
	metadata, err := json.Marshal(request)
	if err != nil {
		return nil, false, err
	}

	worker.mu.Lock()
	defer worker.mu.Unlock()
	if worker.exited() {
		return nil, false, fmt.Errorf("%w: worker exited: %w; stderr: %s", ErrScanFailed, worker.waitErr, worker.stderr.String())
	}
	if err := writeLengthFrame(worker.stdin, metadata, maxControlFrameBytes); err != nil {
		return nil, false, fmt.Errorf("%w: write worker request: %w", ErrScanFailed, err)
	}
	if err := writeLengthFrame(worker.stdin, content, int64(options.MaxInputBytes)); err != nil {
		return nil, false, fmt.Errorf("%w: write worker content: %w", ErrScanFailed, err)
	}
	payload, err := readLengthFrame(worker.stdout, options.MaxOutputBytes+workerResponseOverhead)
	if err != nil {
		return nil, false, fmt.Errorf("%w: read worker response: %w; stderr: %s", ErrIncompleteOutput, err, worker.stderr.String())
	}
	var response workerResultRecord
	if err := json.Unmarshal(payload, &response); err != nil {
		return nil, false, fmt.Errorf("%w: decode worker response: %w", ErrIncompleteOutput, err)
	}
	if response.Type != "workerResult" || response.ID != id || response.Completion.ScanID != id ||
		response.Completion.ProtocolVersion != ProtocolVersion {
		return nil, false, fmt.Errorf("%w: inconsistent worker response", ErrIncompleteOutput)
	}
	worker.jobs.Add(1)
	if response.Completion.Status == "failed" || response.Completion.Status == "cancelled" {
		message := ""
		if response.Error != nil {
			message = response.Error.Message
		}
		return nil, true, fmt.Errorf("%w: status=%s reason=%s %s", ErrScanFailed,
			response.Completion.Status, response.Completion.ReasonCode, message)
	}
	if response.Result == nil || response.Result.SchemaVersion != 2 || response.Result.JobID != id {
		return nil, false, fmt.Errorf("%w: missing analysis result", ErrIncompleteOutput)
	}
	caps, err := p.scanner.Capabilities()
	if err != nil || response.Result.Tool.SourceHash != caps.SourceHash {
		return nil, false, fmt.Errorf("%w: result source hash mismatch", ErrIncompatibleProtocol)
	}
	result := scanResultFromAnalysis(response.Result, &response.Completion)
	if err := loadArtifacts(result, jobDir, options.MaxArtifactBytes); err != nil {
		return nil, true, err
	}
	result.ScanDuration = time.Since(started)
	result.BytesScanned = len(content)
	return result, true, nil
}

func scanResultFromAnalysis(analysis *AnalysisResultV2, completion *ScanCompletion) *ScanResult {
	result := &ScanResult{
		Requests: []ExtractedRequest{}, Analysis: analysis, Completion: completion,
		Diagnostics: append([]Diagnostic(nil), analysis.Diagnostics...),
		Artifacts:   append([]ArtifactDescriptor(nil), analysis.Artifacts...),
	}
	for _, record := range analysis.Records {
		appendAnalysisRecord(result, record)
	}
	return result
}

func (p *WorkerPool) acquire(ctx context.Context) (*framedWorker, error) {
	select {
	case worker := <-p.available:
		return worker, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.ctx.Done():
		return nil, ErrServiceClosed
	}
}

func (p *WorkerPool) release(worker *framedWorker) {
	if worker.jobs.Load() >= int64(p.config.MaxJobs) || worker.exited() || workerRSSBytes(worker.cmd.Process.Pid) > p.config.MaxRSSBytes {
		p.retire(worker, true)
		_ = p.replaceWorker()
		return
	}
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		worker.stop(true)
		return
	}
	select {
	case p.available <- worker:
	case <-p.ctx.Done():
		worker.stop(true)
	}
}

func (p *WorkerPool) retire(worker *framedWorker, graceful bool) {
	p.mu.Lock()
	if _, ok := p.workers[worker]; ok {
		delete(p.workers, worker)
		p.restarts.Add(1)
	}
	p.mu.Unlock()
	worker.stop(graceful)
}

func (p *WorkerPool) replaceWorker() error {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return ErrServiceClosed
	}
	worker, err := p.startWorker()
	if err != nil {
		return err
	}
	select {
	case p.available <- worker:
		return nil
	case <-p.ctx.Done():
		p.retire(worker, false)
		return ErrServiceClosed
	}
}

func workerRSSBytes(pid int) int64 {
	if pid <= 0 {
		return 0
	}
	switch runtime.GOOS {
	case "linux":
		data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "statm"))
		if err != nil {
			return 0
		}
		fields := strings.Fields(string(data))
		if len(fields) < 2 {
			return 0
		}
		pages, _ := strconv.ParseInt(fields[1], 10, 64)
		return pages * int64(os.Getpagesize())
	case "darwin":
		output, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output()
		if err != nil {
			return 0
		}
		kilobytes, _ := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64)
		return kilobytes * 1024
	default:
		return 0
	}
}

func (p *WorkerPool) stopAll(graceful bool) {
	p.mu.Lock()
	workers := make([]*framedWorker, 0, len(p.workers))
	for worker := range p.workers {
		workers = append(workers, worker)
		delete(p.workers, worker)
	}
	p.mu.Unlock()
	for _, worker := range workers {
		worker.stop(graceful)
	}
}

func (p *WorkerPool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()
	p.stopAll(true)
	p.cancel()
	return nil
}
