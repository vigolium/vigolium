package responsechain

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/projectdiscovery/utils/conversion"
	"github.com/projectdiscovery/utils/sync/sizedpool"
	"golang.org/x/net/html"
)

const (
	// DefaultBufferSize is the default size of bytes buffer used for response
	// body storage.
	//
	// Use [SetBufferSize] to adjust the size.
	DefaultBufferSize = int64(10000)

	// DefaultMaxBodySize is the default maximum size of HTTP response body to
	// read.
	//
	// Responses larger than this will be truncated.
	DefaultMaxBodySize = 15 * 1024 * 1024 // 15 MB

	// DefaultMaxLargeBuffers is the maximum number of buffers at [maxBodyRead]
	// size that will be kept in the pool.
	//
	// This prevents pool pollution from accumulating many large buffers while
	// still allowing buffer reuse during burst workloads (e.g., nuclei scans
	// with compression bombs). Excess large buffers are discarded and handled
	// by GC.
	//
	// Default of 20 balances memory usage (~300MB max for large buffers) with
	// performance for typical concurrent workloads.
	//
	// Tuning:
	// - Increase for higher concurrency workloads (e.g., 50+ concurrent reqs)
	// - Decrease for memory-constrained environments (min. 10 recommended)
	//
	// Use [SetMaxLargeBuffers] to adjust the size.
	DefaultMaxLargeBuffers = 20

	// largeBufferThreshold defines when a buffer is considered "large"
	// Buffers >= this size are subject to maxLargeBuffers limiting.
	//
	// Set to 512KB to balance between:
	// - Allowing small-medium responses (< 512KB) to be freely pooled
	// - Limiting accumulation of larger buffers (>= 512KB)
	//
	// This threshold works well for web scanning where:
	// - Most HTML pages are < 200KB (freely pooled)
	// - Medium responses 200-500KB (freely pooled)
	// - Large responses/APIs >= 512KB (limited pooling)
	largeBufferThreshold = 512 * 1024 // 512 KB
)

var (
	bufferSize      = DefaultBufferSize
	maxLargeBuffers = DefaultMaxLargeBuffers
)

// SetBufferSize sets the size of bytes buffer used for response body storage.
//
// Changing the size will reset the buffer pool.
//
// If size is less than 1000, it will be set to 1000.
func SetBufferSize(size int64) {
	if size < 1000 {
		size = 1000
	}
	bufferSize = size

	resetBuffer()
}

// SetMaxLargeBuffers adjusts the maximum number of large buffers that can be
// pooled.
//
// This should be called before making HTTP requests. Changing the limit will
// drain existing pooled buffers to ensure clean state.
//
// If max is less than [DefaultMaxLargeBuffers], it will be set to
// [DefaultMaxLargeBuffers].
func SetMaxLargeBuffers(maxBuffers int) {
	if maxLargeBuffers < DefaultMaxLargeBuffers {
		maxLargeBuffers = DefaultMaxLargeBuffers
	}

	resetBuffer()
}

// use buffer pool for storing response body
// and reuse it for each request
var bufPool *sizedpool.SizedPool[*bytes.Buffer]

func ChangePoolSize(x int64) error {
	return bufPool.Vary(context.Background(), x)
}

func GetPoolSize() int64 {
	return bufPool.Size()
}

// largeBufferSem limits the number of large buffers in the pool
var largeBufferSem chan struct{}

func setLargeBufferSemSize(size int) {
	largeBufferSem = make(chan struct{}, size)
}

func init() {
	var p = &sync.Pool{
		New: func() any {
			// The Pool's New function should generally only return pointer
			// types, since a pointer can be put into the return interface
			// value without an allocation:
			return new(bytes.Buffer)
		},
	}
	var err error
	bufPool, err = sizedpool.New(
		sizedpool.WithPool[*bytes.Buffer](p),
		sizedpool.WithSize[*bytes.Buffer](bufferSize),
	)
	if err != nil {
		panic(err)
	}

	setLargeBufferSemSize(maxLargeBuffers)
}

// getBuffer returns a buffer from the pool
func getBuffer() *bytes.Buffer {
	buff, _ := bufPool.Get(context.Background())

	if buff.Cap() >= largeBufferThreshold {
		select {
		case <-largeBufferSem:
		default:
			// Semaphore wasn't held (shouldn't happen, but handle gracefully)
		}
	}

	return buff
}

// putBuffer returns a buffer to the pool for reuse.
//
// Buffers larger than [DefaultMaxBodySize] are discarded.
// Buffers larger than or equal to largeBufferThreshold are subject to
// maxLargeBuffers limiting.
//
// TODO(dwisiswant0): Current threshold is global. Consider making it
// configurable per instance (via [ResponseChain.maxBodySize]) if needed.
// The current implementation is to prevents memory bloat in typical use-cases.
// And the pool is shared, so per-instance thresholds might cause confusion.
func putBuffer(buf *bytes.Buffer) {
	capacity := buf.Cap()
	if capacity > DefaultMaxBodySize {
		return
	}

	buf.Reset()

	if capacity >= largeBufferThreshold {
		select {
		case largeBufferSem <- struct{}{}:
			bufPool.Put(buf)
		default:
			// NOTE(dwisiswant0): Pool is full of large buffers, discard this
			// one. It will be GC'ed, preventing memory accumulation.
		}
		return
	}

	// Small buffers are always pooled
	bufPool.Put(buf)
}

// resetBuffer drains all buffers from the pool.
// This ensures clean state when pool configuration changes.
func resetBuffer() {
	for range maxLargeBuffers {
		buf, err := bufPool.Get(context.Background())
		if err != nil || buf == nil {
			break
		}
	}

	setLargeBufferSemSize(maxLargeBuffers)
}

// Performance Notes:
// do not use http.Response once we create ResponseChain from it
// as this reuses buffers and saves allocations and also drains response
// body automatically.
// In required cases it can be used but should never be used for anything
// related to response body.
// Bytes.Buffer returned by getters should not be used and are only meant for convinience
// purposes like .String() or .Bytes() calls.
// Remember to call Close() on ResponseChain once you are done with it.

// ResponseChain is a response chain for a http request
// on every call to previous it returns the previous response
// if it was redirected.
type ResponseChain struct {
	headers     *bytes.Buffer
	body        *bytes.Buffer
	resp        *http.Response
	reloaded    bool // if response was reloaded to its previous redirect
	maxBodySize int64

	// Cached HTML parsing (computed on demand via sync.Once)
	htmlOnce   sync.Once
	parsedHTML *html.Node
	htmlErr    error
}

// NewResponseChain creates a new response chain for a http request
// with a maximum body size.
//
// If maxBody is less than or equal to zero, it defaults to [DefaultMaxBodySize].
func NewResponseChain(resp *http.Response, maxBody int64) *ResponseChain {
	if maxBody <= 0 {
		maxBody = int64(DefaultMaxBodySize)
	}

	if resp.Body != nil {
		resp.Body = http.MaxBytesReader(nil, resp.Body, maxBody)
	}

	return &ResponseChain{
		headers:     getBuffer(),
		body:        getBuffer(),
		resp:        resp,
		maxBodySize: maxBody,
	}
}

// Headers returns the current response headers buffer in the chain.
//
// Warning: The returned buffer is pooled and must not be modified or retained.
// Prefer HeadersBytes() or HeadersString() for safe read-only access.
func (r *ResponseChain) Headers() *bytes.Buffer {
	return r.headers
}

// HeadersBytes returns the current response headers as byte slice in the chain.
//
// The returned slice is valid only until Close() is called.
func (r *ResponseChain) HeadersBytes() []byte {
	return r.headers.Bytes()
}

// HeadersString returns the current response headers as string in the chain.
//
// The returned string is a copy and remains valid even after Close() is called.
func (r *ResponseChain) HeadersString() string {
	return r.headers.String()
}

// Body returns the current response body buffer in the chain.
//
// Warning: The returned buffer is pooled and must not be modified or retained.
// Prefer BodyBytes() or BodyString() for safe read-only access.
func (r *ResponseChain) Body() *bytes.Buffer {
	return r.body
}

// BodyBytes returns the current response body as byte slice in the chain.
//
// The returned slice is valid only until Close() is called.
func (r *ResponseChain) BodyBytes() []byte {
	return r.body.Bytes()
}

// BodyString returns the current response body as string in the chain.
//
// The returned string is a copy and remains valid even after Close() is called.
func (r *ResponseChain) BodyString() string {
	return r.body.String()
}

// FullResponse returns a new buffer containing headers+body.
//
// Warning: The caller is responsible for managing the returned buffer's
// lifecycle.
// The buffer should be returned to the pool using putBuffer() or allowed to be
// garbage collected. Prefer FullResponseBytes() or FullResponseString() for
// safe read-only access.
func (r *ResponseChain) FullResponse() *bytes.Buffer {
	buf := getBuffer()
	buf.Write(r.headers.Bytes())
	buf.Write(r.body.Bytes())

	return buf
}

// FullResponseBytes returns the current response (headers+body) as byte slice.
//
// The returned slice is a copy and remains valid even after Close() is called.
func (r *ResponseChain) FullResponseBytes() []byte {
	size := r.headers.Len() + r.body.Len()
	buf := make([]byte, size)

	copy(buf, r.headers.Bytes())
	copy(buf[r.headers.Len():], r.body.Bytes())

	return buf
}

// FullResponseString returns the current response as string in the chain.
//
// The returned string is a copy and remains valid even after Close() is called.
func (r *ResponseChain) FullResponseString() string {
	return conversion.String(r.FullResponseBytes())
}

// previous updates response pointer to previous response
// if it was redirected and returns true else false
func (r *ResponseChain) Previous() bool {
	if r.resp != nil && r.resp.Request != nil && r.resp.Request.Response != nil {
		r.resp = r.resp.Request.Response
		r.reloaded = true
		return true
	}
	return false
}

// Fill buffers
func (r *ResponseChain) Fill() error {
	r.reset()
	if r.resp == nil {
		return fmt.Errorf("response is nil")
	}

	// load headers
	err := DumpResponseIntoBuffer(r.resp, false, r.headers)
	if err != nil {
		return fmt.Errorf("error dumping response headers: %s", err)
	}

	if r.resp.StatusCode != http.StatusSwitchingProtocols && !r.reloaded {
		// Note about reloaded:
		// this is a known behaviour existing from earlier version
		// when redirect is followed and operators are executed on all redirect chain
		// body of those requests is not available since its already been redirected
		// This is not a issue since redirect happens with empty body according to RFC
		// but this may be required sometimes
		// Solution: Manual redirect using dynamic matchers or hijack redirected responses
		// at transport level at replace with bytes buffer and then use it

		// load body
		err = readNNormalizeRespBody(r, r.body)
		if err != nil {
			return fmt.Errorf("error reading response body: %s", err)
		}

		// response body should not be used anymore
		// drain and close
		DrainResponseBody(r.resp)
	}

	return nil
}

// Close the response chain and releases the buffers.
func (r *ResponseChain) Close() {
	if r.headers != nil {
		putBuffer(r.headers)
		r.headers = nil
	}

	if r.body != nil {
		putBuffer(r.body)
		r.body = nil
	}
}

// Has returns true if the response chain has a response
func (r *ResponseChain) Has() bool {
	return r.resp != nil
}

// Request is request of current response
func (r *ResponseChain) Request() *http.Request {
	if r.resp == nil {
		return nil
	}
	return r.resp.Request
}

// Response is response of current response
func (r *ResponseChain) Response() *http.Response {
	return r.resp
}

// reset without releasing the buffers
// useful for redirect chain
func (r *ResponseChain) reset() {
	r.headers.Reset()
	r.body.Reset()
}

// =============================================================================
// HTML Parsing Methods
// =============================================================================

// ParseHTML parses the response body as HTML and returns the parsed DOM tree.
// The result is cached for subsequent calls.
// Returns nil and error if parsing fails or body is not HTML.
func (r *ResponseChain) ParseHTML() (*html.Node, error) {
	r.htmlOnce.Do(func() {
		if r.body == nil || r.body.Len() == 0 {
			r.htmlErr = fmt.Errorf("empty body")
			return
		}

		r.parsedHTML, r.htmlErr = html.Parse(bytes.NewReader(r.body.Bytes()))
	})
	return r.parsedHTML, r.htmlErr
}

// HTML returns the cached parsed HTML DOM tree.
// Returns nil if not yet parsed or parsing failed.
// Call ParseHTML() first to ensure parsing is done.
func (r *ResponseChain) HTML() *html.Node {
	return r.parsedHTML
}
