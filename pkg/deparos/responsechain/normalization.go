package responsechain

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zlib"
	"github.com/klauspost/compress/zstd"
	"github.com/pkg/errors"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"

	stringsutil "github.com/projectdiscovery/utils/strings"
)

const (
	// DefaultChunkSize defines the default chunk size for reading response
	// bodies.
	//
	// Use [SetChunkSize] to adjust the size.
	DefaultChunkSize = 32 * 1024 // 32KB
)

var (
	chunkSize = DefaultChunkSize
	chunkPool = sync.Pool{
		New: func() any {
			b := make([]byte, chunkSize)
			return &b
		},
	}
)

// SetChunkSize sets the chunk size for reading response bodies.
//
// If size is less than or equal to zero, it resets to the default chunk size.
func SetChunkSize(size int) {
	if size <= 0 {
		size = DefaultChunkSize
	}

	chunkSize = size
	chunkPool = sync.Pool{
		New: func() any {
			b := make([]byte, chunkSize)
			return &b
		},
	}
}

// limitedBuffer wraps [bytes.Buffer] to prevent capacity growth beyond maxCap.
// This prevents bytes.Buffer.ReadFrom() from over-allocating when it doesn't
// know the final size.
type limitedBuffer struct {
	buf    *bytes.Buffer
	maxCap int
}

func (lb *limitedBuffer) ReadFrom(r io.Reader) (n int64, err error) {
	chunkPtr, ok := chunkPool.Get().(*[]byte)
	if !ok {
		return 0, fmt.Errorf("chunk pool returned invalid type")
	}
	defer chunkPool.Put(chunkPtr)
	chunk := *chunkPtr

	for {
		available := lb.buf.Cap() - lb.buf.Len()
		if available < chunkSize && lb.buf.Cap() < lb.maxCap {
			needed := min(lb.buf.Len()+chunkSize, lb.maxCap)
			lb.buf.Grow(needed - lb.buf.Len())
		}

		nr, readErr := r.Read(chunk)
		if nr > 0 {
			nw, writeErr := lb.buf.Write(chunk[:nr])
			n += int64(nw)
			if writeErr != nil {
				return n, writeErr
			}
		}

		if readErr != nil {
			if readErr == io.EOF {
				return n, nil
			}
			return n, readErr
		}
	}
}

// readNNormalizeRespBody performs normalization on the http response object.
// and fills body buffer with actual response body.
func readNNormalizeRespBody(rc *ResponseChain, body *bytes.Buffer) (err error) {
	response := rc.resp
	if response == nil {
		return fmt.Errorf("something went wrong response is nil")
	}
	// net/http doesn't automatically decompress the response body if an
	// encoding has been specified by the user in the request so in case we have to
	// manually do it.

	origBody := rc.resp.Body
	if origBody == nil {
		// skip normalization if body is nil
		return nil
	}
	// wrap with decode if applicable
	wrapped, err := wrapDecodeReader(response)
	if err != nil {
		wrapped = origBody
	}
	limitReader := io.LimitReader(wrapped, rc.maxBodySize)

	// Read body using ReadFrom for efficiency, but cap growth at maxBodySize.
	// We use a custom limitedBuffer wrapper to prevent bytes.Buffer from
	// over-allocating (it normally grows to 2x when size is unknown).
	limitedBuf := &limitedBuffer{buf: body, maxCap: int(rc.maxBodySize)}
	_, err = limitedBuf.ReadFrom(limitReader)
	if err != nil {
		if strings.Contains(err.Error(), "gzip: invalid header") {
			// its invalid gzip but we will still use it from original body
			_, gErr := body.ReadFrom(origBody)
			if gErr != nil {
				return errors.Wrap(gErr, "could not read response body after gzip error")
			}
		} else if stringsutil.ContainsAnyI(err.Error(), "unexpected EOF", "read: connection reset by peer", "user canceled", "http: request body too large") {
			// keep partial body and continue (skip error) (add meta header in response for debugging)
			if response.Header == nil {
				response.Header = make(http.Header)
			}
			response.Header.Set("x-nuclei-ignore-error", err.Error())
			return nil
		} else {
			return errors.Wrap(err, "could not read response body")
		}
	}
	return nil
}

// wrapDecodeReader wraps a decompression reader around the response body if it's compressed
// using gzip or deflate.
func wrapDecodeReader(resp *http.Response) (rc io.ReadCloser, err error) {
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		rc, err = gzip.NewReader(resp.Body)
	case "deflate":
		rc, err = zlib.NewReader(resp.Body)
	case "br":
		rc = io.NopCloser(brotli.NewReader(resp.Body))
	case "zstd":
		var zstdReader *zstd.Decoder
		zstdReader, err = zstd.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		rc = io.NopCloser(zstdReader)
	default:
		rc = resp.Body
	}
	if err != nil {
		return nil, err
	}
	// handle GBK encoding
	if isContentTypeGbk(resp.Header.Get("Content-Type")) {
		rc = io.NopCloser(transform.NewReader(rc, simplifiedchinese.GBK.NewDecoder()))
	}
	return rc, nil
}

// isContentTypeGbk checks if the content-type header is gbk
func isContentTypeGbk(contentType string) bool {
	contentType = strings.ToLower(contentType)
	return stringsutil.ContainsAny(contentType, "gbk", "gb2312", "gb18030")
}
