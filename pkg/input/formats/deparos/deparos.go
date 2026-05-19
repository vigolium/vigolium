package deparos

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
	"go.uber.org/zap"
)

// DeparosResult represents a single entry from deparos JSONL output.
type DeparosResult struct {
	URL           string            `json:"url"`
	Method        string            `json:"method"`
	StatusCode    int               `json:"status_code"`
	ContentLength int64             `json:"content_length"`
	ContentType   string            `json:"content_type"`
	Header        map[string]string `json:"header"`
	Title         string            `json:"title"`
	FoundBy       string            `json:"found_by"`
	Depth         int               `json:"depth"`
	Type          string            `json:"type"`
	Location      string            `json:"location"`
	Remarks       []string          `json:"remarks"`
}

// DeparosFormat is a JSONL format parser for deparos content discovery output.
type DeparosFormat struct {
	opts formats.InputFormatOptions
}

// New creates a new deparos format parser.
func New() *DeparosFormat {
	return &DeparosFormat{}
}

var _ formats.Format = &DeparosFormat{}

// Name returns the name of the format.
func (d *DeparosFormat) Name() string {
	return "deparos"
}

// SetOptions sets the options for the input format.
func (d *DeparosFormat) SetOptions(options formats.InputFormatOptions) {
	d.opts = options
}

// Parse parses deparos JSONL input and calls the provided callback
// for each HttpRequestResponse it discovers.
func (d *DeparosFormat) Parse(input string, resultsCb formats.ParseReqRespCallback) error {
	file, err := d.openFile(input)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	dec := json.NewDecoder(file)

	for dec.More() {
		var result DeparosResult
		if err := dec.Decode(&result); err != nil {
			continue
		}

		if result.URL == "" {
			continue
		}

		requestResponse, err := httpmsg.GetRawRequestFromURL(result.URL)
		if err != nil {
			zap.L().Warn("deparos: Could not create request from URL",
				zap.String("url", result.URL), zap.Error(err))
			continue
		}

		// Reconstruct synthetic response from deparos metadata
		if result.StatusCode != 0 || len(result.Header) > 0 {
			rawResponse := httpmsg.BuildRawResponse(
				result.StatusCode,
				result.Header,
				"",
			)
			requestResponse = requestResponse.WithResponse(httpmsg.NewHttpResponse(rawResponse))
		}

		if !resultsCb(requestResponse) {
			return nil
		}
	}

	return nil
}

// Count returns the number of JSON objects in the file.
func (d *DeparosFormat) Count(input string) (int64, error) {
	file, err := d.openFile(input)
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()

	var count int64
	dec := json.NewDecoder(file)
	for dec.More() {
		var obj json.RawMessage
		if err := dec.Decode(&obj); err != nil {
			continue
		}
		count++
	}
	return count, nil
}

// openFile opens a file, handling .gz compression.
func (d *DeparosFormat) openFile(input string) (io.ReadCloser, error) {
	if strings.HasSuffix(input, ".gz") {
		gzFile, err := os.Open(input)
		if err != nil {
			return nil, errors.Wrap(err, "could not open gzipped file")
		}
		gzReader, err := gzip.NewReader(gzFile)
		if err != nil {
			_ = gzFile.Close()
			return nil, errors.Wrap(err, "could not create gzip reader")
		}
		return &gzipFileCloser{gzReader: gzReader, file: gzFile}, nil
	}
	return os.Open(input)
}

// gzipFileCloser wraps gzip.Reader and underlying file for proper cleanup.
type gzipFileCloser struct {
	gzReader *gzip.Reader
	file     *os.File
}

func (g *gzipFileCloser) Read(p []byte) (n int, err error) {
	return g.gzReader.Read(p)
}

func (g *gzipFileCloser) Close() error {
	_ = g.gzReader.Close()
	return g.file.Close()
}
