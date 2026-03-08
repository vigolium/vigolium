package apivoyagerlist

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type APIVoyagerListFormat struct {
	opts formats.InputFormatOptions
}

// New creates a new JSON format parser
func New() *APIVoyagerListFormat {
	return &APIVoyagerListFormat{}
}

var _ formats.Format = &APIVoyagerListFormat{}

type OutputResult struct {
	Date          string `json:"date"`
	RequestURL    string `json:"url,omitempty"`
	RequestRaw    string `json:"request_raw"`
	RequestMethod string `json:"request_method"`

	ResponseRaw         string `json:"response_raw"`
	ResponseContentType string `json:"response_content_type"`
	StatusCode          int    `json:"status_code"`

	MainAPIURL string `json:"main_api_url"`
	CrawlerURL string `json:"crawler_url"`
}

// Name returns the name of the format
func (j *APIVoyagerListFormat) Name() string {
	return "apivoyagerlist"
}

func (j *APIVoyagerListFormat) SetOptions(options formats.InputFormatOptions) {
	j.opts = options
}

func (j *APIVoyagerListFormat) Parse(input string, resultsCb formats.ParseReqRespCallback) error {
	// read lines in input file and read each line as input
	targetsListFile, err := os.Open(input)
	if err != nil {
		return errors.Wrap(err, "could not open json file")
	}
	defer func() { _ = targetsListFile.Close() }()
	sc := bufio.NewScanner(targetsListFile)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		err = j.readData(line, resultsCb)
		if err != nil {
			zap.L().Error("apivoyagerlist: Could not read data", zap.String("input", line), zap.Error(err))
		}
	}
	return nil
}

func (j *APIVoyagerListFormat) readData(input string, resultsCb formats.ParseReqRespCallback) error {
	if input == "" {
		return errors.New("input is empty")
	}
	file, err := j.openFile(input)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	dec := json.NewDecoder(file)
	for dec.More() {
		var outputResult OutputResult
		err := dec.Decode(&outputResult)
		if err != nil {
			continue
		}
		requestURL := outputResult.RequestURL

		if requestURL == "" {
			requestURLPath, _ := httpmsg.GetPath([]byte(outputResult.RequestRaw))
			if requestURLPath == "" {
				continue
			}
			if outputResult.MainAPIURL != "" {
				mainURL := strings.TrimSuffix(outputResult.MainAPIURL, "/")
				requestURL = mainURL + requestURLPath
			}
		}
		if requestURL == "" {
			continue
		}

		// ! Ignore redirects when request method is GET
		if outputResult.RequestMethod == "GET" && outputResult.StatusCode >= 300 && outputResult.StatusCode < 400 {
			continue
		}
		if outputResult.StatusCode == 405 {
			continue
		}

		var requestResponse *httpmsg.HttpRequestResponse
		if outputResult.RequestRaw != "" {
			requestResponse, err = httpmsg.ParseRawRequestWithURL(outputResult.RequestRaw, requestURL)
		} else {
			requestResponse, err = httpmsg.GetRawRequestFromURL(requestURL)
		}
		if err != nil {
			zap.L().Warn("apivoyagerlist: Could not parse raw request", zap.String("url", outputResult.RequestURL), zap.Error(err))
			continue
		}

		// If we have a raw response, attach it
		if outputResult.ResponseRaw != "" {
			requestResponse = requestResponse.WithResponse(httpmsg.NewHttpResponse([]byte(outputResult.ResponseRaw)))
		}

		resultsCb(requestResponse)
	}
	return nil
}

// Count returns the total number of JSON objects across all files in the list.
func (j *APIVoyagerListFormat) Count(input string) (int64, error) {
	targetsListFile, err := os.Open(input)
	if err != nil {
		return 0, err
	}
	defer func() { _ = targetsListFile.Close() }()

	var total int64
	sc := bufio.NewScanner(targetsListFile)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		count, err := j.countFile(line)
		if err != nil {
			zap.L().Debug("apivoyagerlist: Count error", zap.String("file", line), zap.Error(err))
			continue
		}
		total += count
	}
	return total, sc.Err()
}

// countFile counts JSON objects in a single file.
func (j *APIVoyagerListFormat) countFile(input string) (int64, error) {
	file, err := j.openFile(input)
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
func (j *APIVoyagerListFormat) openFile(input string) (io.ReadCloser, error) {
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
