package urls

import (
	"bufio"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// URLListFormat is a JSON format parser for nuclei
// input HTTP requests
type URLListFormat struct {
	opts formats.InputFormatOptions
}

// New creates a new JSON format parser
func New() *URLListFormat {
	return &URLListFormat{}
}

var _ formats.Format = &URLListFormat{}

// Name returns the name of the format
func (j *URLListFormat) Name() string {
	return "urls"
}

func (j *URLListFormat) SetOptions(options formats.InputFormatOptions) {
	j.opts = options
}

// Parse parses the input and calls the provided callback
// function for each RawRequest it discovers.
func (j *URLListFormat) Parse(input string, resultsCb formats.ParseReqRespCallback) error {
	file, err := os.Open(input)
	if err != nil {
		return errors.Wrap(err, "could not open json file")
	}
	defer func() { _ = file.Close() }()
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		rawRequest, err := httpmsg.GetRawRequestFromURL(line)
		if err != nil {
			zap.L().Warn("urls: Could not get raw request from URL", zap.String("url", line), zap.Error(err))
			continue
		}
		resultsCb(rawRequest)
	}

	return nil
}

// Count returns the number of non-empty lines in the file.
func (j *URLListFormat) Count(input string) (int64, error) {
	file, err := os.Open(input)
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()

	var count int64
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			count++
		}
	}
	return count, sc.Err()
}
