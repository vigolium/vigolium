package burpraw

import (
	"fmt"
	"os"

	"github.com/vigolium/vigolium/pkg/input/formats"
	"github.com/vigolium/vigolium/pkg/input/formats/detect"
)

// Format implements formats.Format for raw Burp Suite request files.
// These are single-request files exported via "Copy as raw" or "Save item",
// containing a request optionally followed by a "***" separator and response.
type Format struct {
	formatOpts formats.InputFormatOptions
}

// New creates a new burpraw Format parser.
func New() *Format {
	return &Format{}
}

var _ formats.Format = &Format{}

// Name returns the format name.
func (f *Format) Name() string {
	return "burpraw"
}

// SetOptions sets generic format options.
func (f *Format) SetOptions(options formats.InputFormatOptions) {
	f.formatOpts = options
}

// Parse reads a raw Burp request file and calls callback with the parsed item.
// When the file contains a "***" separator, the response half is parsed and
// attached to the resulting HttpRequestResponse.
func (f *Format) Parse(input string, callback formats.ParseReqRespCallback) error {
	data, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("failed to read burp raw file: %w", err)
	}

	rr, err := detect.ParseBurpPair(string(data))
	if err != nil {
		return fmt.Errorf("failed to parse burp raw file: %w", err)
	}

	callback(rr)
	return nil
}

// Count returns 1 since a burp raw file contains a single request.
func (f *Format) Count(input string) (int64, error) {
	return 1, nil
}
