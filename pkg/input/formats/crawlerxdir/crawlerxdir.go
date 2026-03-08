package crawlerxdir

import (
	"fmt"
	"os"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
	"github.com/pkg/errors"
	"github.com/xitongsys/parquet-go-source/local"
	"github.com/xitongsys/parquet-go/reader"
	"go.uber.org/zap"
)

// Local definition of ParquetRecord to avoid cross-module dependencies
// Based on github.com/theblackturtle/crawlerx/pkg/output/parquet.go
// NOTE: Adjust field types if necessary based on actual Parquet schema and DuckDB behavior
type ParquetRecord struct {
	Url                string            `parquet:"name=url,type=BYTE_ARRAY,convertedtype=UTF8"`
	ResultType         string            `parquet:"name=result_type,type=BYTE_ARRAY,convertedtype=UTF8"`
	Checksum           string            `parquet:"name=checksum,type=BYTE_ARRAY,convertedtype=UTF8"`
	InputURL           string            `parquet:"name=input_url,type=BYTE_ARRAY,convertedtype=UTF8"`
	Time               string            `parquet:"name=time,type=BYTE_ARRAY,convertedtype=UTF8"`
	RequestMethod      string            `parquet:"name=method,type=BYTE_ARRAY,convertedtype=UTF8"`
	Title              string            `parquet:"name=title,type=BYTE_ARRAY,convertedtype=UTF8"`
	ResponseStatusCode int32             `parquet:"name=status_code,type=INT32"` // Use int32
	ResponseBodyLines  int64             `parquet:"name=lines,type=INT64"`
	ResponseBodyWords  int64             `parquet:"name=words,type=INT64"`
	ResponseBodyBytes  int64             `parquet:"name=content_length,type=INT64"`
	RequestHTTPRaw     string            `parquet:"name=req_raw,type=BYTE_ARRAY,convertedtype=UTF8"` // Will also try "req.raw" if this is empty and ParquetReader supports it or has a way to know schema
	RequestBodyData    string            `parquet:"name=req_body,type=BYTE_ARRAY,convertedtype=UTF8"`
	ResponseBodyMd5    string            `parquet:"name=resp_md5,type=BYTE_ARRAY,convertedtype=UTF8"`
	ResponseBodyData   string            `parquet:"name=resp_body,type=BYTE_ARRAY,convertedtype=UTF8"`
	RequestHeaders     map[string]string `parquet:"name=req_headers, type=MAP, keytype=BYTE_ARRAY, keyconvertedtype=UTF8, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	ResponseHeaders    map[string]string `parquet:"name=resp_headers, type=MAP, keytype=BYTE_ARRAY, keyconvertedtype=UTF8, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	ResourceType       string            `parquet:"name=resource_type,type=BYTE_ARRAY,convertedtype=UTF8"`
}

// CrawlerXDirFormat is a Parquet format parser for vigolium
// input containing HTTP requests previously processed by crawlerx, read from a directory.
type CrawlerXDirFormat struct {
	opts formats.InputFormatOptions
}

// New creates a new CrawlerXDir format parser
func New() *CrawlerXDirFormat {
	return &CrawlerXDirFormat{}
}

var _ formats.Format = &CrawlerXDirFormat{}

// Name returns the name of the format
func (j *CrawlerXDirFormat) Name() string {
	return "crawlerxdir"
}

func (j *CrawlerXDirFormat) SetOptions(options formats.InputFormatOptions) {
	j.opts = options
}

// Parse parses all Parquet files matching '*.parquet' within the input directory
// using DuckDB and calls the provided callback function for each RequestResponse it discovers.
func (j *CrawlerXDirFormat) Parse(inputDir string, resultsCb formats.ParseReqRespCallback) error {
	// Verify input is a directory
	info, err := os.Stat(inputDir)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.Errorf("input directory '%s' not found", inputDir)
		}
		return errors.Wrapf(err, "could not stat input directory '%s'", inputDir)
	}
	if !info.IsDir() {
		return errors.Errorf("input path '%s' is not a directory", inputDir)
	}

	// Use the new ParquetReader
	// The ParquetReader itself will find all *.parquet files recursively.
	// The ParquetRecord struct definition needs to match the schema in the Parquet files.
	// The ParquetReader does not yet have a fallback for "req.raw" like the DuckDB version did.
	// This would need to be handled either by ensuring Parquet files are consistent,
	// or by adding more sophisticated schema detection/handling in ParquetReader or here.
	parquetReader, err := NewParquetReader(
		inputDir,
		DefaultMaxOpenFiles,
	) // Pass DefaultMaxOpenFiles
	if err != nil {
		// Check if the error is due to no files found, and return nil as per previous behavior.
		// This might need adjustment based on how NewParquetReader signals "no files".
		// Assuming NewParquetReader returns an error that can be checked, or a specific error type.
		// For now, we'll rely on the error message.
		// Note: NewParquetReader already returns fmt.Errorf("no .parquet files found in %s", inputDir)
		if err.Error() == fmt.Sprintf("no .parquet files found in %s", inputDir) {
			zap.L().Warn("crawlerxdir: No *.parquet files found in directory", zap.String("dir", inputDir))
			return nil
		}
		return errors.Wrapf(err, "could not initialize parquet reader for directory '%s'", inputDir)
	}
	defer parquetReader.Close()

	for {
		parquetRecord, hasNext, err := parquetReader.Next()
		if err != nil {
			zap.L().Warn("crawlerxdir: Error retrieving next parquet record, stopping", zap.Error(err))
			return errors.Wrap(err, "error iterating over parquet records")
		}
		if !hasNext {
			zap.L().Debug("crawlerxdir: Finished processing all parquet records")
			break // No more records
		}

		// --- Processing logic (similar to original, but directly using parquetRecord) ---
		var requestResponse *httpmsg.HttpRequestResponse

		if parquetRecord.Url == "" {
			zap.L().Debug("crawlerxdir: Skipping record with empty URL")
			continue
		}

		// Note: The original DuckDB code had a fallback for "req.raw" vs "req_raw".
		// The current ParquetRecord struct uses "req_raw".
		// If Parquet files might use "req.raw", the ParquetReader or this logic
		// would need to be adapted, or the ParquetRecord struct would need a way
		// to handle alternative field names (e.g. using reflection or multiple tags,
		// though parquet-go might not support multiple tags directly for renaming).
		// For simplicity, we assume "req_raw" is the field name.
		// If RequestHTTPRaw is empty, we might try to get the raw request from URL,
		// or we might assume that if it's empty, it was not available in the Parquet file.
		if parquetRecord.RequestHTTPRaw != "" {
			requestResponse, err = httpmsg.ParseRawRequestWithURL(
				parquetRecord.RequestHTTPRaw,
				parquetRecord.Url,
			)
		} else {
			// If req_raw is empty, attempt to reconstruct from URL.
			// This matches the previous logic if req_raw was missing or empty.
			zap.L().Debug("crawlerxdir: RequestHTTPRaw is empty, attempting to get raw request from URL", zap.String("url", parquetRecord.Url))
			requestResponse, err = httpmsg.GetRawRequestFromURL(parquetRecord.Url)
		}
		if err != nil {
			zap.L().Warn(
				"crawlerxdir: Could not parse or get raw request",
				zap.String("url", parquetRecord.Url),
				zap.Error(err),
			)
			continue
		}

		if requestResponse.Request() == nil {
			zap.L().Warn(
				"crawlerxdir: Request object is nil after initial parsing, skipping",
				zap.String("url", parquetRecord.Url),
			)
			continue
		}

		// Build raw response from parquet data if available
		if parquetRecord.ResponseStatusCode != 0 || len(parquetRecord.ResponseHeaders) > 0 {
			rawResponse := httpmsg.BuildRawResponse(
				int(parquetRecord.ResponseStatusCode),
				parquetRecord.ResponseHeaders,
				parquetRecord.ResponseBodyData,
			)
			requestResponse = requestResponse.WithResponse(httpmsg.NewHttpResponse(rawResponse))
		}

		resultsCb(requestResponse)
		// --- End Processing logic ---
	}

	return nil
}

// Count returns the total number of rows across all Parquet files using metadata.
// This is fast as it reads Parquet metadata without scanning data.
func (j *CrawlerXDirFormat) Count(inputDir string) (int64, error) {
	info, err := os.Stat(inputDir)
	if err != nil {
		return 0, err
	}
	if !info.IsDir() {
		return 0, errors.Errorf("input path '%s' is not a directory", inputDir)
	}

	files, err := listParquetFiles(inputDir)
	if err != nil {
		return 0, err
	}

	var total int64
	for _, filePath := range files {
		count, err := countParquetRows(filePath)
		if err != nil {
			zap.L().Debug("crawlerxdir: Count error", zap.String("file", filePath), zap.Error(err))
			continue
		}
		total += count
	}
	return total, nil
}

// countParquetRows returns the number of rows in a Parquet file using metadata.
func countParquetRows(filePath string) (int64, error) {
	fr, err := local.NewLocalFileReader(filePath)
	if err != nil {
		return 0, err
	}

	pqReader, err := reader.NewParquetReader(fr, new(ParquetRecord), 1)
	if err != nil {
		_ = fr.Close()
		return 0, err
	}
	numRows := pqReader.GetNumRows()
	pqReader.ReadStop()
	return numRows, nil
}
