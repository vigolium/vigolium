// Package burpbridge provides a read-only client for the loopback HTTP listener
// hosted by the Vigolium Burp extension.
package burpbridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

const (
	DefaultURL          = "http://127.0.0.1:9009"
	EnvironmentVariable = "VIGOLIUM_BURP_BRIDGE_URL"
	Source              = "burp"
	UUIDPrefix          = "burp:"
	maxResponseBytes    = 16 * 1024 * 1024
	defaultInspectBytes = 64 * 1024
	MaxImportBytes      = 4 * 1024 * 1024
)

type Client struct {
	baseURL string
	http    *http.Client
}

type Query struct {
	ProjectUUID   string
	Location      string
	Host          string
	Methods       []string
	Path          string
	StatusCodes   []int
	ContentType   string
	SearchTerms   []string
	ExcludeTerms  []string
	HeaderSearch  string
	BodySearch    string
	ExcludeHeader string
	ExcludeBody   string
	DateFrom      *time.Time
	DateTo        *time.Time
	Limit         int
	Offset        int
	SortBy        string
	SortAsc       bool
	IncludeRaw    bool
}

type Result struct {
	Records []*database.HTTPRecord
	Total   int64
}

// Eligible reports whether a database-style filter can include ephemeral Burp
// records. Risk and remark filters are database enrichments that live traffic
// does not have, so those queries remain database-only.
func Eligible(filters database.QueryFilters) bool {
	if filters.Source != "" && !strings.EqualFold(filters.Source, Source) {
		return false
	}
	return filters.MinRiskScore == 0 && filters.Remark == "" && len(filters.Remarks) == 0
}

// QueryFromFilters maps the common traffic filters used by the CLI and REST
// API to the Burp listener protocol.
func QueryFromFilters(filters database.QueryFilters, includeRaw bool) Query {
	searchTerms := append([]string(nil), filters.EffectiveSearchTerms()...)
	if filters.FuzzyTerm != "" {
		searchTerms = append(searchTerms, filters.FuzzyTerm)
	}
	return Query{
		ProjectUUID:   filters.ProjectUUID,
		Location:      "proxy_history",
		Host:          filters.HostPattern,
		Methods:       append([]string(nil), filters.Methods...),
		Path:          filters.PathPattern,
		StatusCodes:   append([]int(nil), filters.StatusCodes...),
		ContentType:   filters.ContentType,
		SearchTerms:   searchTerms,
		ExcludeTerms:  append([]string(nil), filters.EffectiveExcludeTerms()...),
		HeaderSearch:  filters.HeaderSearch,
		BodySearch:    filters.BodySearch,
		ExcludeHeader: filters.ExcludeHeaderSearch,
		ExcludeBody:   filters.ExcludeBodySearch,
		DateFrom:      filters.DateFrom,
		DateTo:        filters.DateTo,
		Limit:         filters.Limit,
		Offset:        filters.Offset,
		SortBy:        filters.SortBy,
		SortAsc:       filters.SortAsc,
		IncludeRaw:    includeRaw,
	}
}

func New(rawURL string) (*Client, error) {
	baseURL, err := ValidateURL(rawURL)
	if err != nil {
		return nil, err
	}
	return &Client{
		baseURL: baseURL,
		http:    &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func URLFromEnvironment() string {
	return strings.TrimSpace(os.Getenv(EnvironmentVariable))
}

func ValidateURL(rawURL string) (string, error) {
	value := strings.TrimRight(strings.TrimSpace(rawURL), "/")
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() == "" || parsed.Port() == "" {
		return "", errors.New("burp bridge URL must be an http:// loopback URL with a port")
	}
	host := strings.ToLower(parsed.Hostname())
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", errors.New("burp bridge URL must use a loopback host")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("burp bridge URL must not include a path")
	}
	return value, nil
}

func IsBridgeUUID(uuid string) bool {
	return strings.HasPrefix(uuid, UUIDPrefix)
}

func (c *Client) Query(ctx context.Context, query Query) (Result, error) {
	location := query.Location
	if location == "" {
		location = "proxy_history"
	}
	args := map[string]any{
		"location":       location,
		"host":           query.Host,
		"methods":        query.Methods,
		"path":           query.Path,
		"status":         query.StatusCodes,
		"mime_type":      query.ContentType,
		"search_terms":   query.SearchTerms,
		"exclude_terms":  query.ExcludeTerms,
		"header":         query.HeaderSearch,
		"body":           query.BodySearch,
		"exclude_header": query.ExcludeHeader,
		"exclude_body":   query.ExcludeBody,
		"limit":          query.Limit,
		"offset":         query.Offset,
		"sort":           query.SortBy,
		"order":          map[bool]string{true: "asc", false: "desc"}[query.SortAsc],
	}
	if query.DateFrom != nil {
		args["from"] = query.DateFrom.UTC().Format(time.RFC3339Nano)
	}
	if query.DateTo != nil {
		args["to"] = query.DateTo.UTC().Format(time.RFC3339Nano)
	}

	var response searchResponse
	if err := c.post(ctx, "/api/burp-bridge/search", args, &response); err != nil {
		return Result{}, err
	}
	records := make([]*database.HTTPRecord, 0, len(response.Records))
	for _, item := range response.Records {
		record := item.toHTTPRecord(query.ProjectUUID)
		if query.IncludeRaw {
			inspection, err := c.InspectWithLimit(ctx, record.UUID, query.ProjectUUID, defaultInspectBytes)
			if err != nil {
				return Result{}, err
			}
			full := inspection.Record
			full.SentAt = record.SentAt
			full.CreatedAt = record.CreatedAt
			full.Remarks = record.Remarks
			record = full
		}
		records = append(records, record)
	}
	total := response.Total
	if total == 0 && len(records) > 0 {
		// Compatibility with listener builds predating the total field.
		total = len(records)
	}
	return Result{Records: records, Total: int64(total)}, nil
}

func (c *Client) Inspect(ctx context.Context, uuid, projectUUID string) (*database.HTTPRecord, error) {
	inspection, err := c.InspectWithLimit(ctx, uuid, projectUUID, defaultInspectBytes)
	if err != nil {
		return nil, err
	}
	return inspection.Record, nil
}

type Inspection struct {
	Record            *database.HTTPRecord
	RequestTruncated  bool
	ResponseTruncated bool
}

func (c *Client) InspectWithLimit(ctx context.Context, uuid, projectUUID string, maxBytes int) (Inspection, error) {
	ref := strings.TrimPrefix(uuid, UUIDPrefix)
	if ref == "" || ref == uuid {
		return Inspection{}, fmt.Errorf("invalid Burp bridge record UUID %q", uuid)
	}
	if maxBytes <= 0 || maxBytes > MaxImportBytes {
		maxBytes = MaxImportBytes
	}
	var response inspectResponse
	if err := c.post(ctx, "/api/burp-bridge/inspect", map[string]any{
		"ref": ref, "max_bytes": maxBytes,
	}, &response); err != nil {
		return Inspection{}, err
	}
	rawRequest := []byte(response.Request)
	if response.RequestBase64 != "" {
		var err error
		rawRequest, err = base64.StdEncoding.DecodeString(response.RequestBase64)
		if err != nil {
			return Inspection{}, fmt.Errorf("decode Burp request: %w", err)
		}
	}
	if len(rawRequest) == 0 {
		return Inspection{}, errors.New("burp bridge inspect response did not include a request")
	}
	rr, err := httpmsg.ParseRawRequestWithURL(string(rawRequest), response.URL)
	if err != nil {
		return Inspection{}, fmt.Errorf("parse Burp request: %w", err)
	}
	rawResponse := []byte(response.Response)
	if response.ResponseBase64 != "" {
		var err error
		rawResponse, err = base64.StdEncoding.DecodeString(response.ResponseBase64)
		if err != nil {
			return Inspection{}, fmt.Errorf("decode Burp response: %w", err)
		}
	}
	if len(rawResponse) > 0 {
		rr = rr.WithResponse(httpmsg.NewHttpResponse(rawResponse))
	}
	record := &database.HTTPRecord{}
	if err := record.FromHttpRequestResponse(rr); err != nil {
		return Inspection{}, fmt.Errorf("convert Burp record: %w", err)
	}
	record.UUID = uuid
	record.ProjectUUID = projectUUID
	record.Source = Source
	return Inspection{
		Record:            record,
		RequestTruncated:  response.RequestTruncated,
		ResponseTruncated: response.ResponseTruncated,
	}, nil
}

func (c *Client) post(ctx context.Context, path string, input, output any) error {
	payload, err := json.Marshal(input)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("burp bridge at %s is unavailable: %w", c.baseURL, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxResponseBytes {
		return errors.New("burp bridge response exceeds 2 MiB")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("burp bridge HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, output); err != nil {
		return fmt.Errorf("decode Burp bridge response: %w", err)
	}
	return nil
}

type searchResponse struct {
	Total   int             `json:"total"`
	Records []recordSummary `json:"records"`
}

type recordSummary struct {
	Ref         string `json:"ref"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	RequestHash string `json:"request_hash"`
	Status      int    `json:"status"`
	MimeType    string `json:"mime_type"`
	Notes       string `json:"notes"`
	Time        string `json:"time"`
}

func (s recordSummary) toHTTPRecord(projectUUID string) *database.HTTPRecord {
	parsed, _ := url.Parse(s.URL)
	port := 0
	if parsed != nil {
		port, _ = strconv.Atoi(parsed.Port())
		if port == 0 {
			if parsed.Scheme == "https" {
				port = 443
			} else {
				port = 80
			}
		}
	}
	sentAt := time.Now()
	if value, err := time.Parse(time.RFC3339Nano, s.Time); err == nil {
		sentAt = value
	}
	record := &database.HTTPRecord{
		UUID:                UUIDPrefix + s.Ref,
		ProjectUUID:         projectUUID,
		Method:              s.Method,
		URL:                 s.URL,
		StatusCode:          s.Status,
		HasResponse:         s.Status > 0,
		ResponseContentType: s.MimeType,
		RequestHash:         s.RequestHash,
		Source:              Source,
		SentAt:              sentAt,
		CreatedAt:           sentAt,
	}
	if parsed != nil {
		record.Scheme = parsed.Scheme
		record.Hostname = parsed.Hostname()
		record.Port = port
		record.Path = parsed.EscapedPath()
		if record.Path == "" {
			record.Path = "/"
		}
	}
	if s.Notes != "" {
		record.Remarks = []string{s.Notes}
	}
	return record
}

type inspectResponse struct {
	URL               string `json:"url"`
	Request           string `json:"request"`
	Response          string `json:"response"`
	RequestBase64     string `json:"request_base64"`
	ResponseBase64    string `json:"response_base64"`
	RequestTruncated  bool   `json:"request_truncated"`
	ResponseTruncated bool   `json:"response_truncated"`
}
