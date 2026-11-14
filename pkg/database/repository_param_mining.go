package database

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// Param-mining reads and writes. The phase (internal/runner) picks endpoints
// from this scan's records, gathers the parameter names the host already uses
// as the wordlist's first tier, and stores each confirmed hidden parameter as
// a new record the dynamic-assessment phase then picks up.

// ParamMiningRemarkPrefix starts the remark a param-mining record carries per
// hidden parameter: "param-mining:name=<n>;signal=<s>".
const ParamMiningRemarkPrefix = "param-mining:"

// paramMiningCandidateColumns are what candidate selection reads: identity,
// the request to replay, and the ranking/filter columns. No response body.
var paramMiningCandidateColumns = []string{
	"uuid", "scheme", "hostname", "port", "method", "path", "url",
	"raw_request", "request_content_type", "response_content_type",
	"status_code", "risk_score", "surface_score", "source",
}

// ParamMiningCandidates returns the records the param-mining phase may mine:
// the ones the dynamic-assessment phase of scanUUID will see (after the scan
// cursor, in the project, within hosts), answered 2xx, GET or POST, and not
// param-mining output themselves. Ordered by risk_score, then surface_score,
// then age; at most perHost rows per origin (scheme, hostname, port), so one
// large host cannot crowd the others out of a global cap. perHost <= 0 = no
// cap. Content-type and per-endpoint selection is left to the caller.
func (r *Repository) ParamMiningCandidates(ctx context.Context, scanUUID string, hosts []HostTarget, perHost int) ([]HTTPRecord, error) {
	scan, err := r.GetScanByUUID(ctx, scanUUID)
	if err != nil {
		return nil, fmt.Errorf("load scan %s: %w", scanUUID, err)
	}
	filter := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = q.Where("has_response = ?", true).
			Where("status_code >= 200 AND status_code < 300").
			Where("method IN (?)", bun.List([]string{"GET", "POST"})).
			Where("(source IS NULL OR source != ?)", RecordSourceParamMining)
		if !scan.CursorAt.IsZero() {
			at := dbTimestampString(r.db.Driver(), scan.CursorAt)
			q = q.Where("(created_at > ? OR (created_at = ? AND uuid > ?))", at, at, scan.CursorUUID)
		}
		q = applyHostScopeFilter(q, hosts)
		return applyProjectFilter(q, scan.ProjectUUID)
	}

	var rows []HTTPRecord
	q := r.db.NewSelect().Model(&rows).Column(paramMiningCandidateColumns...)
	if perHost > 0 {
		ranked := filter(r.db.NewSelect().Model((*HTTPRecord)(nil)).Column("uuid").
			ColumnExpr("ROW_NUMBER() OVER (PARTITION BY scheme, hostname, port " +
				"ORDER BY risk_score DESC, surface_score DESC, created_at ASC, uuid ASC) AS host_rank"))
		keep := r.db.NewSelect().TableExpr("(?) AS ranked", ranked).Column("ranked.uuid").
			Where("ranked.host_rank <= ?", perHost)
		q = q.Where("uuid IN (?)", keep)
	} else {
		q = filter(q)
	}
	if err := q.OrderExpr("risk_score DESC, surface_score DESC, created_at ASC, uuid ASC").Scan(ctx); err != nil {
		return nil, err
	}
	return rows, nil
}

// HostParamNames are the parameter names one host's records already use,
// split by where they came from and each ordered by how often it appeared.
type HostParamNames struct {
	// JS holds names from the target's JavaScript: jstangle-derived records
	// and the request hints in jstangle-facts artifacts.
	JS []string
	// Observed holds names from every other record of the host (crawl,
	// discovery, ingested traffic).
	Observed []string
}

// hostParamNamesRowCap bounds how many records and artifacts one host's name
// harvest reads.
const hostParamNamesRowCap = 5000

// ParamNamesForHost collects the parameter names projectUUID's records use on
// hostname, the first tier of the param-mining wordlist.
func (r *Repository) ParamNamesForHost(ctx context.Context, projectUUID, hostname string) (HostParamNames, error) {
	js, observed := map[string]int{}, map[string]int{}

	var rows []HTTPRecord
	q := r.db.NewSelect().Model(&rows).Column("source", "parameters").
		Where("hostname = ?", hostname).
		Where("parameters IS NOT NULL")
	q = applyProjectFilter(q, projectUUID)
	if err := q.Limit(hostParamNamesRowCap).Scan(ctx); err != nil {
		return HostParamNames{}, err
	}
	for _, row := range rows {
		into := observed
		if row.Source == "jstangle" {
			into = js
		}
		for _, p := range row.Parameters {
			switch p.Type {
			case "url", "body", "json", "multipart":
				if p.Name != "" {
					into[p.Name]++
				}
			}
		}
	}

	// Request hints are httpRequest facts discovery never replayed (low
	// confidence, variable URL), so no record carries their query names.
	var artifacts []AnalysisArtifact
	aq := r.db.NewSelect().Model(&artifacts).Column("aa.content").
		Join("JOIN http_records AS r ON r.uuid = aa.http_record_uuid").
		Where("aa.kind = ?", "jstangle-facts").
		Where("r.hostname = ?", hostname)
	if projectUUID != "" {
		aq = aq.Where("aa.project_uuid = ?", projectUUID)
	}
	if err := aq.Limit(hostParamNamesRowCap).Scan(ctx); err != nil {
		return HostParamNames{}, err
	}
	for _, a := range artifacts {
		for _, n := range jsFactQueryNames(a.Content) {
			js[n]++
		}
	}
	return HostParamNames{JS: keysByCount(js, 0), Observed: keysByCount(observed, 0)}, nil
}

// jsFactBundleNames is the slice of a jstangle-facts artifact that carries
// parameter names. Declared here rather than imported so the database layer
// does not depend on the discovery engine for one field path.
type jsFactBundleNames struct {
	RequestHints []struct {
		Query []struct {
			Name struct {
				Rendered string `json:"rendered"`
				Static   bool   `json:"static"`
			} `json:"name"`
		} `json:"query"`
	} `json:"httpRequestHint"`
}

func jsFactQueryNames(content []byte) []string {
	var b jsFactBundleNames
	if err := json.Unmarshal(content, &b); err != nil {
		return nil
	}
	var out []string
	for _, h := range b.RequestHints {
		for _, q := range h.Query {
			if q.Name.Static && q.Name.Rendered != "" {
				out = append(out, q.Name.Rendered)
			}
		}
	}
	return out
}

// ParamMiningRemark renders the remark for one confirmed hidden parameter.
func ParamMiningRemark(name, signal string) string {
	return ParamMiningRemarkPrefix + "name=" + name + ";signal=" + signal
}

// SaveParamMiningRecord stores the exchange that confirmed hidden parameters
// as a record with source param-mining: its EmbeddedParam entries for hidden
// are marked Hidden, and remarks are attached. scanUUID is stamped on a new
// row so the scan's own exports count it. created is false when an identical
// exchange was already stored (its UUID is returned, remarks appended).
func (r *Repository) SaveParamMiningRecord(ctx context.Context, rr *httpmsg.HttpRequestResponse, projectUUID, scanUUID string, hidden []string, remarks []string) (uuid string, created bool, err error) {
	if rr == nil || rr.Request() == nil {
		return "", false, fmt.Errorf("invalid HttpRequestResponse")
	}
	record := &HTTPRecord{}
	if err := record.FromHttpRequestResponse(rr); err != nil {
		return "", false, fmt.Errorf("failed to convert request: %w", err)
	}
	record.Source = RecordSourceParamMining
	record.ProjectUUID = defaultProjectUUID(projectUUID)
	record.ScanUUID = scanUUID
	record.Remarks = remarks
	markHiddenParams(record.Parameters, hidden)

	if existing, derr := r.findDuplicateRecord(ctx, record); derr == nil && existing != "" {
		if len(remarks) > 0 {
			if err := r.AppendRemarks(ctx, map[string][]string{existing: remarks}); err != nil {
				return existing, false, err
			}
		}
		return existing, false, nil
	}
	if _, err := r.db.NewInsert().Model(record).Exec(ctx); err != nil {
		return "", false, fmt.Errorf("failed to insert record: %w", err)
	}
	r.emitRecordSaved(record)
	return record.UUID, true, nil
}

// markHiddenParams sets Hidden on the parameters named in hidden.
func markHiddenParams(params []EmbeddedParam, hidden []string) {
	if len(hidden) == 0 {
		return
	}
	set := make(map[string]bool, len(hidden))
	for _, h := range hidden {
		set[h] = true
	}
	for i := range params {
		if set[params[i].Name] && !strings.EqualFold(params[i].Type, "cookie") {
			params[i].Hidden = true
		}
	}
}
