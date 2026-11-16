package database

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/uptrace/bun"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// The body-shape inventory (`vigolium params --paths`): per operation —
// (origin, path template, method) — the union of the JSON key paths its
// recorded request bodies carried, with each path's JSON types and how many
// records carried it. Values are never kept: a body shape says which keys an
// operation accepts and of what type, which is what a probe needs to send a
// body the handler parses, and nothing about the values a user sent.
//
// It reads the key paths stored on each JSON parameter (EmbeddedParam.Metadata
// and JSONType, set at storage by EnrichFromHttpRequestResponse), on the same
// light-record stream and endpoint ids as `vigolium endpoints` and `params`.

// JSONTypeName names a parsed JSON value type for storage and output.
func JSONTypeName(t httpmsg.JSONValueType) string {
	switch t {
	case httpmsg.JSONTypeString:
		return "string"
	case httpmsg.JSONTypeNumber:
		return "number"
	case httpmsg.JSONTypeBool:
		return "boolean"
	case httpmsg.JSONTypeNull:
		return "null"
	default:
		return ""
	}
}

// ParamPathOptions shapes a ParamPaths call.
type ParamPathOptions struct {
	// Endpoint keeps one endpoint, by EndpointView id or by template.
	Endpoint string
	// MinSamples drops key paths carried by fewer records.
	MinSamples int64
	// Limit/Offset page the list; Limit 0 returns every path.
	Limit, Offset int
	// MaxPaths overrides DefaultMaxParams (0 = default).
	MaxPaths int
}

// ParamPathView is one JSON key path of one operation's request bodies.
type ParamPathView struct {
	EndpointID string `json:"endpoint_id"`
	Origin     string `json:"origin"`
	Template   string `json:"template"`
	Method     string `json:"method"`
	// KeyPath is the dotted key path ("user.address.city"); array elements
	// share their array's path.
	KeyPath string `json:"key_path"`
	// JSONType is the type the path carried most often (string, number,
	// boolean, null; "" when no sample had a recognised type); JSONTypes
	// counts every type seen, so a path that is sometimes null says so.
	JSONType  string           `json:"json_type"`
	JSONTypes map[string]int64 `json:"json_types"`
	// SampleCount is how many records' bodies carried the path;
	// OperationRecords how many JSON-body records the operation has, so a
	// path present in fewer of them is optional in what was observed.
	SampleCount      int64 `json:"sample_count"`
	OperationRecords int64 `json:"operation_records"`
}

// ParamPathResult is a bounded body-shape inventory.
type ParamPathResult struct {
	Paths          []ParamPathView
	Total          int64
	RecordsScanned int64
	Capped         bool
	// RecordsWithoutPaths counts records whose JSON parameters were stored
	// without a key path (written before paths were recorded): their keys are
	// in `params`, not here.
	RecordsWithoutPaths int64
}

// ParamPaths aggregates the filtered records into per-operation JSON body
// shapes.
func (qb *QueryBuilder) ParamPaths(ctx context.Context, opts ParamPathOptions) (ParamPathResult, error) {
	maxPaths := opts.MaxPaths
	if maxPaths <= 0 {
		maxPaths = DefaultMaxParams
	}
	type opKey struct{ origin, template, method string }
	type pathKey struct {
		opKey
		path string
	}
	type pathAcc struct {
		samples int64
		types   map[string]int64
	}
	endpointIDs := map[[2]string]string{}
	opRecords := map[opKey]int64{}
	accs := map[pathKey]*pathAcc{}

	var res ParamPathResult
	origins := originCache{}
	counted := map[string]bool{}
	seen, err := qb.forEachInventoryRecord(ctx, func(r *inventoryRecord) {
		method := strings.ToUpper(r.Method)
		var jsonParams, withPath int
		for _, p := range r.Parameters {
			if p.Type == "json" {
				jsonParams++
				if p.Metadata != "" {
					withPath++
				}
			}
		}
		if jsonParams == 0 {
			return
		}
		if withPath == 0 {
			res.RecordsWithoutPaths++
			return
		}
		origin := origins.origin(r.Scheme, r.Hostname, r.Port)
		template, _ := endpointShape(r.Path)
		ek := [2]string{origin, template}
		id, ok := endpointIDs[ek]
		if !ok {
			id = EndpointID(origin, template)
			endpointIDs[ek] = id
		}
		if opts.Endpoint != "" && opts.Endpoint != template && opts.Endpoint != id {
			return
		}
		op := opKey{origin, template, method}
		opRecords[op]++
		// A path counts once per record however many array elements carried
		// it; every element's type counts.
		clear(counted)
		for _, p := range r.Parameters {
			if p.Type != "json" || p.Metadata == "" {
				continue
			}
			key := pathKey{op, p.Metadata}
			a := accs[key]
			if a == nil {
				if len(accs) >= maxPaths {
					res.Capped = true
					continue
				}
				a = &pathAcc{types: map[string]int64{}}
				accs[key] = a
			}
			if !counted[p.Metadata] {
				counted[p.Metadata] = true
				a.samples++
			}
			if p.JSONType != "" {
				a.types[p.JSONType]++
			}
		}
	})
	if err != nil {
		return ParamPathResult{}, err
	}
	res.RecordsScanned = seen

	views := make([]ParamPathView, 0, len(accs))
	for k, a := range accs {
		if a.samples < opts.MinSamples {
			continue
		}
		v := ParamPathView{
			EndpointID:       endpointIDs[[2]string{k.origin, k.template}],
			Origin:           k.origin,
			Template:         k.template,
			Method:           k.method,
			KeyPath:          k.path,
			JSONTypes:        a.types,
			SampleCount:      a.samples,
			OperationRecords: opRecords[k.opKey],
		}
		var best int64
		for t, n := range a.types {
			if n > best || (n == best && t < v.JSONType) {
				best, v.JSONType = n, t
			}
		}
		views = append(views, v)
	}
	sort.Slice(views, func(i, j int) bool {
		a, b := views[i], views[j]
		if a.Origin != b.Origin {
			return a.Origin < b.Origin
		}
		if a.Template != b.Template {
			return a.Template < b.Template
		}
		if a.Method != b.Method {
			return a.Method < b.Method
		}
		return a.KeyPath < b.KeyPath
	})
	res.Total = int64(len(views))
	res.Paths = pageSlice(views, opts.Offset, opts.Limit)
	return res, nil
}

// jsonParamPathsBackfillMaxRows bounds the one-time key-path backfill, like
// decodedBackfillMaxRows.
const jsonParamPathsBackfillMaxRows = 50000

// backfillJSONParamPaths re-parses the request of each record whose JSON
// parameters were stored without a key path and rewrites its parameters
// (schema v6's one-time pass, see CreateSchema). Best effort and bounded: a
// row past the bound, or one that fails to parse, keeps its parameters and is
// counted by `params --paths` as records_without_paths.
func (db *DB) backfillJSONParamPaths(ctx context.Context) (int, error) {
	type row struct {
		UUID       string          `bun:"uuid"`
		Parameters json.RawMessage `bun:"parameters"`
	}
	type reqRow struct {
		UUID       string `bun:"uuid"`
		RawRequest []byte `bun:"raw_request"`
	}
	return db.runBackfill(ctx, "backfill JSON parameter paths", jsonParamPathsBackfillMaxRows,
		func(ctx context.Context, after string, limit int) (string, int, []backfillUpdate, error) {
			var page []row
			// A row whose stored parameters may name a JSON value: the LIKE is a
			// prefilter on the stored JSON text (spacing differs between SQLite's
			// text and Postgres's jsonb rendering, so it matches the quoted word
			// alone); the decode below decides.
			if err := db.NewSelect().
				TableExpr("http_records").
				ColumnExpr("uuid, parameters").
				Where("parameters IS NOT NULL").
				Where(`CAST(parameters AS TEXT) LIKE ?`, `%"json"%`).
				Where("uuid > ?", after).
				OrderExpr("uuid ASC").
				Limit(int64(limit)).
				Scan(ctx, &page); err != nil || len(page) == 0 {
				return after, 0, nil, err
			}
			last := page[len(page)-1].UUID
			// Only the rows that need a re-parse load their request bytes.
			stored := map[string][]EmbeddedParam{}
			for _, r := range page {
				var ps []EmbeddedParam
				if json.Unmarshal(r.Parameters, &ps) == nil && needsJSONPaths(ps) {
					stored[r.UUID] = ps
				}
			}
			if len(stored) == 0 {
				return last, len(page), nil, nil
			}
			var reqs []reqRow
			if err := db.NewSelect().
				TableExpr("http_records").
				ColumnExpr("uuid, raw_request").
				Where("uuid IN (?)", bun.List(slices.Collect(maps.Keys(stored)))).
				OrderExpr("uuid ASC").
				Scan(ctx, &reqs); err != nil {
				return last, len(page), nil, err
			}
			var updates []backfillUpdate
			for _, r := range reqs {
				params, err := httpmsg.NewHttpRequest(r.RawRequest).Parameters()
				if err != nil {
					continue
				}
				rec := &HTTPRecord{Parameters: embeddedParams(params)}
				// Hidden (param-mined) parameters are not in the request bytes;
				// carry them over.
				for _, p := range stored[r.UUID] {
					if p.Hidden {
						rec.Parameters = append(rec.Parameters, p)
					}
				}
				updates = append(updates, backfillUpdate{uuid: r.UUID, apply: func(ctx context.Context, idb bun.IDB) error {
					_, err := idb.NewUpdate().
						Model(rec).
						Column("parameters").
						Where("uuid = ?", r.UUID).
						Exec(ctx)
					return err
				}})
			}
			return last, len(page), updates, nil
		})
}

// needsJSONPaths reports whether a stored parameter list has a JSON value
// without its key path.
func needsJSONPaths(params []EmbeddedParam) bool {
	for _, p := range params {
		if p.Type == "json" && p.Metadata == "" {
			return true
		}
	}
	return false
}
