package database

import (
	"context"

	"database/sql"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/agent/recon"

	"github.com/uptrace/bun"
)

// hostObservationBatchSize bounds one insert transaction. A sweep can observe
// tens of thousands of endpoints, and handing them to the driver as a single
// statement builds one enormous query string in memory for no gain - these rows
// are small and there is nothing to gain past a few hundred per round trip.
const hostObservationBatchSize = 500

// HostObservationInput is one endpoint's observation, as the probe collects it,
// before it becomes a row.
//
// HostFacts is embedded rather than restated: the answer being stored IS the
// answer that will later be emitted, and copying its fields here meant two
// places to edit for every new fact and two Empty() methods that could silently
// disagree. What this type adds is the two things HostFacts cannot carry -
// which endpoint the answer describes, and whether the lookup finished.
type HostObservationInput struct {
	Hostname string
	Port     int
	HostFacts

	// The record types `vigolium dns` resolves beyond addresses and CNAME.
	MX, NS, TXT, SOA, CAA []string

	// Fingerprint and NotFound are the fingerprint phase's conclusions.
	Fingerprint *recon.TechStackReport
	NotFound    *NotFoundBaseline

	// Complete reports that the lookup ran to an answer. A cut-short prefetch
	// records incomplete observations rather than none, so a later reader can
	// tell "no AAAA record" from "we never got there".
	Complete bool
}

// Empty reports whether the observation carries nothing worth storing. A row
// with no answer AND no completeness claim states nothing that the absence of a
// row does not already state.
func (o HostObservationInput) Empty() bool {
	return o.HostFacts.Empty() && !o.Complete && len(o.MX)+len(o.NS)+len(o.TXT)+len(o.SOA)+len(o.CAA) == 0 &&
		o.Fingerprint == nil && o.NotFound == nil
}

// SaveHostObservations persists a run's host observations in bounded batches.
//
// ON CONFLICT (scan_uuid, hostname, port) updates rather than inserting: within
// ONE run an endpoint has one observation, so a second write for it is a
// refinement (the TLS handshake finishing after the DNS answer, say) and not a
// second event. A refinement only adds: each fact column keeps its stored value
// when the new write leaves it empty, so the fingerprint phase writing its
// report after the DNS/TLS prefetch does not erase the prefetch's answers. ACROSS runs the conflict cannot fire, which is the point -
// re-probing a host next month adds that month's observation and leaves this
// one intact.
func (r *Repository) SaveHostObservations(ctx context.Context, projectUUID, scanUUID string, obs []HostObservationInput) error {
	if r == nil || r.db == nil || len(obs) == 0 {
		return nil
	}
	project := defaultProjectUUID(projectUUID)
	now := time.Now().UTC()

	rows := make([]HostObservation, 0, len(obs))
	for _, o := range obs {
		// dnsKey, not an inline ToLower+TrimSpace: it owns the hostname
		// normalization rule, and a writer that normalized differently from a
		// reader would make a stored answer invisible to the caller that wanted it.
		host := dnsKey(o.Hostname)
		if host == "" || o.Empty() {
			continue
		}
		rows = append(rows, HostObservation{
			ProjectUUID: project,
			ScanUUID:    scanUUID,
			Hostname:    host,
			Port:        o.Port,
			ObservedAt:  now,
			DNSA:        o.A,
			DNSAAAA:     o.AAAA,
			DNSCNAME:    o.CNAME,
			DNSMX:       o.MX,
			DNSNS:       o.NS,
			DNSTXT:      o.TXT,
			DNSSOA:      o.SOA,
			DNSCAA:      o.CAA,
			TLS:         o.TLS,
			Fingerprint: o.Fingerprint,
			NotFound:    o.NotFound,
			Favicon:     o.Favicon,
			Complete:    o.Complete,
		})
	}

	// Chunked with slices.Chunk, the same way deleteRecordsByUUIDsTx bounds its
	// statements: a sweep can observe tens of thousands of endpoints, and one
	// statement for all of them builds an enormous query string for no gain.
	for chunk := range slices.Chunk(rows, hostObservationBatchSize) {
		if _, err := r.db.NewInsert().Model(&chunk).
			On("CONFLICT (scan_uuid, hostname, port) DO UPDATE").
			Set("observed_at = EXCLUDED.observed_at").
			Set("dns_a = COALESCE(EXCLUDED.dns_a, ho.dns_a)").
			Set("dns_aaaa = COALESCE(EXCLUDED.dns_aaaa, ho.dns_aaaa)").
			Set("dns_cname = COALESCE(EXCLUDED.dns_cname, ho.dns_cname)").
			Set("dns_mx = COALESCE(EXCLUDED.dns_mx, ho.dns_mx)").
			Set("dns_ns = COALESCE(EXCLUDED.dns_ns, ho.dns_ns)").
			Set("dns_txt = COALESCE(EXCLUDED.dns_txt, ho.dns_txt)").
			Set("dns_soa = COALESCE(EXCLUDED.dns_soa, ho.dns_soa)").
			Set("dns_caa = COALESCE(EXCLUDED.dns_caa, ho.dns_caa)").
			Set("tls = COALESCE(EXCLUDED.tls, ho.tls)").
			Set("fingerprint = COALESCE(EXCLUDED.fingerprint, ho.fingerprint)").
			Set("not_found = COALESCE(EXCLUDED.not_found, ho.not_found)").
			Set("favicon = COALESCE(EXCLUDED.favicon, ho.favicon)").
			Set("complete = EXCLUDED.complete").
			Exec(ctx); err != nil {
			return fmt.Errorf("save host observations: %w", err)
		}
	}
	return nil
}

// HasHostObservations reports whether this database can answer endpoint lookups
// at all.
//
// A database written before this table existed has nothing stored, which is a
// fact about it and not a failure. Asked once up front so a read of an older
// file degrades to the cache-only behaviour silently, instead of failing a query
// per endpoint about a table it was never going to have. A read-only handle
// cannot be migrated into having one either, and missingColumns only tracks
// ALTER-added columns, never whole tables.
func (r *Repository) HasHostObservations(ctx context.Context) bool {
	if r == nil || r.db == nil {
		return false
	}
	return r.db.tableExists(ctx, "host_observations")
}

// LookupHostObservation returns the observation for one endpoint, or zero facts
// when none is stored.
//
// One endpoint per call, rather than loading a run's observations up front.
// Preloading looked right for a streaming emit path - fetch once, then answer
// every record from memory - and was wrong in both directions. This table
// accumulates a row per endpoint per RUN, so the project-wide preload returned
// endpoints × runs rows to build a map of endpoints: on 20k endpoints across 25
// runs, exporting a two-record database peaked at 842 MB against a 120 MB
// baseline, with export memory growing in scan history rather than in the corpus
// being exported. Resolving "latest per endpoint" in SQL instead still cost a
// full scan and a temp b-tree. And a paginated reader (`traffic -j`, 100 rows)
// paid all of it to ask about a handful of hosts.
//
// A point lookup is index-only against idx_host_obs_project_host_id, and the
// caller memoizes, so the cost is one query per DISTINCT endpoint actually
// emitted and the memory is one entry per the same.
//
// scanUUID empty widens the read to the whole project and takes the most
// recently RECORDED observation - the right answer for `export` of a database
// whose runs this process did not perform.
func (r *Repository) LookupHostObservation(ctx context.Context, projectUUID, scanUUID, hostname string, port int) (HostFacts, error) {
	if r == nil || r.db == nil || hostname == "" {
		return HostFacts{}, nil
	}
	row := new(HostObservation)
	// Only the columns HostFacts carries: the fingerprint report and the
	// not-found baseline are the bulk of a row, and this runs per endpoint
	// emitted.
	q := r.db.NewSelect().Model(row).Column("dns_a", "dns_aaaa", "dns_cname", "tls", "favicon").
		Where("project_uuid = ?", defaultProjectUUID(projectUUID)).
		Where("hostname = ?", dnsKey(hostname)).
		Where("port = ?", port)
	if scanUUID != "" {
		// One scan holds at most one observation per endpoint (the unique index),
		// so this is already a single row - no ordering needed, and asking for one
		// would make SQLite open a sorter to order a single row.
		q = q.Where("scan_uuid = ?", scanUUID)
	} else {
		// Highest id, not latest observed_at: id is the insertion order, so this
		// is "most recently recorded", which is well-defined even when two runs
		// stamp the same timestamp.
		q = q.Order("id DESC")
	}
	if err := q.Limit(1).Scan(ctx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return HostFacts{}, nil
		}
		return HostFacts{}, fmt.Errorf("lookup host observation: %w", err)
	}
	return row.Facts(), nil
}

// Facts renders a stored observation back into the output shape. The columns are
// bun jsonb fields, so this is a field copy rather than a decode.
func (o *HostObservation) Facts() HostFacts {
	return HostFacts{A: o.DNSA, AAAA: o.DNSAAAA, CNAME: o.DNSCNAME, TLS: o.TLS, Favicon: o.Favicon}
}

// HostObservationQuery selects host observations for `vigolium hosts`.
type HostObservationQuery struct {
	// ProjectUUID scopes the read; "" reads every project (an unscoped -S read).
	ProjectUUID string
	// ScanUUID limits the read to one run's observations.
	ScanUUID string
	// HostPattern is a hostname, or a pattern with * wildcards.
	HostPattern string
	// History returns every observation; otherwise the latest per endpoint.
	History bool
	// Has keeps rows carrying a fact: "tls", "fingerprint", "not-found",
	// "favicon" or "dns".
	Has string
	// SoftNotFound keeps origins that answer 2xx/3xx to a missing path.
	SoftNotFound bool
	// ObservedFrom and ObservedTo bound observed_at (inclusive); nil is open.
	ObservedFrom *time.Time
	ObservedTo   *time.Time
	Limit        int
	Offset       int
}

// hostPredicate applies HostPattern in any form ParseHostFilter accepts; a
// port narrows to that endpoint (observations carry no scheme).
func (q HostObservationQuery) hostPredicate(sel *bun.SelectQuery) *bun.SelectQuery {
	h := ParseHostFilter(q.HostPattern)
	if h.Host == "" {
		return sel
	}
	if h.Glob() {
		sel = sel.Where(WithLikeEscape("ho.hostname LIKE ?"), LikeGlob(strings.ToLower(h.Host)))
	} else {
		sel = sel.Where("ho.hostname = ?", dnsKey(h.Host))
	}
	if h.Port != 0 {
		sel = sel.Where("ho.port = ?", h.Port)
	}
	return sel
}

// observedRange applies the observed_at bounds.
func (q HostObservationQuery) observedRange(sel *bun.SelectQuery) *bun.SelectQuery {
	if q.ObservedFrom != nil {
		sel = sel.Where("ho.observed_at >= ?", *q.ObservedFrom)
	}
	if q.ObservedTo != nil {
		sel = sel.Where("ho.observed_at <= ?", *q.ObservedTo)
	}
	return sel
}

// hostObservationHas maps a Has value to its predicate.
var hostObservationHas = map[string]string{
	"tls":         "ho.tls IS NOT NULL",
	"fingerprint": "ho.fingerprint IS NOT NULL",
	"not-found":   "ho.not_found IS NOT NULL",
	"favicon":     "ho.favicon IS NOT NULL",
	"dns": "(ho.dns_a IS NOT NULL OR ho.dns_aaaa IS NOT NULL OR ho.dns_cname IS NOT NULL OR ho.dns_mx IS NOT NULL " +
		"OR ho.dns_ns IS NOT NULL OR ho.dns_txt IS NOT NULL OR ho.dns_soa IS NOT NULL OR ho.dns_caa IS NOT NULL)",
}

// HostObservationHasValues are the accepted HostObservationQuery.Has values.
func HostObservationHasValues() []string {
	return slices.Sorted(maps.Keys(hostObservationHas))
}

func (r *Repository) hostObservationQuery(q HostObservationQuery) (*bun.SelectQuery, error) {
	sel := r.db.NewSelect().Model((*HostObservation)(nil))
	if q.ProjectUUID != "" {
		sel = sel.Where("ho.project_uuid = ?", q.ProjectUUID)
	}
	if q.ScanUUID != "" {
		sel = sel.Where("ho.scan_uuid = ?", q.ScanUUID)
	}
	sel = q.observedRange(sel)
	sel = q.hostPredicate(sel)
	if q.Has != "" {
		pred, ok := hostObservationHas[q.Has]
		if !ok {
			return nil, fmt.Errorf("unknown fact %q (want one of %s)", q.Has, strings.Join(HostObservationHasValues(), ", "))
		}
		sel = sel.Where(pred)
	}
	if q.SoftNotFound {
		if r.db.Driver() == driverPostgres {
			sel = sel.Where("(ho.not_found->>'soft_not_found')::boolean IS TRUE")
		} else {
			sel = sel.Where("json_extract(ho.not_found, '$.soft_not_found') = 1")
		}
	}
	if !q.History {
		// The latest observation per endpoint: the highest id is the most
		// recently recorded, which is well-defined even when two runs stamp
		// the same timestamp.
		latest := r.db.NewSelect().Model((*HostObservation)(nil)).ColumnExpr("MAX(ho.id)").Group("ho.hostname", "ho.port")
		if q.ProjectUUID != "" {
			latest = latest.Where("ho.project_uuid = ?", q.ProjectUUID)
		}
		// The same host filter as the outer query, so one host's lookup does
		// not group the whole project's history.
		latest = q.hostPredicate(latest)
		if q.ScanUUID != "" {
			latest = latest.Where("ho.scan_uuid = ?", q.ScanUUID)
		}
		latest = q.observedRange(latest)
		sel = sel.Where("ho.id IN (?)", latest)
	}
	return sel, nil
}

// ListHostObservationsWithCount returns the observations q selects, hostname then
// port order (newest first within an endpoint under History), and the unpaged
// total.
func (r *Repository) ListHostObservationsWithCount(ctx context.Context, q HostObservationQuery) ([]*HostObservation, int, error) {
	if r == nil || r.db == nil || !r.HasHostObservations(ctx) {
		return nil, 0, nil
	}
	sel, err := r.hostObservationQuery(q)
	if err != nil {
		return nil, 0, err
	}
	var rows []*HostObservation
	sel = sel.Order("ho.hostname ASC", "ho.port ASC", "ho.id DESC")
	if q.Limit > 0 {
		sel = sel.Limit(int64(q.Limit))
	}
	if q.Offset > 0 {
		sel = sel.Offset(int64(q.Offset))
	}
	total, err := sel.ScanAndCount(ctx, &rows)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, 0, fmt.Errorf("list host observations: %w", err)
	}
	return rows, int(total), nil
}

// LookupNotFoundBaseline returns the most recently recorded not-found baseline
// for an origin, nil when none is stored.
func (r *Repository) LookupNotFoundBaseline(ctx context.Context, projectUUID, hostname string, port int) (*NotFoundBaseline, error) {
	if r == nil || r.db == nil || hostname == "" {
		return nil, nil
	}
	row := new(HostObservation)
	q := r.db.NewSelect().Model(row).Column("not_found").
		Where("hostname = ?", dnsKey(hostname)).Where("port = ?", port).Where("not_found IS NOT NULL")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if err := q.Order("id DESC").Limit(1).Scan(ctx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("lookup not-found baseline: %w", err)
	}
	return row.NotFound, nil
}
