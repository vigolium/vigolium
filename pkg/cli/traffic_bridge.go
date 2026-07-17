package cli

import (
	"context"

	"github.com/vigolium/vigolium/pkg/burpbridge"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// recordsQuery builds the records query for a traffic-style listing, projecting
// away the raw request/response unless the caller renders them.
func recordsQuery(db *database.DB, filters database.QueryFilters, includeRaw bool) *database.QueryBuilder {
	qb := database.NewQueryBuilder(db, filters)
	if !includeRaw {
		qb = qb.OmitBodies()
	}
	return qb
}

// queryTrafficRecords is the shared traffic data path for listing, TUI, JSON,
// Markdown, and replay modes. When --burp-bridge-url is set it merges live
// Burp Proxy history with the ordinary database query and applies one global
// sort/page over both sources.
//
// includeRaw declares whether the caller reads the raw request/response off the
// returned records; when false they are left out of the SELECT (see
// QueryBuilder.OmitBodies) rather than hydrated and discarded. Filters still
// apply either way — they run in SQL against the stored columns — so --search
// and friends are unaffected.
func queryTrafficRecords(
	ctx context.Context,
	db *database.DB,
	filters database.QueryFilters,
	includeRaw bool,
) ([]*database.HTTPRecord, int64, error) {
	if trafficBurpBridgeURL == "" || !burpbridge.Eligible(filters) {
		return recordsQuery(db, filters, includeRaw).ExecuteWithCount(ctx)
	}

	fetchFilters := filters
	fetchFilters.Offset = 0
	if filters.Limit > 0 {
		fetchFilters.Limit = filters.Offset + filters.Limit
	}
	local, localTotal, err := recordsQuery(db, fetchFilters, includeRaw).ExecuteWithCount(ctx)
	if err != nil {
		return nil, 0, err
	}

	client, err := burpbridge.New(trafficBurpBridgeURL)
	if err != nil {
		return nil, 0, err
	}
	bridgeQuery := burpbridge.QueryFromFilters(fetchFilters, includeRaw)
	live, bridgeErr := client.Query(ctx, bridgeQuery)
	if bridgeErr != nil {
		// The bridge is an optional source: retain normal database behavior when
		// Burp is closed or the extension listener is temporarily unavailable.
		zap.L().Warn("Burp bridge traffic unavailable; showing database records only", zap.Error(bridgeErr))
	}

	records, total := burpbridge.MergePage(
		local,
		live.Records,
		localTotal,
		live.Total,
		filters.Offset,
		filters.Limit,
		filters.SortBy,
		filters.SortAsc,
	)
	return records, total, nil
}
