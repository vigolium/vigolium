package core

import (
	"context"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// scopeClass is the scope rule class that refused the record ("" = in scope).
func (e *Executor) persistAndCheckScope(ctx context.Context, item *work.WorkItem, req *httpmsg.HttpRequestResponse, scopeClass string, redirectHops []*httpmsg.HttpRequestResponse) bool {
	inScope := scopeClass == ""
	if e.cfg.ScopeMatcher != nil {
		if req.Service() == nil {
			return false
		}

		if !inScope {
			e.noteScopeRejected(scopeClass)
		}
		if !inScope && e.cfg.ScopeOnIngest {
			e.noteDrop(req.Target(), DropOutOfScope, nil)
			return false
		}

		e.saveToDatabase(ctx, item, req, redirectHops)
		return inScope
	}

	e.saveToDatabase(ctx, item, req, redirectHops)
	return true
}

// saveToDatabase stores the request/response record in the database if enabled.
func (e *Executor) saveToDatabase(ctx context.Context, item *work.WorkItem, req *httpmsg.HttpRequestResponse, redirectHops []*httpmsg.HttpRequestResponse) {
	if e.repo == nil {
		return
	}
	if item.RecordUUID != "" {
		// Item maps to an existing DB record — reuse its UUID (skip insert) so
		// findings link to it instead of creating a duplicate record. Counted as
		// stored: the question Stored() answers is "is this input in the store",
		// and for a record that CAME from the store the answer is yes.
		e.stored.Add(1)
		e.caches.requestUUIDs.Store(req.Request().ID(), item.RecordUUID)

		// Backfill the response for records stored as request-only stubs (e.g.
		// endpoints synthesized from a discovered OpenAPI/Swagger spec). The
		// executor just fetched a real baseline to scan the endpoint; persist it
		// so the route shows its actual status/body instead of staying at
		// status 0 with an empty response in the traffic view. item.Request is
		// the untouched stub (fetchBaseline returns a copy via
		// WithResponse), so a nil response there marks a stub even though req now
		// carries one. The repo update is a no-op once the record has a response.
		if item.Request != nil && item.Request.Response() == nil && req.Response() != nil {
			if err := e.repo.BackfillRecordResponse(ctx, item.RecordUUID, req); err != nil {
				zap.L().Debug("Failed to backfill stub record response",
					zap.String("uuid", item.RecordUUID), zap.Error(err))
			}
		}
		return
	}

	// Redirect hops first, oldest to newest, so each one's parent already exists
	// by the time its child is written. The last hop's UUID becomes the final
	// record's parent, giving the whole chain one walkable parent_uuid spine.
	//
	// Guarded on len: only a chain-recording phase has hops, and req.Target()
	// rebuilds the URL string, so the unguarded call cost one allocation per
	// saved record across every phase to shape a nil slice.
	target := item.Target
	var parentUUID, rootUUID string
	if len(redirectHops) > 0 {
		parentUUID, rootUUID = e.saveRedirectHops(ctx,
			http.ShapeRedirectChain(redirectHops, req.Target()), target)
	}

	recordUUID, err := e.writeRecord(ctx, req, e.recordSource(), database.RecordLineage{
		ParentUUID: parentUUID,
		RootUUID:   rootUUID,
		Target:     target,
		// The terminal row is truncated when it is itself a 3xx: the transport
		// handed back a redirect as the final response, which means it stopped
		// rather than arrived — the follow cap, the mode's host rule, or the
		// authentication gate. Without the flag that row is indistinguishable
		// from a chain that legitimately ended at a redirect whose destination
		// never answered.
		ChainTruncated: req.Response() != nil && httpmsg.IsRedirectStatus(req.Response().StatusCode()),
		Remarks:        item.Remarks,
	})
	if err != nil {
		e.storeFailed.Add(1)
		e.noteDrop(req.Target(), DropStoreError, err)
		zap.L().Debug("Failed to save record to database", zap.Error(err))
		return
	}
	e.stored.Add(1)
	e.caches.requestUUIDs.Store(req.Request().ID(), recordUUID)
	if e.cfg.OnRecordStored != nil {
		e.cfg.OnRecordStored(recordUUID, req)
	}
}

// saveRedirectHops persists each intermediate redirect response as its own
// record, chained through parent_uuid, and returns the UUID of the LAST hop —
// the parent the final record should point at. Returns "" when there are no
// hops, or when the first write fails.
//
// A hop that fails to write ends the chain rather than aborting the item: the
// final response is the one that carries the evidence, and losing an
// intermediate 301 must not cost the 200 behind it. The chain simply stops at
// the last hop that did persist, which reads correctly as a shorter chain
// rather than as a wrong one.
// It also returns the chain's ROOT uuid — the first hop's — which every row
// carries so "which chain is this" is answerable from a single record instead
// of by walking parent_uuid back to a row the storage cap may have dropped.
func (e *Executor) saveRedirectHops(ctx context.Context, rows []http.ChainRow, target string) (parentUUID, rootUUID string) {
	for _, row := range rows {
		if row.RR == nil || row.RR.Request() == nil {
			continue
		}
		hopUUID, err := e.writeRecord(ctx, row.RR, e.recordSource(), database.RecordLineage{
			ParentUUID:     parentUUID,
			RootUUID:       rootUUID,
			Target:         target,
			ChainTruncated: row.Truncated,
		})
		if err != nil {
			zap.L().Debug("Failed to save redirect hop record",
				zap.String("url", row.RR.Target()), zap.Error(err))
			break
		}
		if rootUUID == "" {
			rootUUID = hopUUID
		}
		parentUUID = hopUUID
	}
	return parentUUID, rootUUID
}

// writeRecord persists one request/response pair, preferring the batched writer
// for throughput and falling back to an individual insert. lineage places the
// row in its redirect chain and names the target it came from; a zero value
// means a standalone record.
//
// The single owner of "which persistence path does this executor use" — finding
// evidence (emitResult) goes through it too, so a change to that choice has one
// place to land.
func (e *Executor) writeRecord(ctx context.Context, req *httpmsg.HttpRequestResponse, source string, lineage database.RecordLineage) (string, error) {
	// Every row this executor inserts belongs to its scan — the item's own
	// record, its redirect hops and finding evidence alike. Applied to new rows
	// only; a dedup hit keeps the scan that stored the exchange first.
	if lineage.ScanUUID == "" {
		lineage.ScanUUID = e.scanUUID
	}
	if e.recordWriter != nil {
		return e.recordWriter.WriteWithLineage(ctx, req, source, e.projectUUID, lineage)
	}
	return e.repo.SaveRecordWithLineage(ctx, req, source, e.projectUUID, lineage)
}

// recordSource is the http_records.source label this executor stamps on the
// records it owns. Finding evidence carries its own record kind instead.
func (e *Executor) recordSource() string {
	if e.cfg.RecordSource == "" {
		return database.RecordSourceScanner
	}
	return e.cfg.RecordSource
}
