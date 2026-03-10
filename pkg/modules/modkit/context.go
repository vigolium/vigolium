package modkit

import (
	"context"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/mutation"
)

// RequestFeeder allows modules to inject discovered requests back into the scanning pipeline.
type RequestFeeder interface {
	// Feed submits a new request for scanning. Returns true if accepted, false if dropped.
	Feed(rr *httpmsg.HttpRequestResponse) bool
}

// RiskScoreUpdater updates risk scores for HTTP records in the database.
type RiskScoreUpdater interface {
	UpdateRiskScores(ctx context.Context, scores map[string]int) error
}

// RemarksAnnotator appends semantic tags (remarks) to HTTP records in the database.
type RemarksAnnotator interface {
	// AppendRemarks merges the given remarks into existing remarks for each record UUID.
	// Duplicate remarks within a record are deduplicated.
	AppendRemarks(ctx context.Context, annotations map[string][]string) error
}

// RequestUUIDResolver resolves a request hash to a database record UUID.
type RequestUUIDResolver interface {
	ResolveRequestUUID(requestHash string) string
}

// OASTProvider generates out-of-band callback URLs for blind vulnerability detection.
type OASTProvider interface {
	GenerateURL(targetURL, paramName, injectionType, moduleID, requestHash string) string
	Enabled() bool
}

// MutationGenerator provides value-aware mutation capabilities.
type MutationGenerator interface {
	Classify(value string, hint *mutation.SchemaHint) mutation.ValueType
	Generate(value string, vtype mutation.ValueType, opts *mutation.GenerateOptions) mutation.MutationSet
}

const baselineCacheSize = 4096

// ScanContext provides shared resources to modules during scanning.
type ScanContext struct {
	DedupManager        *dedup.Manager
	RiskScoreUpdater    RiskScoreUpdater
	RemarksAnnotator    RemarksAnnotator
	RequestUUIDResolver RequestUUIDResolver
	OASTProvider        OASTProvider
	MutationGen         MutationGenerator
	RequestFeeder       RequestFeeder

	baselineOnce  sync.Once
	baselineCache *lru.Cache[string, *BaselineEntry]
}

// getBaselineCache returns the LRU baseline cache, lazily initializing on first use.
func (sc *ScanContext) getBaselineCache() *lru.Cache[string, *BaselineEntry] {
	sc.baselineOnce.Do(func() {
		// lru.New only errors if size <= 0
		sc.baselineCache, _ = lru.New[string, *BaselineEntry](baselineCacheSize)
	})
	return sc.baselineCache
}

// DedupMgr returns the DedupManager or nil safely.
func (sc *ScanContext) DedupMgr() *dedup.Manager {
	if sc == nil {
		return nil
	}
	return sc.DedupManager
}

// OASTProv returns the OASTProvider or nil safely.
func (sc *ScanContext) OASTProv() OASTProvider {
	if sc == nil {
		return nil
	}
	return sc.OASTProvider
}

// Feeder returns the RequestFeeder or nil safely.
func (sc *ScanContext) Feeder() RequestFeeder {
	if sc == nil {
		return nil
	}
	return sc.RequestFeeder
}

// MutGen returns the MutationGenerator or a default implementation if nil.
func (sc *ScanContext) MutGen() MutationGenerator {
	if sc == nil || sc.MutationGen == nil {
		return &defaultMutationGen{}
	}
	return sc.MutationGen
}

// defaultMutationGen is the fallback implementation using the mutation package directly.
type defaultMutationGen struct{}

func (d *defaultMutationGen) Classify(value string, hint *mutation.SchemaHint) mutation.ValueType {
	return mutation.Classify(value, hint)
}

func (d *defaultMutationGen) Generate(value string, vtype mutation.ValueType, opts *mutation.GenerateOptions) mutation.MutationSet {
	return mutation.Generate(value, vtype, opts)
}
