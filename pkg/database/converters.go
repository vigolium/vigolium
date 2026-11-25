package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	neturl "net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/vulnclass"
	"golang.org/x/net/html"
	"golang.org/x/sync/singleflight"
)

const (
	// dnsPositiveTTL / dnsNegativeTTL bound how long a resolved / failed lookup is
	// trusted. A short negative TTL means a host that was briefly unreachable (or
	// resolved after the first miss) is retried soon, rather than being pinned to
	// "" for the process lifetime.
	dnsPositiveTTL = 10 * time.Minute
	dnsNegativeTTL = 30 * time.Second
	// dnsCacheMaxEntries bounds retained entries so a long-lived ingest server
	// scanning huge host sets can't grow the cache without limit.
	dnsCacheMaxEntries = 8192
)

// dnsEntry is a cached resolution with its expiry. A zero-value ip means the
// lookup failed (negative cache).
type dnsEntry struct {
	ip     string
	a      []string // IPv4 addresses
	aaaa   []string // IPv6 addresses
	cname  []string // canonical-name chain (empty when the name is not aliased)
	expiry time.Time

	// cnameChecked distinguishes "this name is not aliased" from "nobody asked".
	// Both leave cname empty, and without the flag they are indistinguishable to
	// the next reader - so an address-only background resolve (the write path,
	// which never wants the chain) would satisfy a later sweep caller that does,
	// and the host's CNAME would be silently missing from the output. The flag is
	// what makes such an entry a miss for a CNAME-wanting caller.
	cnameChecked bool
}

// dnsCache is a bounded, TTL'd hostname → resolution cache (LRU is internally
// synchronized, so no extra lock is needed).
var dnsCache = mustNewDNSCache()

func mustNewDNSCache() *lru.Cache[string, dnsEntry] {
	c, _ := lru.New[string, dnsEntry](dnsCacheMaxEntries)
	return c
}

// dnsGroup collapses concurrent resolves of one hostname into a single lookup
// whose result every caller receives. See resolveAndCache.
var dnsGroup singleflight.Group

// dnsBackgroundSem bounds the one caller that has no bound of its own:
// scheduleHostnameResolve, which spawns a naked goroutine per record on the
// write path, so a broad scan could otherwise fan out into thousands of
// simultaneous resolvers.
//
// It is charged there rather than inside resolveAndCache, which is what lets a
// self-bounded caller resolve at its own width. The probe's prefetch stage runs
// a worker pool capped at probeDNSConcurrencyMax and does nothing else while it
// waits; charging it against this budget too meant its 128 workers funnelled
// into 16 slots, so the stage ran at an eighth of its stated concurrency - and
// because it is a barrier ahead of the first request, that showed up as
// time-to-first-result on every sweep of a large list. A second, wider semaphore
// for those callers would have been ceremony: sized to the prefetch ceiling it
// could never deny a slot, and it coupled a constant here to one in the runner.
var dnsBackgroundSem = make(chan struct{}, 16)

// dnsLookupTimeout bounds one resolution attempt.
//
// net.Resolver applies no deadline of its own without a context, so a lookup
// inherited whatever the system resolver chose - on a misconfigured resolv.conf,
// tens of seconds - while holding a semaphore slot for all of it. A slow
// resolver should cost a slot briefly, not remove it from the pool.
const dnsLookupTimeout = 5 * time.Second

// dnsKey normalizes a hostname into the cache key. Every entry point takes it,
// so the write path and the read path cannot key the same host differently —
// which would make a resolved answer invisible to the reader that wanted it.
func dnsKey(hostname string) string {
	return strings.ToLower(strings.TrimSpace(hostname))
}

// resolveHostnameIP returns the cached IP for a hostname if known and fresh, and
// otherwise returns "" (or a stale value while refreshing) while scheduling the
// DNS lookup in the background.
//
// This deliberately does NOT block on net.LookupHost: it runs on the
// record-write/convert path (RecordWriter.Write -> FromHttpRequestResponse),
// where a dead or slow host would otherwise stall the writer for a full DNS
// timeout (~5s). IP is best-effort metadata, so the first record for a host may
// be persisted without it; once the background resolve completes, every later
// record for that host picks up the cached value. Literal IPs are still
// resolved synchronously (no DNS involved).
func resolveHostnameIP(hostname string) string {
	key := dnsKey(hostname)
	if e, ok := dnsCache.Get(key); ok {
		if time.Now().Before(e.expiry) {
			return e.ip // fresh hit (may be "" for a still-negative host)
		}
		// Expired: refresh off the write path, but serve the stale value meanwhile
		// so records aren't briefly stripped of a known IP on every TTL boundary.
		scheduleHostnameResolve(key)
		return e.ip
	}

	// If the hostname is already an IP address, cache and return it directly.
	if net.ParseIP(key) != nil {
		dnsCache.Add(key, literalIPEntry(key))
		return key
	}

	// Not cached and needs a real DNS lookup: schedule it off the write path.
	scheduleHostnameResolve(key)
	return ""
}

// scheduleHostnameResolve kicks off a background resolve for hostname and
// returns immediately. Address-only: the CNAME chain is read exclusively by the
// host-sweep output path, and asking for it here would double the query volume
// and the semaphore hold of every scan that writes a record, for an answer
// nothing on this path reads.
func scheduleHostnameResolve(key string) {
	// context.Background(): nothing is waiting on this, so there is no caller
	// whose cancellation should end it. Its bound is dnsLookupTimeout, applied
	// inside the flight.
	//
	// The concurrency budget is charged HERE because this is the caller that
	// needs one - a goroutine per record, with nothing else bounding the fan-out.
	// Callers that block on their answer already bound themselves.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
		defer cancel()
		select {
		case dnsBackgroundSem <- struct{}{}:
		case <-ctx.Done():
			return // congestion, not an answer; the next record retries
		}
		defer func() { <-dnsBackgroundSem }()
		_, _ = resolveAndCache(ctx, key, false)
	}()
}

// ResolveHostnameNow resolves hostname synchronously and caches the answer,
// returning the full answer. Returns the cached value when one is fresh.
//
// This is the DNS-prefetch entry point for a host sweep, where DNS is part of
// the ANSWER rather than incidental metadata: the probe phase resolves its whole
// target list through here (bounded, before any HTTP) so every record it writes
// carries a complete A/AAAA/CNAME set. Every other path keeps using the
// background best-effort resolver, because on a normal scan's write path a
// blocking lookup would stall the record writer for a full DNS timeout per dead
// host.
//
// ctx cancels the WAIT, not the lookup: a resolution in flight is shared with
// every other caller asking the same question, so one caller walking away must
// not take the answer with it. The lookup itself is bounded by dnsLookupTimeout.
func ResolveHostnameNow(ctx context.Context, hostname string) (ipv4, ipv6, cname []string) {
	key := dnsKey(hostname)
	if key == "" {
		return nil, nil, nil
	}
	// cnameChecked is part of the hit condition, not just freshness: an entry left
	// by the background write-path resolver is fresh and complete for addresses
	// while carrying no chain, and accepting it here would return the sweep an
	// answer that is missing the half it came for.
	if e, ok := dnsCache.Get(key); ok && e.cnameChecked && time.Now().Before(e.expiry) {
		return e.a, e.aaaa, e.cname
	}
	// Literal IPs need no lookup, and must not be handed to the resolver.
	if net.ParseIP(key) != nil {
		e := literalIPEntry(key)
		dnsCache.Add(key, e)
		return e.a, e.aaaa, e.cname
	}
	// The chain is returned, not just the addresses: the sweep wants the whole
	// answer, and resolveAndCache already has it in hand. Returning half of it
	// forced the caller into a second CachedDNS round trip to read back the entry
	// this call had just written.
	entry, _ := resolveAndCache(ctx, key, true)
	return entry.a, entry.aaaa, entry.cname
}

// resolveAndCache performs one resolution per hostname at a time and gives every
// concurrent caller the SAME answer.
//
// singleflight rather than a hand-rolled in-flight claim: a claim only
// suppresses the duplicate query, it does not share the result, so a prefetch
// that lost the race to the background write-path resolver returned empty — the
// host was counted unresolved and its record carried no addresses, which is the
// exact failure the prefetch stage exists to remove. Do makes the loser block on
// and receive the winner's entry.
//
// wantCNAME asks for the canonical-name chain as well. It is a parameter rather
// than always-on because the CNAME is a second query, and only the sweep's
// output reads it.
//
// ctx bounds how long THIS caller waits. The flight itself deliberately runs on
// a detached context: singleflight hands one lookup's result to every caller
// waiting on it, so honouring the first caller's cancellation would cancel the
// resolution out from under all the others. dnsLookupTimeout is what bounds the
// flight, and an abandoned flight still finishes and populates the cache, which
// is the useful outcome for the next caller.
func resolveAndCache(ctx context.Context, key string, wantCNAME bool) (dnsEntry, error) {
	// The singleflight key carries wantCNAME. Sharing one flight per hostname
	// meant an in-flight address-only resolve could hand its (chain-less) result
	// to a caller that asked for the chain - the same completeness hole as the
	// cache read, one layer up. Two concurrent lookups for one host is the price,
	// and only for the rare overlap of a sweep and a write-path resolve.
	group := key
	if wantCNAME {
		group = key + "\x00cname"
	}
	ch := dnsGroup.DoChan(group, func() (any, error) {
		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dnsLookupTimeout)
		defer cancel()
		entry := lookupHostname(lctx, key, wantCNAME)
		entry.cnameChecked = wantCNAME
		if !wantCNAME {
			// Carry forward a chain this process already observed rather than
			// overwriting it with "unknown": an address-only refresh learns
			// nothing about aliasing, so it has no business unlearning it.
			if prev, ok := dnsCache.Get(key); ok && prev.cnameChecked {
				entry.cname = prev.cname
				entry.cnameChecked = true
			}
		}
		dnsCache.Add(key, entry)
		return entry, nil
	})
	select {
	case <-ctx.Done():
		return dnsEntry{}, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return dnsEntry{}, res.Err
		}
		entry, _ := res.Val.(dnsEntry)
		return entry, nil
	}
}

// CachedDNS returns the full DNS answer this PROCESS resolved for hostname, or
// nothing when it never looked it up (or the entry has aged out).
//
// Deliberately not persisted. `ip` — one address per record — is the only DNS
// the schema stores. A host sweep writes many records per host (a redirect chain
// alone is three), and a corpus of thousands of records across a few hundred
// hosts would otherwise store the same A/AAAA/CNAME arrays thousands of times,
// inflating the database for data that is identical on every row and stale the
// moment the TTL expires. Resolving is cheap and repeatable; storing it is not.
//
// So this is a read-time attachment: the run that did the resolving reports the
// full answer inline in its output, and reading the same database back later in
// a fresh process correctly shows only `ip`. Expiry is deliberately NOT checked
// — this reports what was resolved for the records being emitted, and a sweep
// long enough to cross the TTL should still describe the rows it wrote.
func CachedDNS(hostname string) (a, aaaa, cname []string) {
	key := dnsKey(hostname)
	if key == "" {
		return nil, nil, nil
	}
	e, ok := dnsCache.Get(key)
	if !ok {
		return nil, nil, nil
	}
	return e.a, e.aaaa, e.cname
}

// lookupHostname performs the actual resolution: addresses split by family, plus
// the CNAME chain. Never returns an error — a failure is a negative cache entry,
// which is the same thing every caller does with it.
//
// ip is the FIRST address, matching what the single `ip` column has always
// meant. IPv4 is preferred for it because that is what the dialer will almost
// always pick on a dual-stack host, so the column keeps describing where the
// request actually went.
func lookupHostname(ctx context.Context, hostname string, wantCNAME bool) dnsEntry {
	entry := dnsEntry{expiry: time.Now().Add(dnsNegativeTTL)}

	// The Resolver's context form, not the package-level net.LookupHost: that one
	// takes no deadline and inherits whatever the system resolver was configured
	// with, so a misconfigured resolv.conf turned every dead host into a
	// multi-second hold on a concurrency slot that nothing could interrupt.
	addrs, err := net.DefaultResolver.LookupHost(ctx, hostname)
	if err == nil {
		for _, a := range addrs {
			switch ip := net.ParseIP(a); {
			case ip == nil:
				continue
			case ip.To4() != nil:
				entry.a = append(entry.a, a)
			default:
				entry.aaaa = append(entry.aaaa, a)
			}
		}
	}
	switch {
	case len(entry.a) > 0:
		entry.ip = entry.a[0]
	case len(entry.aaaa) > 0:
		entry.ip = entry.aaaa[0]
	}
	if entry.ip != "" {
		entry.expiry = time.Now().Add(dnsPositiveTTL)
	}

	// A name that is its own canonical name is not aliased; reporting it as a
	// CNAME of itself would be noise on every non-aliased host. LookupCNAME
	// returns a trailing dot.
	if !wantCNAME {
		return entry
	}
	if cname, cerr := net.DefaultResolver.LookupCNAME(ctx, hostname); cerr == nil {
		if trimmed := strings.TrimSuffix(cname, "."); trimmed != "" && !strings.EqualFold(trimmed, hostname) {
			entry.cname = []string{trimmed}
		}
	}
	return entry
}

// literalIPEntry builds the cache entry for a hostname that is already an IP
// literal: it resolves to itself, in its own family, with no CNAME.
func literalIPEntry(hostname string) dnsEntry {
	// cnameChecked: an address is not a name and cannot be aliased, so the empty
	// chain is a final answer rather than an unasked question. Without it every
	// IP-literal target would re-resolve on each sweep read.
	e := dnsEntry{ip: hostname, expiry: time.Now().Add(dnsPositiveTTL), cnameChecked: true}
	if ip := net.ParseIP(hostname); ip != nil && ip.To4() != nil {
		e.a = []string{hostname}
	} else {
		e.aaaa = []string{hostname}
	}
	return e
}

// FromHttpRequestResponse populates an HTTPRecord from httpmsg.HttpRequestResponse.
//
// The record OWNS its RawRequest/RawResponse: both are copied out of the source
// message rather than aliased. This is a lifetime requirement, not a style
// choice. A converted record routinely outlives the call that produced it —
// RecordWriter.admit hands it to a shard channel and returns, the flush goroutine
// inserts it later, and Repository.emitRecordSaved passes it to the filesystem
// mirror, which writes it from yet another goroutine. Meanwhile the executor
// builds its responses over a POOLED buffer (see pkg/core, getResponseBuffer)
// that processItem returns to the pool as soon as it is done with the item.
// Aliasing therefore let a record be persisted or mirrored with another
// response's bytes whenever the write outlived the caller — on scan cancellation
// the caller stops waiting while the record is still queued, which is exactly
// when this happened.
//
// The copy (bytes.Clone below) costs one memcpy per converted record, which is
// small next to the two SHA-256 passes below, and is only paid for records that
// get enriched at all.
//
// Conversion is split in two halves, and a caller that deduplicates should use
// them separately rather than calling this: PrepareIdentity fills only the
// columns that decide WHICH row this is, and EnrichFromHttpRequestResponse does
// the expensive response-derived work. See PrepareIdentity.
func (r *HTTPRecord) FromHttpRequestResponse(ctx *httpmsg.HttpRequestResponse) error {
	if err := r.PrepareIdentity(ctx); err != nil {
		return err
	}
	return r.EnrichFromHttpRequestResponse(ctx)
}

// PrepareIdentity fills the columns that establish a record's identity — the
// ones recordDedupKey builds its key from and findDuplicateRecordUUIDs matches
// on — and nothing else. Cheap: a URL parse, a few header reads, and one SHA-256
// over the raw request.
//
// It exists so a duplicate can be recognized WITHOUT paying for enrichment.
// EnrichFromHttpRequestResponse runs two more passes over the response body
// (a normalized-body-hash regex, a word count), tokenizes HTML to pull out a
// title, and copies the raw bytes. Profiling a 64 KiB HTML response put ~57% of
// conversion CPU in the normalizing regex alone, and the whole conversion at
// ~2.6ms and ~786 KiB allocated. On duplicate-heavy ingestion — discovery and
// spidering re-encountering the same URLs, which is the case the dedup cache was
// added for — all of that was spent on records thrown away microseconds later.
//
// Deliberately NOT here: hostname resolution. The IP is stored metadata, not
// identity, and scheduling it from this half would spawn a background DNS
// goroutine for every duplicate too.
//
// Callers must set Source (and ProjectUUID) before building a dedup key from the
// result: recordDedupKey consults both.
func (r *HTTPRecord) PrepareIdentity(ctx *httpmsg.HttpRequestResponse) error {
	if ctx == nil || ctx.Request() == nil {
		return fmt.Errorf("invalid HttpRequestResponse")
	}

	req := ctx.Request()
	u, err := ctx.URL()
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}

	// Host info
	r.Scheme = u.Scheme
	r.Hostname = u.Hostname()
	port := 0
	if u.Port() != "" {
		// strconv, not fmt.Sscanf: this runs for every record before the dedup
		// check, and Sscanf costs ~1us and several allocations (the &port escapes
		// through an `any`) where Atoi costs ~20ns and none.
		port, _ = strconv.Atoi(u.Port())
	} else if u.Scheme == "https" {
		port = 443
	} else {
		port = 80
	}
	r.Port = port

	// Request fields
	r.Method = req.Method()
	r.Path = req.Path()
	r.HTTPVersion = "HTTP/1.1"
	r.URL = u.String()

	r.RequestContentType = req.Header("Content-Type")
	r.RequestContentLength = int64(len(req.Body()))

	// Request hash. Hashing reads the raw bytes without retaining them, so this
	// half can work straight off the caller's buffer; the owned copy is taken in
	// the enrichment half, which is where the record starts outliving its caller.
	hash := sha256.Sum256(req.Raw())
	r.RequestHash = hex.EncodeToString(hash[:])
	r.RequestIdentityHash = requestIdentityHash(req.Header("Authorization"), req.Header("Cookie"))

	return nil
}

// requestIdentityHash is the principal half of a body-less request's dedup
// identity: a short SHA-256 of the Authorization and Cookie values, "" when
// the request sent neither. Hashed rather than stored so the column never
// holds a credential; the full values stay in raw_request, where they always
// were.
func requestIdentityHash(authorization, cookie string) string {
	if authorization == "" && cookie == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("authorization\x00" + authorization + "\x00cookie\x00" + cookie))
	return hex.EncodeToString(sum[:16])
}

// EnrichFromHttpRequestResponse fills everything PrepareIdentity left out: the
// owned raw bytes, all response-derived columns, request authorization,
// parameters, resolved IP, and timestamps. Run it only for a record that is
// actually going to be stored. Safe to call on a record whose identity half has
// already run; it does not recompute it.
func (r *HTTPRecord) EnrichFromHttpRequestResponse(ctx *httpmsg.HttpRequestResponse) error {
	if ctx == nil || ctx.Request() == nil {
		return fmt.Errorf("invalid HttpRequestResponse")
	}

	req := ctx.Request()

	// The UUID is assigned here, not in PrepareIdentity: nothing between the two
	// halves reads it (recordDedupKey does not), so generating one for a record
	// the dedup cache is about to discard would burn a crypto/rand read and a
	// 36-byte string per duplicate.
	r.UUID = uuid.New().String()

	// A row with no chain above it is its own chain root, so root_uuid is never
	// empty on a stored record and "every row of this chain" is one equality
	// test. Resolved HERE rather than in RecordLineage.applyTo because the
	// batched writer applies lineage during PrepareIdentity, before the UUID
	// this falls back to exists.
	if r.RootUUID == "" {
		r.RootUUID = r.UUID
	}

	// Resolve hostname to IP (cached per hostname). Only the single address is
	// persisted; the full A/AAAA/CNAME sets stay in the process-local cache and
	// are attached at serialization time (see CachedDNS) so a corpus of many
	// records per host does not store the same answer thousands of times.
	if ip := resolveHostnameIP(r.Hostname); ip != "" {
		r.IP = ip
	}

	// Request authorization (prefer Authorization header, fall back to Cookie)
	if auth := req.Header("Authorization"); auth != "" {
		r.RequestAuthorization = auth
	} else if cookie := req.Header("Cookie"); cookie != "" {
		r.RequestAuthorization = cookie
	}

	r.RawRequest = bytes.Clone(req.Raw())

	// Response (if available)
	if ctx.HasResponse() {
		resp := ctx.Response()
		// An ingested body still in its wire coding is stored decoded, and
		// every column below is derived from the stored bytes
		// (response_decode.go).
		if raw, coding, ok := decodeStoredResponse(resp); ok {
			resp = httpmsg.NewHttpResponseWithDuration(raw, resp.Duration())
			r.ResponseDecodedFrom = coding
		}
		r.HasResponse = true
		r.StatusCode = resp.StatusCode()
		r.ResponseHTTPVersion = extractResponseHTTPVersion(resp.Raw())

		r.ResponseContentType = resp.Header("Content-Type")
		r.RawResponse = bytes.Clone(resp.Raw())

		// The redirect destination, parsed once here rather than re-read out of
		// raw_response every time a tree renders. Stored verbatim: a relative
		// Location stays relative, since resolving it would record a URL the
		// server never sent.
		if IsRedirectStatus(r.StatusCode) {
			r.ResponseLocation = strings.TrimSpace(resp.Header("Location"))
		}

		cols := deriveResponseColumns(resp, r.ResponseContentType, r.Path, r.URL)
		r.ResponseTitle = cols.Title
		r.ResponseWords = cols.Words
		r.ResponseHash = cols.Hash
		r.ResponseNormHash = cols.NormHash
		r.ResponseContentLength = cols.ContentLength

		// Zero stays zero and means "not measured"; see httpmsg.MeasuredMillis,
		// which owns that rule for every column that stores it.
		r.ResponseTimeMs = httpmsg.MeasuredMillis(resp.Duration())

		r.ReceivedAt = time.Now()
	} else {
		// First written without a response: a template, not an exchange.
		// Only an insert reads this; the backfill and snapshot updates name
		// their columns and never clear it.
		at := time.Now()
		r.RequestOnlyAtStore = &at
	}

	// Parameters
	params, err := req.Parameters()
	if err == nil && len(params) > 0 {
		r.Parameters = embeddedParams(params)
	}

	// Timestamps
	r.SentAt = time.Now()

	return nil
}

// responseColumns are the http_records columns derived from a stored response.
type responseColumns struct {
	Hash          string // response_hash: sha256 of the stored raw bytes
	NormHash      string // response_norm_hash
	Words         int64  // response_words
	ContentLength int64  // response_content_length: the stored body's length
	Title         string // response_title; "" unless contentType names HTML
}

// deriveResponseColumns computes the response-derived columns from resp, the
// response exactly as it is stored. It is the one derivation behind
// EnrichFromHttpRequestResponse, the decoded-response backfill and
// OverwriteRecordResponseBody, so a record rewritten by any of them hashes as
// one ingested with the same bytes would. path and url feed the normalized
// hash; the title is only extracted when contentType names HTML.
func deriveResponseColumns(resp *httpmsg.HttpResponse, contentType, path, url string) responseColumns {
	body := resp.Body()
	sum := sha256.Sum256(resp.Raw())
	c := responseColumns{
		Hash:  hex.EncodeToString(sum[:]),
		Words: countResponseWords(body, resp.Headers()),
		// Reflected-URL-robust signature: strip the request path/URL the
		// response may echo back (e.g. an error page that mirrors the requested
		// URI) and collapse dynamic runs, so probes that differ only by the
		// reflected target dedup together instead of surviving as N
		// near-identical records. BodyToString is memoized on the response, and
		// the passive stage has usually materialized it already — string(body)
		// would copy the whole body again for an identical value, and so an
		// identical hash.
		NormHash:      modkit.NormalizedBodyHash(resp.BodyToString(), path, url),
		ContentLength: int64(len(body)),
	}
	if strings.Contains(strings.ToLower(contentType), "html") {
		c.Title = extractHTMLTitle(body)
	}
	return c
}

// embeddedParams converts parsed request parameters to their stored form.
func embeddedParams(params []*httpmsg.Param) []EmbeddedParam {
	out := make([]EmbeddedParam, 0, len(params))
	for _, p := range params {
		ep := EmbeddedParam{
			Name:       p.Name(),
			Value:      p.Value(),
			Type:       ParameterTypeFromParamType(p.Type()),
			NameStart:  p.NameStart(),
			NameEnd:    p.NameEnd(),
			ValueStart: p.ValueStart(),
			ValueEnd:   p.ValueEnd(),
		}
		// A JSON body value keeps where it sits (its dotted key path, the
		// parser's Param.Metadata) and its JSON type, which `params --paths`
		// aggregates into the operation's body shape.
		if p.Type() == httpmsg.ParamJSON {
			ep.Metadata = p.Metadata()
			ep.JSONType = JSONTypeName(p.JSONType())
		}
		out = append(out, ep)
	}
	return out
}

// FromResultEvent converts output.ResultEvent to Finding
func (f *Finding) FromResultEvent(event *output.ResultEvent) error {
	if event == nil {
		return fmt.Errorf("invalid ResultEvent")
	}

	f.ModuleID = event.ModuleID
	f.ModuleName = event.Info.Name
	f.Description = event.Info.Description
	f.Severity = event.Info.Severity.String()
	f.Confidence = event.Info.Confidence.String()
	f.Tags = event.Info.Tags

	f.URL = firstNonEmpty(event.URL, event.Matched)
	f.Hostname = resolveFindingHostname(event.Host, event.URL, event.Matched)

	if event.Matched != "" {
		f.MatchedAt = []string{event.Matched}
	}
	f.ExtractedResults = event.ExtractedResults

	f.Request = event.Request
	f.Response = event.Response
	// Static assets (JS/CSS/source maps) can be megabytes; on a finding we only
	// need the matched region in context. Store the response head (status line +
	// headers) verbatim plus a window of the body around the match. event.Response
	// is left untouched so the linked http_record still carries the full body for
	// display. Non-static responses are stored whole.
	if windowed, ok := windowStaticFindingResponse(f.URL, event.Response, event.ExtractedResults); ok {
		f.Response = windowed
	}
	// Cap evidence carried straight off the event (modules that collect many
	// request/response pairs themselves, e.g. OAST/timing collectors) to the same
	// ceiling the dedup merge paths enforce, so a single finding never persists an
	// unbounded payload.
	f.AdditionalEvidence = event.AdditionalEvidence
	if len(f.AdditionalEvidence) > maxAdditionalEvidence {
		f.AdditionalEvidence = f.AdditionalEvidence[:maxAdditionalEvidence]
	}
	f.ModuleType = event.ModuleType
	f.FindingSource = event.FindingSource
	f.RecordKind = string(event.EffectiveRecordKind())
	f.EvidenceGrade = string(event.EvidenceGrade)
	f.ModuleShort = event.ModuleShort

	// Classification: native modules already publish a CWE in the result event's
	// metadata map (Metadata["cwe"], e.g. "CWE-79"), but the finding's cwe_id
	// column — which exists and is rendered in reports — was never populated from
	// native results. Surface it so console/JSON/HTML/DB/API all carry it.
	f.CWEID = cweFromMetadata(event.Metadata)
	// The reported class: the result's own (an OAST callback names the class
	// its payload was minted for), else the module's declared one.
	f.VulnClass = string(vulnclass.ForFinding(vulnclass.Class(event.VulnClass), event.ModuleID))
	// The severity the module asked for when the emit-time rule filed the
	// finding lower (core.clampTentativeSeverity), so a reader can weigh the
	// module's claim without the stored severity overstating the proof.
	f.ClaimedSeverity = claimedSeverityFromMetadata(event.Metadata, f.Severity)
	f.Principals = principalsFromMetadata(event.Metadata)

	// Replay context for `finding verify` (see output.ResultEvent).
	f.OriginRecordUUID = event.OriginRecordUUID
	if event.InsertionPointType != "" || event.FuzzingParameter != "" {
		f.InsertionPoint = &FindingInsertionPoint{Type: event.InsertionPointType, Name: event.FuzzingParameter}
	}
	f.Payload = event.Payload
	f.Proof = event.Proof

	f.FindingHash = event.ID()
	f.FoundAt = time.Now()

	// Native scan results come from deterministic engines — they're trusted by
	// default and skip the triage queue. Caller may override (e.g. user import).
	f.Status = StatusTriaged

	return nil
}

// principalsFromMetadata returns the sessions a cross-session result compares,
// primary first: Metadata["primary_session"] then Metadata["compare_session"].
// Nil when the result names no compare session.
func principalsFromMetadata(meta map[string]interface{}) []string {
	compare, _ := meta["compare_session"].(string)
	if strings.TrimSpace(compare) == "" {
		return nil
	}
	primary, _ := meta["primary_session"].(string)
	if strings.TrimSpace(primary) == "" {
		return []string{"", compare}
	}
	return []string{primary, compare}
}

// claimedSeverityFromMetadata returns Metadata["claimed_severity"] when it
// names a severity other than the stored one, "" otherwise: a claim equal to
// the stored severity says nothing.
func claimedSeverityFromMetadata(meta map[string]interface{}, stored string) string {
	v, ok := meta["claimed_severity"].(string)
	if !ok {
		return ""
	}
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" || strings.EqualFold(v, stored) {
		return ""
	}
	return v
}

// cweFromMetadata extracts a CWE identifier from a ResultEvent's metadata map.
// Native modules publish it as Metadata["cwe"], typically a single "CWE-nnn"
// string; a slice of strings/interfaces is joined. Returns "" when absent.
func cweFromMetadata(meta map[string]interface{}) string {
	if len(meta) == 0 {
		return ""
	}
	v, ok := meta["cwe"]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case []string:
		return joinNonEmpty(t)
	case []interface{}:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				parts = append(parts, s)
			}
		}
		return joinNonEmpty(parts)
	}
	return ""
}

// joinNonEmpty trims each element and joins the non-empty ones with ", ".
func joinNonEmpty(in []string) string {
	parts := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, ", ")
}

// windowStaticFindingResponse returns a size-bounded copy of a finding's raw
// response when it belongs to a static asset (JS/CSS/source map/font/image/...),
// keeping the response head verbatim and windowing the body around the matched
// value (locators). It reports ok=false — leaving the caller's full response in
// place — for non-static content, an unparsable response head, an empty response,
// or a body small enough to store whole. Static-ness is decided by Content-Type,
// falling back to the URL's file extension so source maps served as
// application/json are still caught.
func windowStaticFindingResponse(findingURL, rawResponse string, locators []string) (string, bool) {
	opts := modkit.DefaultResponseWindowOpts()
	// Cheap pre-gate on the raw length: the body can't exceed the whole response,
	// so anything at or below the threshold is never windowed. This skips the
	// full-response copy and parse for the common small-response finding.
	if len(rawResponse) <= opts.FullThreshold {
		return "", false
	}

	resp := httpmsg.NewHttpResponse([]byte(rawResponse))
	head := resp.Head()
	if len(head) == 0 {
		return "", false // unparsable head — don't risk dropping it
	}
	body := resp.Body()
	if len(body) <= opts.FullThreshold {
		return "", false // body fits whole — keep the original, skip the rebuild
	}

	static := modkit.IsStaticAssetContentType(resp.Header("Content-Type"))
	if !static && findingURL != "" {
		if u, err := neturl.Parse(findingURL); err == nil {
			static = modkit.HasStaticAssetExtension(u.Path)
		}
	}
	if !static {
		return "", false
	}

	return string(head) + modkit.WindowBody(body, locators, 0, opts), true
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// resolveFindingHostname picks the hostname for a finding, preferring the
// explicit Host field on the event, then parsing the URL or matched-at value.
func resolveFindingHostname(host, url, matched string) string {
	if host != "" {
		// event.Host is populated inconsistently by modules: some set the bare host
		// ("localhost"), others the authority with port ("localhost:3000"). The
		// findings table carries no port column, and the scan-completion summary +
		// hostname filters (CountFindingsBySeverity, GetFindingsByHostname) all match
		// the bare hostname stored on http_records. Normalize to the bare host so a
		// port-bearing event.Host doesn't get filtered out of those queries.
		return stripHostPort(host)
	}
	for _, candidate := range []string{url, matched} {
		if candidate == "" {
			continue
		}
		if parsed, err := neturl.Parse(candidate); err == nil && parsed.Hostname() != "" {
			return parsed.Hostname()
		}
	}
	return ""
}

// stripHostPort returns the bare host from an authority value, dropping any
// ":port" suffix. Handles IPv6 literals ("[::1]:3000" → "::1") and bare hosts
// (no port) unchanged. Parsing as "//host" lets net/url do the host[:port]
// (and bracketed-IPv6) splitting without us reimplementing it.
func stripHostPort(host string) string {
	if host == "" {
		return ""
	}
	if parsed, err := neturl.Parse("//" + host); err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	// Fallback: parse failed (e.g. an unusual value) — keep the original so we
	// never lose the host entirely.
	return host
}

// extractResponseHTTPVersion extracts the HTTP version from the raw response status line.
// Falls back to "HTTP/1.1" if parsing fails or the version is missing/invalid
// (e.g. "HTTP/0.0", which Go's http.Response.Write produces for responses with
// unset ProtoMajor/ProtoMinor).
func extractResponseHTTPVersion(raw []byte) string {
	if len(raw) == 0 {
		return "HTTP/1.1"
	}
	// Find end of first line (status line)
	end := bytes.IndexByte(raw, '\n')
	if end < 0 {
		end = len(raw)
	}
	line := string(raw[:end])
	// Status line format: "HTTP/1.1 200 OK" — version is the first space-delimited token
	if idx := strings.IndexByte(line, ' '); idx > 0 {
		version := strings.TrimSpace(line[:idx])
		if isValidHTTPVersion(version) {
			return version
		}
	}
	return "HTTP/1.1"
}

// isValidHTTPVersion reports whether v looks like a real HTTP version token.
// Rejects empty/malformed values and "HTTP/0.x" (which standard library
// rendering emits for responses missing ProtoMajor/ProtoMinor).
func isValidHTTPVersion(v string) bool {
	if !strings.HasPrefix(v, "HTTP/") {
		return false
	}
	rest := v[len("HTTP/"):]
	if rest == "" {
		return false
	}
	// Major version is the leading digit(s). Require at least one non-zero digit.
	major := rest
	if dot := strings.IndexByte(rest, '.'); dot >= 0 {
		major = rest[:dot]
	}
	if major == "" {
		return false
	}
	for _, r := range major {
		if r < '0' || r > '9' {
			return false
		}
	}
	return strings.Trim(major, "0") != ""
}

// titleScanLimit bounds how far into a body the title scan reads. A title lives
// in the head, so a document that has not declared one within this much markup
// does not have one worth recording — and stopping here keeps a multi-megabyte
// minified bundle or data blob from being walked for a field it cannot contain.
const titleScanLimit = 256 << 10 // 256 KiB

// maxTitleLength caps the stored title. Longer values are a page dumping
// content into the element, not a name for it.
const maxTitleLength = 512

// extractHTMLTitle returns the text of the first <title> element in an HTML
// body, trimmed and capped. Empty when the body declares none.
//
// Tokenized rather than parsed: this runs once per stored HTML response, and
// building a whole DOM to read one element in the head meant walking every byte
// of the document and allocating a node per tag — 896us and 15,960 allocations
// on a 64 KiB body, against 1.8us and 9 for a scan that stops at the title.
//
// The tokenizer sees the same title the parser did on every case that
// distinguishes them, because <title> is RCDATA: its content is raw text to the
// tokenizer exactly as it is to the parser, so markup inside it stays literal,
// and a <title> written inside a comment or a <script> is never emitted as a
// start tag at all. See TestExtractHTMLTitle.
func extractHTMLTitle(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	if len(body) > titleScanLimit {
		body = body[:titleScanLimit]
	}

	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		switch z.Next() {
		case html.ErrorToken:
			// EOF, or malformed markup the tokenizer could not carry on past.
			// Either way no title was reached.
			return ""
		case html.StartTagToken:
			if name, _ := z.TagName(); string(name) != "title" {
				continue
			}
			return readTitleText(z)
		}
	}
}

// readTitleText accumulates the text tokens inside an open <title> up to its end
// tag, EOF, or the length cap.
func readTitleText(z *html.Tokenizer) string {
	var b strings.Builder
	for {
		switch z.Next() {
		case html.TextToken:
			// Bounded as it accumulates: a page that never closes the element
			// would otherwise buffer the rest of the document for a value about
			// to be truncated to maxTitleLength anyway. The margin leaves room
			// for leading whitespace that the trim below removes.
			if b.Len() < 2*maxTitleLength {
				b.Write(z.Text())
			}
		default:
			// An end tag closes it; an error token means EOF or malformed
			// markup, and whatever text was gathered is still the title.
			title := strings.TrimSpace(b.String())
			if len(title) > maxTitleLength {
				title = title[:maxTitleLength]
			}
			return title
		}
	}
}

// countResponseWords counts whitespace-delimited words in the response body and headers.
// Uses byte-level scanning to avoid allocating a string copy or []string slice.
func countResponseWords(body []byte, headers []httpmsg.HttpHeader) int64 {
	count := int64(countWordsBytes(body))
	for _, h := range headers {
		count += int64(countWordsString(h.Name))
		count += int64(countWordsString(h.Value))
	}
	return count
}

// countWordsBytes counts whitespace-delimited words in a byte slice without allocations.
func countWordsBytes(b []byte) int {
	n := 0
	inWord := false
	for _, c := range b {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
			inWord = false
		} else if !inWord {
			inWord = true
			n++
		}
	}
	return n
}

// countWordsString counts whitespace-delimited words in a string without allocations.
func countWordsString(s string) int {
	n := 0
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
			inWord = false
		} else if !inWord {
			inWord = true
			n++
		}
	}
	return n
}

// ParameterTypeFromParamType converts ParamType to database parameter type string
func ParameterTypeFromParamType(ptype httpmsg.ParamType) string {
	switch ptype {
	case httpmsg.ParamURL:
		return "url"
	case httpmsg.ParamBody, httpmsg.ParamBodyMultipart:
		return "body"
	case httpmsg.ParamJSON:
		return "json"
	case httpmsg.ParamXML, httpmsg.ParamXMLAttr:
		return "xml"
	case httpmsg.ParamCookie:
		return "cookie"
	case httpmsg.ParamPathFolder, httpmsg.ParamPathFilename:
		return "path"
	case httpmsg.ParamMultipartAttr:
		return "multipart"
	default:
		return "unknown"
	}
}
