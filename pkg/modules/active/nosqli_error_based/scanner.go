package nosqli_error_based

import (
	"fmt"
	"regexp"

	"github.com/pkg/errors"
	httputil "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// nosqlError defines a database error pattern.
type nosqlError struct {
	dbms    string
	pattern *regexp.Regexp
	// weak marks generic English / JS-ish phrasing and lone operator tokens
	// (e.g. a bare "$expr", an "unknown operator" phrase) that legitimately occur
	// inside ordinary source code or JSON data, not only in a driver error. A
	// weak match is believed ONLY when the body ALSO carries an independent
	// database/error-context marker (dbErrorContext); the strong driver/class
	// signatures below stay trustworthy on their own. The motivating false
	// positive: a minified pdf.js worker (served application/javascript) whose
	// code contained an "$expr"/"expression"-shaped token tripped the old single
	// combined Mongo pattern.
	weak bool
}

// errorPatterns are DBMS error signatures. Every token must be specific enough
// that a real application body cannot plausibly carry it inside a random
// per-request token — the bare 4-/6-char forms "BSON", "mongod", "couchdb" and
// the generic English phrases "bad query" / "invalid operator" matched
// base64/SPA noise (a Salesforce community 404 shell and a Cloudflare challenge
// both tripped (?i)BSON on a random token), so they are replaced with their
// genuine driver/error-context forms.
var errorPatterns = []nosqlError{
	// --- Strong: unique driver / server / class signatures and distinctive
	// error phrases. These do not occur in ordinary code or data, so they fire
	// on their own. ---
	// MongoDB driver / server error class names (CamelCase — does not occur in
	// random base64) and import paths.
	{"MongoDB", regexp.MustCompile(`(?i)\bMongo(?:Error|ServerError|ServerSelectionError|NetworkError|NetworkTimeoutError|WriteError|BulkWriteError|ParseError|CommandError|InvalidOperationException)\b`), false},
	{"MongoDB", regexp.MustCompile(`(?i)\bMongoClient\b|com\.mongodb|\bpymongo\b|\bmongoose\b|\bTopologyDescription\b|mongodb://`), false},
	// BSON only in genuine error/type contexts, never the bare token.
	{"MongoDB", regexp.MustCompile(`(?i)\bBSON(?:Error|Obj|Type|Element|Document|TooLarge)\b|invalid BSON|BSON field|\bbson\.(?:M|D|E|A|ObjectI[dD]|Raw)\b`), false},
	// Distinctive Mongo query/operator error messages.
	{"MongoDB", regexp.MustCompile(`(?i)E11000 duplicate key|cannot index parallel arrays|\$where\b[^.]{0,40}\brequires\b|Cannot apply \$?\w+ update operator`), false},
	{"CouchDB", regexp.MustCompile(`(?i)org\.apache\.couchdb|"error":"bad_request"|"reason":"invalid_json"|"error":"illegal_database_name"|"reason":"invalid UTF-8 JSON"`), false},
	{"Cassandra", regexp.MustCompile(`(?i)com\.datastax\.driver|InvalidRequestException|SyntaxException.{0,40}CQL|no viable alternative at input`), false},
	{"DynamoDB", regexp.MustCompile(`(?i)com\.amazonaws\.services\.dynamodbv2|ValidationException.{0,40}dynamodb|DynamoDbException|SerializationException`), false},
	{"Redis", regexp.MustCompile(`(?i)WRONGTYPE Operation|ERR unknown command|Redis::CommandError|redis\.exceptions\.ResponseError`), false},
	{"Elasticsearch", regexp.MustCompile(`(?i)SearchPhaseExecutionException|ElasticsearchParseException|QueryParsingException|index_not_found_exception|x_content_parse_exception`), false},

	// --- Weak: generic query/operator/expression phrasing and lone operator
	// tokens that also appear in ordinary code or data. Only believed alongside a
	// dbErrorContext marker (see checkNoSQLError). ---
	{"MongoDB", regexp.MustCompile(`(?i)unknown (?:top level )?operator|unrecognized expression|\bFailedToParse\b|\$expr\b`), true},
}

// dbErrorContext is the corroboration layer for a weak match: an independent
// database-engine name or error-envelope marker that a genuine driver error
// surfaces alongside the operator/expression token, but a code/data bundle that
// merely contains a "$expr"-shaped token does not. It is deliberately framed
// around DB vocabulary and error structure (not generic words like "error" that
// appear in any JS bundle) so requiring it adds real evidence rather than rubber-
// stamping every body. Checked within a window around the match (contextNearMatch)
// so the marker must sit NEAR the token, not anywhere in a large body.
var dbErrorContext = regexp.MustCompile(`(?i)\bmongo|\bbson\b|couchdb|cassandra|dynamodb|datastax|elasticsearch|\bredis\b|neo4j|rethinkdb|arangodb|"errmsg"|"codeName"|"ok"\s*:\s*0|query parser|aggregation pipeline|\bexception\b|traceback|stack ?trace|failed to parse`)

// errorResponseShape marks a body that genuinely looks like an EMITTED error —
// a JSON error envelope, a stack trace, or an exception class — rather than
// arbitrary page content that merely contains a driver-name substring. Combined
// with a 5xx status it is the "is this actually an error response" gate: a
// genuine error-based leak arrives either as a server error (5xx) or wrapped in
// one of these structures, whereas a Mongo token incidentally present in normal
// HTML/JSON data carries neither. This is the strongest single FP filter for the
// class of false positives where a driver name appears in benign content.
var errorResponseShape = regexp.MustCompile(`(?i)"error"\s*:|"errmsg"\s*:|"message"\s*:|"reason"\s*:|"exception"\s*:|"ok"\s*:\s*0|"code"\s*:\s*"?[A-Za-z0-9_]+|\btraceback\b|stack ?trace|\bexception\b|\n\s+at\s|\bat [\w.$]+\([^)]*:\d+\)`)

var fuzzPayloads = []string{
	`'`,
	`"`,
	`{"$gt":""}`,
	`[$ne]=1`,
	`{$where: "1==1"}`,
	`{"$regex":".*"}`,
	`'; return true; var a='`,
	`{"$eq":""}`,
	`{"$in":[""]}`,
	`{"$nin":[""]}`,
	`{"$lt":""}`,
}

// Module implements the NoSQLi Error Based active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new NoSQLi Error Based module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		rhm: dedup.LazyDefaultRHM("nosqli_error_based"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests a single insertion point for NoSQL injection.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Get original response body to avoid false positives
	var origBody string
	if ctx.Response() != nil {
		origBody = ctx.Response().BodyToString()
	}

	var results []*output.ResultEvent

	for _, payload := range fuzzPayloads {
		fullPayload := ip.BaseValue() + payload

		fuzzedRaw := ip.BuildRequest([]byte(fullPayload))
		// BuildRequest produces well-formed raw, so wrap directly instead
		// of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		// A WAF/CDN challenge, auth gate, rate-limit, or maintenance response is
		// not produced by the application stack, so any DB-error substring it
		// carries is noise rather than an injection leak. The motivating false
		// positive: a Cloudflare 403 "Just a moment..." page whose base64
		// challenge token happened to contain "bSON", matching the MongoDB
		// pattern. Skip such responses before error matching.
		if isBlockedResponse(resp) {
			resp.Close()
			continue
		}

		// A 404/redirect means the route never resolved, so no NoSQL query ran:
		// a DB-error substring in such a body is page noise, not an injection
		// leak. The motivating false positive: a Salesforce community 404 SPA
		// shell — packed with fresh random base64 tokens on every request, one of
		// which matched the short MongoDB "BSON" pattern in the fuzzed response
		// but not the captured baseline. Only an application error surface
		// (5xx, or a 2xx/4xx the app returns with the driver message echoed) can
		// carry a genuine leak.
		if !infra.IsErrorSurfaceStatus(resp) {
			resp.Close()
			continue
		}

		// A static asset / code bundle served on the LIVE fuzzed response is never
		// a NoSQL query handler (the captured baseline content-type may have been
		// absent or wrong, as in the pdf.js-worker false positive, so re-check
		// here). A DB-error-shaped token baked into such a body is incidental.
		if resp.Response() != nil &&
			modkit.IsStaticAssetContentType(resp.Response().Header.Get("Content-Type")) {
			resp.Close()
			continue
		}

		body := resp.Body().String()
		// Strip our own injected value so a reflected operator payload (e.g.
		// {$where:...}, {$expr:...}) can never satisfy a pattern as the app simply
		// echoing the request back — the match must come from the database, not
		// from our payload bouncing off the page.
		dbms, regExp, matched := checkNoSQLError(modkit.StripReflected(body, fullPayload), origBody)
		if !matched {
			resp.Close()
			continue
		}

		// The response must actually look like an emitted database error, not
		// arbitrary content that happens to contain a driver token: a server error
		// (5xx) OR a structured error response (JSON envelope, stack trace,
		// exception). A driver name sitting in a normal 200 HTML/JSON body with no
		// error shape is the dominant false-positive class, so it is dropped here.
		respStatus := 0
		if resp.Response() != nil {
			respStatus = resp.Response().StatusCode
		}
		if respStatus < 500 && !errorResponseShape.MatchString(body) {
			resp.Close()
			continue
		}

		fullResp := resp.FullResponseString()
		resp.Close()

		// Confirm the error is genuinely introduced by the NoSQL payload: it must
		// reproduce when the same payload is re-sent (a per-request random token
		// that coincidentally matched will not recur — Salesforce mints a new
		// token each request) AND be absent from a fresh control fetch of the
		// original value (so a page that returns the pattern for any input is
		// rejected). Fails open on a transport error so a transient failure never
		// suppresses a true positive.
		if !modkit.ConfirmMatchReproduces(ctx, ip, httpClient, fuzzedRaw, regExp) {
			continue
		}

		results = append(results, &output.ResultEvent{
			URL:              urlx.String(),
			Request:          string(fuzzedRaw),
			Response:         fullResp,
			FuzzingParameter: ip.Name(),
			ExtractedResults: []string{payload},
			Info: output.Info{
				Description: fmt.Sprintf("DBMS: %s", dbms),
			},
		})
		return results, nil
	}

	return results, nil
}

// isBlockedResponse reports whether resp came from a WAF/CDN challenge, auth
// gate, rate limiter, or maintenance page rather than the application. Genuine
// error-based NoSQLi leaks are emitted by the app stack (typically a 500), so a
// denied or challenged response can only yield false matches. It combines the
// vendor-aware block detector (Cloudflare, Akamai, Incapsula, ...) with a plain
// status gate that also catches generic WAFs the detector does not recognize.
func isBlockedResponse(resp *httputil.ResponseChain) bool {
	return infra.IsBlockedResponse(resp)
}

// checkNoSQLError checks if response contains a NoSQL error pattern not already
// present in the original (unfuzzed) body. It returns the identified DBMS and the
// matched pattern so the caller can re-confirm the leak reproduces and is absent
// from a clean control.
//
// A weak pattern (generic operator/expression phrasing) must additionally be
// corroborated by a dbErrorContext marker NEAR the match — a lone "$expr" or
// "unrecognized expression" token in a code/data bundle, with no database-engine
// name or error envelope next to it, is not believed.
func checkNoSQLError(body, origBody string) (string, *regexp.Regexp, bool) {
	for _, ep := range errorPatterns {
		loc := ep.pattern.FindStringIndex(body)
		if loc == nil {
			continue
		}
		if origBody != "" && ep.pattern.MatchString(origBody) {
			continue // already present without the payload — not introduced by it
		}
		if ep.weak && !contextNearMatch(body, loc, dbErrorContext) {
			continue // generic token with no corroborating DB/error context nearby
		}
		return ep.dbms, ep.pattern, true
	}
	return "", nil, false
}

// contextNearMatch reports whether re matches inside a window of contextWindow
// bytes on either side of the [start,end) match span. Requiring the corroboration
// to sit NEAR the token — rather than anywhere in the body — stops a "$expr" at
// the top of a bundle and an unrelated "exception" far below from accidentally
// corroborating each other.
const contextWindow = 256

func contextNearMatch(body string, loc []int, re *regexp.Regexp) bool {
	start := loc[0] - contextWindow
	if start < 0 {
		start = 0
	}
	end := loc[1] + contextWindow
	if end > len(body) {
		end = len(body)
	}
	return re.MatchString(body[start:end])
}

// CanProcess extends the default to skip static assets / code bundles, which are
// never a NoSQL query handler — a DB-error-shaped token (a driver class name, a
// lone "$expr") found inside one is incidental, not a leaked database error. The
// motivating false positive was a MongoDB pattern matched inside a minified
// pdf.js worker served as application/javascript. Both the captured content-type
// and the URL path are checked so an asset whose baseline lacked a content-type
// is still skipped by extension.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if !m.BaseActiveModule.CanProcess(ctx) {
		return false
	}
	if ctx.Response() != nil && modkit.IsStaticAssetContentType(ctx.Response().Header("Content-Type")) {
		return false
	}
	if u, err := ctx.URL(); err == nil && modkit.IsStaticAssetPath(u.Path) {
		return false
	}
	return true
}
