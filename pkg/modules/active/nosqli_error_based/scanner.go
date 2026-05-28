package nosqli_error_based

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// nosqlError defines a database error pattern.
type nosqlError struct {
	dbms    string
	pattern *regexp.Regexp
}

var errorPatterns = []nosqlError{
	{"MongoDB", regexp.MustCompile(`(?i)(?:MongoError|BSON|mongod|MongoClient|mongo server|TopologyDescription|Cannot apply.*update operator)`)},
	{"MongoDB", regexp.MustCompile(`(?i)(?:E11000 duplicate key|cannot index parallel arrays|\$where requires|bad query|invalid operator|unknown top level operator)`)},
	{"CouchDB", regexp.MustCompile(`(?i)(?:couchdb|org\.apache\.couchdb|{"error":"bad_request"|"reason":"invalid_json")`)},
	{"Cassandra", regexp.MustCompile(`(?i)(?:com\.datastax\.driver|InvalidRequestException|SyntaxException.*CQL|no viable alternative at input)`)},
	{"DynamoDB", regexp.MustCompile(`(?i)(?:com\.amazonaws\.services\.dynamodbv2|ValidationException.*dynamodb|SerializationException)`)},
	{"Redis", regexp.MustCompile(`(?i)(?:WRONGTYPE Operation|ERR unknown command|Redis::CommandError|redis\.exceptions\.ResponseError)`)},
	{"Elasticsearch", regexp.MustCompile(`(?i)(?:SearchPhaseExecutionException|ElasticsearchParseException|QueryParsingException|index_not_found_exception)`)},
}

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
		fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		body := resp.Body().String()
		if dbms, matched := checkNoSQLError(body, origBody); matched {
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(fuzzedRaw),
				Response:         resp.FullResponseString(),
				FuzzingParameter: ip.Name(),
				ExtractedResults: []string{payload},
				Info: output.Info{
					Description: fmt.Sprintf("DBMS: %s", dbms),
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}

// checkNoSQLError checks if response contains NoSQL error patterns not in original.
func checkNoSQLError(body, origBody string) (string, bool) {
	for _, ep := range errorPatterns {
		if ep.pattern.MatchString(body) {
			if origBody != "" && ep.pattern.MatchString(origBody) {
				continue
			}
			return ep.dbms, true
		}
	}
	return "", false
}

// CanProcess extends the default to also skip if the content type suggests non-injectable content.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if !m.BaseActiveModule.CanProcess(ctx) {
		return false
	}
	if ctx.Response() != nil {
		ct := strings.ToLower(ctx.Response().Header("Content-Type"))
		if strings.Contains(ct, "image/") || strings.Contains(ct, "audio/") || strings.Contains(ct, "video/") {
			return false
		}
	}
	return true
}
