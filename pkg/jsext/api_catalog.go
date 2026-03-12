package jsext

import "sync"

// Category constants for grouping API functions in display output.
const (
	CatLogging    = "Logging"
	CatEncoding   = "Encoding & Decoding"
	CatHashing    = "Hashing"
	CatStrings    = "Strings & Generation"
	CatSystem     = "System & Control"
	CatFileIO     = "File I/O"
	CatExtract    = "Data Extraction"
	CatDetection  = "Detection"
	CatHTTP       = "HTTP Requests"
	CatScan       = "Scan Control"
	CatIngest     = "Ingestion"
	CatSource     = "Source Code"
	CatConfig     = "Configuration"
	CatDBRecords  = "DB Records"
	CatDBFindings = "DB Findings"
	CatDBAnalysis = "DB Analysis"
	CatAgent      = "Agent"
	CatRecord     = "Current Record"
)

// APICatalogEntry is an APIFunction with an assigned display category.
type APICatalogEntry struct {
	Category string
	APIFunction
}

// ─── vigolium.log ────────────────────────────────────────────────────────────
const exLogInfo = `vigolium.log.info("scanning: " + ctx.request.url)`
const exLogWarn = `vigolium.log.warn("unexpected status: " + resp.status)`
const exLogError = `vigolium.log.error("request failed: " + ctx.request.url)`
const exLogDebug = `vigolium.log.debug("payload: " + payload)`

// ─── vigolium.utils / Encoding ───────────────────────────────────────────────
const exBase64Encode = `var encoded = vigolium.utils.base64Encode("admin:password")`
const exBase64Decode = `var decoded = vigolium.utils.base64Decode("YWRtaW4=")`
const exURLEncode = `var q = vigolium.utils.urlEncode("key=val&foo=bar")`
const exURLDecode = `var raw = vigolium.utils.urlDecode("key%3Dval")`
const exHTMLEncode = `var safe = vigolium.utils.htmlEncode("<script>")`
const exHTMLDecode = `var raw = vigolium.utils.htmlDecode("&lt;script&gt;")`

// ─── vigolium.utils / Hashing ────────────────────────────────────────────────
const exSHA1 = `var hash = vigolium.utils.sha1("hello")`
const exSHA256 = `var hash = vigolium.utils.sha256("hello")`
const exMD5 = `var hash = vigolium.utils.md5("hello")`

// ─── vigolium.utils / Strings ────────────────────────────────────────────────
const exRandomString = `var canary = "VGNM" + vigolium.utils.randomString(8)`

// ─── vigolium.utils / System ─────────────────────────────────────────────────
const exSleep = `vigolium.utils.sleep(500) // wait 500ms`
const exExec = `var result = vigolium.utils.exec("curl -s http://example.com")`
const exGetEnv = `var token = vigolium.utils.getEnv("API_TOKEN")`
const exSetEnv = `vigolium.utils.setEnv("MY_VAR", "value")`

// ─── vigolium.utils / File I/O ───────────────────────────────────────────────
const exGlob = `var files = vigolium.utils.glob("/tmp/wordlists/*.txt")`
const exReadFile = `var data = vigolium.utils.readFile("/tmp/tokens.txt")`
const exReadLines = `var lines = vigolium.utils.readLines("/tmp/wordlist.txt")`
const exWriteFile = `vigolium.utils.writeFile("/tmp/out.txt", "result data")`
const exMkdir = `vigolium.utils.mkdir("/tmp/results")`

// ─── vigolium.utils / Data Extraction ────────────────────────────────────────
const exJSONExtract = `var name = vigolium.utils.jsonExtract('{"a":{"b":"val"}}', "a.b")`
const exRegexMatch = `if (vigolium.utils.regexMatch(body, "error|exception")) { ... }`
const exRegexExtract = `var ver = vigolium.utils.regexExtract(header, "Apache/([0-9.]+)")`
const exParseURL = `var host = vigolium.utils.parse_url("https://sub.example.com/path", "%d")`
const exParseURLFile = `vigolium.utils.parse_url_file("urls.txt", "%s://%d", "hosts.txt")`

// ─── vigolium.utils / Detection ──────────────────────────────────────────────
const exDetectAnomaly = `var ranked = vigolium.utils.detectAnomaly(responses)`

// ─── vigolium.http ───────────────────────────────────────────────────────────
const exHTTPGet = `var resp = vigolium.http.get("https://example.com/api")`
const exHTTPPost = `var resp = vigolium.http.post("https://example.com/api", "data=test")`
const exHTTPRequest = `var resp = vigolium.http.request({method: "PUT", url: "https://example.com", body: "{}"})`
const exHTTPSend = `var built = insertion.buildRequest(payload); var resp = vigolium.http.send(built)`

// ─── vigolium.scan ───────────────────────────────────────────────────────────
const exScanListModules = `var mods = vigolium.scan.listModules()`
const exScanIsInScope = `if (vigolium.scan.isInScope("example.com", "/admin")) { ... }`
const exScanGetScope = `var scope = vigolium.scan.getScope()`
const exScanSetScope = `vigolium.scan.setScope({host: {include: ["*.example.com"]}})`
const exScanCreateFinding = `vigolium.scan.createFinding({url: ctx.request.url, matched: "admin", name: "Admin panel", severity: "medium"})`
const exScanGetCurrentScan = `var scan = vigolium.scan.getCurrentScan()`
const exScanStartNewScan = `var r = vigolium.scan.startNewScan({targets: ["https://example.com/api"], modules: ["xss", "sqli"]})`

// ─── vigolium.ingest ─────────────────────────────────────────────────────────
const exIngestURL = `var r = vigolium.ingest.url("https://example.com/api/users")`
const exIngestURLs = "var r = vigolium.ingest.urls(\"https://example.com/a\\nhttps://example.com/b\")"
const exIngestCurl = `var r = vigolium.ingest.curl("curl -X POST https://example.com/api -d 'data=test'")`
const exIngestRaw = "var r = vigolium.ingest.raw(\"GET /api HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n\")"
const exIngestOpenAPI = `var r = vigolium.ingest.openapi(specJSON, {base_url: "https://api.example.com"})`
const exIngestPostman = `var r = vigolium.ingest.postman(collectionJSON)`

// ─── vigolium.source ─────────────────────────────────────────────────────────
const exSourceList = `var repos = vigolium.source.list("example.com")`
const exSourceGet = `var repo = vigolium.source.get(1)`
const exSourceGetByHostname = `var repos = vigolium.source.getByHostname(ctx.request.hostname)`
const exSourceReadFile = `var code = vigolium.source.readFile("example.com", "src/app.js")`
const exSourceListFiles = `var files = vigolium.source.listFiles("example.com", "*.js")`
const exSourceSearchFiles = `var matches = vigolium.source.searchFiles("example.com", "eval\\(")`

// ─── vigolium.db ─────────────────────────────────────────────────────────────
const exDBRecordsQuery = `var records = vigolium.db.records.query({hostname: "example.com", limit: 10})`
const exDBRecordsGet = `var record = vigolium.db.records.get("uuid-string")`
const exDBRecordsGetRelated = `var related = vigolium.db.records.getRelated("uuid-string", {limit: 5})`
const exDBRecordsAnnotate = `vigolium.db.records.annotate("uuid-string", {risk_score: 80, remarks: ["suspicious"]})`
const exDBFindingsQuery = `var findings = vigolium.db.findings.query({severity: ["high", "critical"], limit: 20})`
const exDBFindingsGet = `var finding = vigolium.db.findings.get(42)`
const exDBFindingsGetByRecord = `var findings = vigolium.db.findings.getByRecord("uuid-string")`
const exDBFindingsCreate = `vigolium.db.findings.create({module_id: "my-ext", module_name: "My Extension", severity: "high", description: "Found issue"})`
const exDBCompareResponses = `var result = vigolium.db.compareResponses(records)`

// ─── vigolium.record ─────────────────────────────────────────────────────────
const exRecordUUID = `var uuid = vigolium.record.uuid`
const exRecordAnnotate = `vigolium.record.annotate({risk_score: 80, remarks: ["suspicious"]})`
const exRecordAddRiskScore = `vigolium.record.addRiskScore(10)`
const exRecordAddRemarks = `vigolium.record.addRemarks(["admin-path", "needs-review"])`

// ─── vigolium.config ─────────────────────────────────────────────────────────
const exConfigKey = `var token = vigolium.config.auth_token`

var (
	apiCatalogOnce  sync.Once
	apiCatalogCache []APICatalogEntry
)

// APICatalog returns all API functions in display order, each with a category.
// The catalog is derived from allFuncDefs(), ensuring it never drifts from the
// actual registered handlers.
func APICatalog() []APICatalogEntry {
	apiCatalogOnce.Do(func() {
		defs := allFuncDefs()
		apiCatalogCache = make([]APICatalogEntry, 0, len(defs))
		for _, d := range defs {
			apiCatalogCache = append(apiCatalogCache, APICatalogEntry{
				Category: d.Category,
				APIFunction: APIFunction{
					Namespace:   d.Namespace,
					Name:        d.Name,
					Signature:   d.Signature,
					Returns:     d.Returns,
					Description: d.Description,
					Example:     d.Example,
				},
			})
		}
	})
	return apiCatalogCache
}
