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
// The catalog is immutable and initialized once.
func APICatalog() []APICatalogEntry {
	apiCatalogOnce.Do(func() {
		apiCatalogCache = buildAPICatalog()
	})
	return apiCatalogCache
}

func buildAPICatalog() []APICatalogEntry {
	return []APICatalogEntry{
		// ── Logging ──────────────────────────────────────────────────────────
		{CatLogging, APIFunction{Namespace: "vigolium.log", Name: "info", Signature: ".info(msg: string)", Returns: "void", Description: "Log an informational message.", Example: exLogInfo}},
		{CatLogging, APIFunction{Namespace: "vigolium.log", Name: "warn", Signature: ".warn(msg: string)", Returns: "void", Description: "Log a warning message.", Example: exLogWarn}},
		{CatLogging, APIFunction{Namespace: "vigolium.log", Name: "error", Signature: ".error(msg: string)", Returns: "void", Description: "Log an error message.", Example: exLogError}},
		{CatLogging, APIFunction{Namespace: "vigolium.log", Name: "debug", Signature: ".debug(msg: string)", Returns: "void", Description: "Log a debug message (only visible at debug log level).", Example: exLogDebug}},

		// ── Encoding & Decoding ───────────────────────────────────────────────
		{CatEncoding, APIFunction{Namespace: "vigolium.utils", Name: "base64Encode", Signature: ".base64Encode(s: string)", Returns: "string", Description: "Encode a string to base64.", Example: exBase64Encode}},
		{CatEncoding, APIFunction{Namespace: "vigolium.utils", Name: "base64Decode", Signature: ".base64Decode(s: string)", Returns: "string", Description: "Decode a base64 string. Returns empty string on error.", Example: exBase64Decode}},
		{CatEncoding, APIFunction{Namespace: "vigolium.utils", Name: "urlEncode", Signature: ".urlEncode(s: string)", Returns: "string", Description: "URL-encode (percent-encode) a string.", Example: exURLEncode}},
		{CatEncoding, APIFunction{Namespace: "vigolium.utils", Name: "urlDecode", Signature: ".urlDecode(s: string)", Returns: "string", Description: "Decode a URL-encoded string.", Example: exURLDecode}},
		{CatEncoding, APIFunction{Namespace: "vigolium.utils", Name: "htmlEncode", Signature: ".htmlEncode(s: string)", Returns: "string", Description: "HTML-escape a string (<, >, &, quotes).", Example: exHTMLEncode}},
		{CatEncoding, APIFunction{Namespace: "vigolium.utils", Name: "htmlDecode", Signature: ".htmlDecode(s: string)", Returns: "string", Description: "Unescape HTML entities.", Example: exHTMLDecode}},

		// ── Hashing ──────────────────────────────────────────────────────────
		{CatHashing, APIFunction{Namespace: "vigolium.utils", Name: "sha1", Signature: ".sha1(s: string)", Returns: "string", Description: "Compute SHA-1 hex digest.", Example: exSHA1}},
		{CatHashing, APIFunction{Namespace: "vigolium.utils", Name: "sha256", Signature: ".sha256(s: string)", Returns: "string", Description: "Compute SHA-256 hex digest.", Example: exSHA256}},
		{CatHashing, APIFunction{Namespace: "vigolium.utils", Name: "md5", Signature: ".md5(s: string)", Returns: "string", Description: "Compute MD5 hex digest.", Example: exMD5}},

		// ── Strings & Generation ──────────────────────────────────────────────
		{CatStrings, APIFunction{Namespace: "vigolium.utils", Name: "randomString", Signature: ".randomString(len: number)", Returns: "string", Description: "Generate a random alphanumeric string of the given length.", Example: exRandomString}},

		// ── System & Control ─────────────────────────────────────────────────
		{CatSystem, APIFunction{Namespace: "vigolium.utils", Name: "sleep", Signature: ".sleep(ms: number)", Returns: "void", Description: "Sleep for the given number of milliseconds (max 30000).", Example: exSleep}},
		{CatSystem, APIFunction{Namespace: "vigolium.utils", Name: "exec", Signature: ".exec(cmd: string)", Returns: "{stdout, stderr, exitCode}", Description: "Execute a shell command. Requires extensions.allow_exec: true.", Example: exExec}},
		{CatSystem, APIFunction{Namespace: "vigolium.utils", Name: "getEnv", Signature: ".getEnv(name: string)", Returns: "string", Description: "Read an environment variable.", Example: exGetEnv}},
		{CatSystem, APIFunction{Namespace: "vigolium.utils", Name: "setEnv", Signature: ".setEnv(name: string, val: string)", Returns: "bool", Description: "Set an environment variable. Requires extensions.allow_exec: true.", Example: exSetEnv}},

		// ── File I/O ─────────────────────────────────────────────────────────
		{CatFileIO, APIFunction{Namespace: "vigolium.utils", Name: "glob", Signature: ".glob(pattern: string)", Returns: "string[]", Description: "Find files matching a glob pattern (within sandbox).", Example: exGlob}},
		{CatFileIO, APIFunction{Namespace: "vigolium.utils", Name: "readFile", Signature: ".readFile(path: string)", Returns: "string", Description: "Read a file's contents as a string (within sandbox).", Example: exReadFile}},
		{CatFileIO, APIFunction{Namespace: "vigolium.utils", Name: "readLines", Signature: ".readLines(path: string)", Returns: "string[]", Description: "Read a file as an array of lines (within sandbox).", Example: exReadLines}},
		{CatFileIO, APIFunction{Namespace: "vigolium.utils", Name: "writeFile", Signature: ".writeFile(path: string, data: string)", Returns: "bool", Description: "Write data to a file (within sandbox). Returns true on success.", Example: exWriteFile}},
		{CatFileIO, APIFunction{Namespace: "vigolium.utils", Name: "mkdir", Signature: ".mkdir(path: string)", Returns: "bool", Description: "Create a directory (and parents) within sandbox.", Example: exMkdir}},

		// ── Data Extraction ───────────────────────────────────────────────────
		{CatExtract, APIFunction{Namespace: "vigolium.utils", Name: "jsonExtract", Signature: `.jsonExtract(json: string, path: string)`, Returns: "any", Description: "Extract a value from a JSON string using dot-path notation.", Example: exJSONExtract}},
		{CatExtract, APIFunction{Namespace: "vigolium.utils", Name: "regexMatch", Signature: ".regexMatch(str: string, pattern: string)", Returns: "bool", Description: "Test whether a string matches a regular expression.", Example: exRegexMatch}},
		{CatExtract, APIFunction{Namespace: "vigolium.utils", Name: "regexExtract", Signature: ".regexExtract(str: string, pattern: string)", Returns: "string | string[] | null", Description: "Extract the first match (or capture groups) from a regex. Returns null if no match.", Example: exRegexExtract}},
		{CatExtract, APIFunction{Namespace: "vigolium.utils", Name: "parse_url", Signature: ".parse_url(url: string, format: string)", Returns: "string", Description: "Parse a URL and format it using printf-style directives (see format table below).", Example: exParseURL}},
		{CatExtract, APIFunction{Namespace: "vigolium.utils", Name: "parse_url_file", Signature: ".parse_url_file(input: string, format: string, output: string)", Returns: "bool", Description: "Parse all URLs in a file, format them, deduplicate, and write to output file.", Example: exParseURLFile}},

		// ── Detection ────────────────────────────────────────────────────────
		{CatDetection, APIFunction{Namespace: "vigolium.utils", Name: "detectAnomaly", Signature: ".detectAnomaly(responses: object[])", Returns: "{index, score}[]", Description: "Rank an array of HTTP responses by anomaly score. Each input object should have {status, body, headers}.", Example: exDetectAnomaly}},

		// ── HTTP Requests ─────────────────────────────────────────────────────
		{CatHTTP, APIFunction{Namespace: "vigolium.http", Name: "get", Signature: ".get(url: string, opts?: {headers})", Returns: "{status, headers, body, raw}", Description: "Send an HTTP GET request.", Example: exHTTPGet}},
		{CatHTTP, APIFunction{Namespace: "vigolium.http", Name: "post", Signature: ".post(url: string, body: string, opts?: {headers})", Returns: "{status, headers, body, raw}", Description: "Send an HTTP POST request.", Example: exHTTPPost}},
		{CatHTTP, APIFunction{Namespace: "vigolium.http", Name: "request", Signature: ".request({method, url, headers, body})", Returns: "{status, headers, body, raw}", Description: "Send a custom HTTP request with full control over method, headers, and body.", Example: exHTTPRequest}},
		{CatHTTP, APIFunction{Namespace: "vigolium.http", Name: "send", Signature: ".send(rawRequest: string)", Returns: "{status, headers, body, raw}", Description: "Send a raw HTTP request string (as built by insertion.buildRequest).", Example: exHTTPSend}},

		// ── Scan Control ──────────────────────────────────────────────────────
		{CatScan, APIFunction{Namespace: "vigolium.scan", Name: "listModules", Signature: ".listModules()", Returns: "[{id, name, type, severity, description}]", Description: "List all registered scanner modules (active + passive).", Example: exScanListModules}},
		{CatScan, APIFunction{Namespace: "vigolium.scan", Name: "isInScope", Signature: ".isInScope(host: string, path: string)", Returns: "bool", Description: "Check if a host+path combination is within the current scan scope.", Example: exScanIsInScope}},
		{CatScan, APIFunction{Namespace: "vigolium.scan", Name: "getScope", Signature: ".getScope()", Returns: "{host, path, status_code, ...}", Description: "Get the current scope configuration. Each key has {include, exclude} arrays.", Example: exScanGetScope}},
		{CatScan, APIFunction{Namespace: "vigolium.scan", Name: "setScope", Signature: ".setScope(scopeObj: object)", Returns: "bool", Description: "Update the scope configuration for this VM instance.", Example: exScanSetScope}},
		{CatScan, APIFunction{Namespace: "vigolium.scan", Name: "createFinding", Signature: ".createFinding({url, matched, name, description, severity, request, response, additional_evidence})", Returns: "bool", Description: "Emit a finding from a hook or module. Severity: critical, high, medium, low, info.", Example: exScanCreateFinding}},
		{CatScan, APIFunction{Namespace: "vigolium.scan", Name: "getCurrentScan", Signature: ".getCurrentScan()", Returns: "{uuid}", Description: "Get information about the current scan session.", Example: exScanGetCurrentScan}},
		{CatScan, APIFunction{Namespace: "vigolium.scan", Name: "startNewScan", Signature: ".startNewScan({targets: string[], modules?: string[], name?: string})", Returns: "{scan_uuid, queued, errors}", Description: "Queue targets for scanning and create a new scan record. Modules default to [\"all\"], name defaults to \"extension-scan\".", Example: exScanStartNewScan}},

		// ── Ingestion ─────────────────────────────────────────────────────────
		{CatIngest, APIFunction{Namespace: "vigolium.ingest", Name: "url", Signature: ".url(url: string)", Returns: "IngestResult", Description: "Ingest a single URL into the database. Fetches response if HTTP client is available.", Example: exIngestURL}},
		{CatIngest, APIFunction{Namespace: "vigolium.ingest", Name: "urls", Signature: ".urls(content: string)", Returns: "IngestBatchResult", Description: "Ingest newline-separated URLs into the database.", Example: exIngestURLs}},
		{CatIngest, APIFunction{Namespace: "vigolium.ingest", Name: "curl", Signature: ".curl(command: string)", Returns: "IngestResult", Description: "Parse a curl command and ingest into the database.", Example: exIngestCurl}},
		{CatIngest, APIFunction{Namespace: "vigolium.ingest", Name: "raw", Signature: ".raw(rawRequest: string, rawResponse?: string)", Returns: "IngestResult", Description: "Ingest a raw HTTP request (and optional response) into the database.", Example: exIngestRaw}},
		{CatIngest, APIFunction{Namespace: "vigolium.ingest", Name: "openapi", Signature: ".openapi(spec: string, opts?: {base_url?: string})", Returns: "IngestBatchResult", Description: "Parse an OpenAPI/Swagger spec and ingest all operations.", Example: exIngestOpenAPI}},
		{CatIngest, APIFunction{Namespace: "vigolium.ingest", Name: "postman", Signature: ".postman(collection: string)", Returns: "IngestBatchResult", Description: "Parse a Postman collection and ingest all requests.", Example: exIngestPostman}},

		// ── Source Code ───────────────────────────────────────────────────────
		{CatSource, APIFunction{Namespace: "vigolium.source", Name: "list", Signature: ".list(hostname?: string)", Returns: "SourceRepo[]", Description: "List source repos, optionally filtered by hostname.", Example: exSourceList}},
		{CatSource, APIFunction{Namespace: "vigolium.source", Name: "get", Signature: ".get(id: number)", Returns: "SourceRepo | null", Description: "Get a source repo by ID.", Example: exSourceGet}},
		{CatSource, APIFunction{Namespace: "vigolium.source", Name: "getByHostname", Signature: ".getByHostname(hostname: string)", Returns: "SourceRepo[]", Description: "Get source repos for a hostname.", Example: exSourceGetByHostname}},
		{CatSource, APIFunction{Namespace: "vigolium.source", Name: "readFile", Signature: ".readFile(hostname: string, path: string)", Returns: "string", Description: "Read a file from the source repo for a hostname (path-traversal protected).", Example: exSourceReadFile}},
		{CatSource, APIFunction{Namespace: "vigolium.source", Name: "listFiles", Signature: ".listFiles(hostname: string, glob?: string)", Returns: "string[]", Description: "List files in a source repo for a hostname, optionally filtered by glob.", Example: exSourceListFiles}},
		{CatSource, APIFunction{Namespace: "vigolium.source", Name: "searchFiles", Signature: ".searchFiles(hostname: string, pattern: string)", Returns: "SearchMatch[]", Description: "Grep source files for a hostname's repo using a regex pattern. Returns matches with file path and line number.", Example: exSourceSearchFiles}},

		// ── DB Records ────────────────────────────────────────────────────────
		{CatDBRecords, APIFunction{Namespace: "vigolium.db.records", Name: "query", Signature: ".query(filters?: {hostname?, path?, methods?, status_codes?, limit?, offset?, sort_by?, sort_asc?})", Returns: "DBRecord[]", Description: "Query HTTP records from the database with optional filters.", Example: exDBRecordsQuery}},
		{CatDBRecords, APIFunction{Namespace: "vigolium.db.records", Name: "get", Signature: ".get(uuid: string)", Returns: "DBRecord | null", Description: "Get a single HTTP record by UUID.", Example: exDBRecordsGet}},
		{CatDBRecords, APIFunction{Namespace: "vigolium.db.records", Name: "getRelated", Signature: ".getRelated(uuid: string, opts?: {limit?: number})", Returns: "DBRecord[]", Description: "Get HTTP records related to a given record UUID.", Example: exDBRecordsGetRelated}},
		{CatDBRecords, APIFunction{Namespace: "vigolium.db.records", Name: "annotate", Signature: ".annotate(uuid: string, patch: {risk_score?, remarks?})", Returns: "bool", Description: "Update annotations (risk score, remarks) on an HTTP record.", Example: exDBRecordsAnnotate}},

		// ── DB Findings ───────────────────────────────────────────────────────
		{CatDBFindings, APIFunction{Namespace: "vigolium.db.findings", Name: "query", Signature: ".query(filters?: {severity?, module_name?, scan_uuid?, limit?, offset?})", Returns: "DBFinding[]", Description: "Query findings from the database with optional filters.", Example: exDBFindingsQuery}},
		{CatDBFindings, APIFunction{Namespace: "vigolium.db.findings", Name: "get", Signature: ".get(id: number)", Returns: "DBFinding | null", Description: "Get a single finding by ID.", Example: exDBFindingsGet}},
		{CatDBFindings, APIFunction{Namespace: "vigolium.db.findings", Name: "getByRecord", Signature: ".getByRecord(uuid: string)", Returns: "DBFinding[]", Description: "Get all findings associated with an HTTP record UUID.", Example: exDBFindingsGetByRecord}},
		{CatDBFindings, APIFunction{Namespace: "vigolium.db.findings", Name: "create", Signature: ".create(finding: {module_id, module_name, severity?, confidence?, description?, ...})", Returns: "bool", Description: "Create a new finding in the database.", Example: exDBFindingsCreate}},

		// ── DB Analysis ───────────────────────────────────────────────────────
		{CatDBAnalysis, APIFunction{Namespace: "vigolium.db", Name: "compareResponses", Signature: ".compareResponses(records: object[])", Returns: "{all_similar, scores, variant_count, summary}", Description: "Compare HTTP responses by anomaly score. Each input should have {uuid, status_code, response_body, response_headers}.", Example: exDBCompareResponses}},

		// ── Current Record ────────────────────────────────────────────────────
		{CatRecord, APIFunction{Namespace: "vigolium.record", Name: "uuid", Signature: ".uuid", Returns: "string", Description: "Database UUID of the current HTTP record being processed. Empty string if not persisted. Also available as ctx.record.uuid.", Example: exRecordUUID}},
		{CatRecord, APIFunction{Namespace: "vigolium.record", Name: "annotate", Signature: ".annotate(patch: {risk_score?, remarks?})", Returns: "bool", Description: "Replace annotations (risk score and/or remarks) on the current HTTP record. Risk score is clamped to [0, 100]. Also available as ctx.record.annotate().", Example: exRecordAnnotate}},
		{CatRecord, APIFunction{Namespace: "vigolium.record", Name: "addRiskScore", Signature: ".addRiskScore(delta: number)", Returns: "bool", Description: "Increment risk_score by delta (can be negative). Result is clamped to [0, 100]. Also available as ctx.record.addRiskScore().", Example: exRecordAddRiskScore}},
		{CatRecord, APIFunction{Namespace: "vigolium.record", Name: "addRemarks", Signature: ".addRemarks(remarks: string[])", Returns: "bool", Description: "Append remarks to the current HTTP record with deduplication. Existing remarks are preserved. Also available as ctx.record.addRemarks().", Example: exRecordAddRemarks}},

		// ── Configuration ─────────────────────────────────────────────────────
		{CatConfig, APIFunction{Namespace: "vigolium.config", Name: "<key>", Signature: ".<key>", Returns: "string", Description: "Access custom variables defined in extensions.variables config.", Example: exConfigKey}},
	}
}
