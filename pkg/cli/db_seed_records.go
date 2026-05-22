package cli

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
)

// ---------------------------------------------------------------------------
// HTTP Record seeds
// ---------------------------------------------------------------------------

// seedHost holds reusable host/origin data for building records.
type seedHost struct {
	scheme   string
	hostname string
	port     int
	ip       string
}

var seedHosts = []seedHost{
	{"https", "example.com", 443, "93.184.216.34"},
	{"https", "api.shop.local", 443, "10.0.0.50"},
	{"https", "blog.test", 443, "172.16.0.5"},
	{"http", "legacy.example.com", 80, "93.184.216.35"},
	{"https", "cdn.example.com", 443, "93.184.216.36"},
	{"https", "admin.example.com", 8443, "93.184.216.37"},
}

// seedEndpoint describes a single endpoint template.
type seedEndpoint struct {
	method      string
	path        string
	host        int // index into seedHosts
	scan        int // index into scans slice (-1 = no scan)
	status      int
	phrase      string
	contentType string
	bodyLen     int64
	timeMs      int64
	title       string
	params      []database.EmbeddedParam
	reqCT       string
	reqBody     []byte
	reqAuth     string
	reqHeaders  map[string][]string
	respHeaders map[string][]string
	remarks     []string
	technology  []string
	parentPath  string // path of parent record on same host (empty = no parent)
}

func seedHTTPRecords(_ *rand.Rand, scans []*database.Scan) []*database.HTTPRecord {
	now := time.Now()

	endpoints := []seedEndpoint{
		// ---- example.com (scan 0) ----
		{method: "GET", path: "/", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 14520, timeMs: 120, title: "Example Domain — Home",
			reqHeaders:  map[string][]string{"Host": {"example.com"}, "Accept": {"text/html,application/xhtml+xml"}, "User-Agent": {"Mozilla/5.0"}},
			respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}, "Server": {"nginx/1.24"}, "X-Frame-Options": {"SAMEORIGIN"}},
			technology:  []string{"nginx/1.24", "next.js"},
		},
		{method: "GET", path: "/about", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 8732, timeMs: 95, title: "About Us — Example",
			reqHeaders: map[string][]string{"Host": {"example.com"}, "Accept": {"text/html"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}, "Cache-Control": {"max-age=3600"}},
		},
		{method: "GET", path: "/contact", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 6200, timeMs: 88, title: "Contact — Example",
			reqHeaders: map[string][]string{"Host": {"example.com"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
		},
		{method: "GET", path: "/login", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 4310, timeMs: 72, title: "Login",
			reqHeaders: map[string][]string{"Host": {"example.com"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}, "Set-Cookie": {"session=abc123; HttpOnly; Secure"}},
		},
		{method: "POST", path: "/login", host: 0, scan: 0, status: 302, phrase: "Found", contentType: "text/html", bodyLen: 0, timeMs: 210, title: "",
			reqCT: "application/x-www-form-urlencoded", reqBody: []byte("username=admin&password=test123"),
			params:     []database.EmbeddedParam{{Name: "username", Value: "admin", Type: "body"}, {Name: "password", Value: "test123", Type: "body"}},
			reqHeaders: map[string][]string{"Host": {"example.com"}, "Content-Type": {"application/x-www-form-urlencoded"}}, respHeaders: map[string][]string{"Location": {"/dashboard"}, "Set-Cookie": {"session=xyz789; HttpOnly; Secure"}},
			remarks: []string{"auth-endpoint", "has-credentials"},
		},
		{method: "GET", path: "/dashboard", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 22100, timeMs: 180, title: "Dashboard — Example",
			reqAuth:    "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc",
			reqHeaders: map[string][]string{"Host": {"example.com"}, "Authorization": {"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
			remarks: []string{"authenticated", "jwt-bearer"},
		},
		{method: "GET", path: "/search?q=test&page=1", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 9800, timeMs: 145, title: "Search Results — test",
			params:     []database.EmbeddedParam{{Name: "q", Value: "test", Type: "url"}, {Name: "page", Value: "1", Type: "url"}},
			reqHeaders: map[string][]string{"Host": {"example.com"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
		},
		{method: "GET", path: "/search?q=<script>alert(1)</script>&page=1", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 9500, timeMs: 150, title: "Search Results",
			params:     []database.EmbeddedParam{{Name: "q", Value: "<script>alert(1)</script>", Type: "url"}, {Name: "page", Value: "1", Type: "url"}},
			reqHeaders: map[string][]string{"Host": {"example.com"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
			remarks: []string{"reflected-input", "xss-payload"},
		},
		{method: "GET", path: "/profile/1", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 7500, timeMs: 130, title: "User Profile",
			reqAuth:    "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc",
			reqHeaders: map[string][]string{"Host": {"example.com"}, "Authorization": {"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
			remarks: []string{"idor-candidate", "authenticated"},
		},
		{method: "GET", path: "/admin/users", host: 0, scan: 0, status: 403, phrase: "Forbidden", contentType: "text/html", bodyLen: 1200, timeMs: 45, title: "403 Forbidden",
			reqHeaders: map[string][]string{"Host": {"example.com"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
			remarks: []string{"forbidden-bypass-candidate", "admin-panel"},
		},
		{method: "GET", path: "/nonexistent", host: 0, scan: 0, status: 404, phrase: "Not Found", contentType: "text/html", bodyLen: 2100, timeMs: 30, title: "Page Not Found",
			reqHeaders: map[string][]string{"Host": {"example.com"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
		},
		{method: "GET", path: "/assets/style.css", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/css", bodyLen: 45200, timeMs: 15, title: "",
			reqHeaders: map[string][]string{"Host": {"example.com"}, "Accept": {"text/css,*/*"}}, respHeaders: map[string][]string{"Content-Type": {"text/css"}, "Cache-Control": {"public, max-age=31536000"}},
		},
		{method: "GET", path: "/assets/app.js", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "application/javascript", bodyLen: 128000, timeMs: 22, title: "",
			reqHeaders: map[string][]string{"Host": {"example.com"}}, respHeaders: map[string][]string{"Content-Type": {"application/javascript"}, "Cache-Control": {"public, max-age=31536000"}},
		},
		{method: "GET", path: "/robots.txt", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/plain", bodyLen: 150, timeMs: 8, title: "",
			reqHeaders: map[string][]string{"Host": {"example.com"}}, respHeaders: map[string][]string{"Content-Type": {"text/plain"}},
		},
		{method: "GET", path: "/sitemap.xml", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "application/xml", bodyLen: 3200, timeMs: 18, title: "",
			reqHeaders: map[string][]string{"Host": {"example.com"}}, respHeaders: map[string][]string{"Content-Type": {"application/xml"}},
		},

		// ---- api.shop.local (scan 1) — JSON API ----
		{method: "GET", path: "/api/v1/products", host: 1, scan: 1, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 34500, timeMs: 85, title: "",
			reqAuth:    "Bearer shop-api-token-abc123",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Accept": {"application/json"}, "Authorization": {"Bearer shop-api-token-abc123"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}, "X-RateLimit-Remaining": {"98"}},
			technology: []string{"fastapi", "python/3.11", "uvicorn"},
		},
		{method: "GET", path: "/api/v1/products/42", host: 1, scan: 1, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 1250, timeMs: 35, title: "",
			reqAuth:    "Bearer shop-api-token-abc123",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Authorization": {"Bearer shop-api-token-abc123"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}},
		},
		{method: "POST", path: "/api/v1/products", host: 1, scan: 1, status: 201, phrase: "Created", contentType: "application/json", bodyLen: 580, timeMs: 120, title: "",
			reqCT: "application/json", reqBody: []byte(`{"name":"Widget Pro","price":29.99,"category":"electronics"}`),
			params:     []database.EmbeddedParam{{Name: "name", Value: "Widget Pro", Type: "json"}, {Name: "price", Value: "29.99", Type: "json"}, {Name: "category", Value: "electronics", Type: "json"}},
			reqAuth:    "Bearer shop-api-token-abc123",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Content-Type": {"application/json"}, "Authorization": {"Bearer shop-api-token-abc123"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}, "Location": {"/api/v1/products/101"}},
		},
		{method: "PUT", path: "/api/v1/products/42", host: 1, scan: 1, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 600, timeMs: 95, title: "",
			reqCT: "application/json", reqBody: []byte(`{"name":"Widget Pro v2","price":34.99}`),
			params:     []database.EmbeddedParam{{Name: "name", Value: "Widget Pro v2", Type: "json"}, {Name: "price", Value: "34.99", Type: "json"}},
			reqAuth:    "Bearer shop-api-token-abc123",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Content-Type": {"application/json"}, "Authorization": {"Bearer shop-api-token-abc123"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}},
		},
		{method: "DELETE", path: "/api/v1/products/99", host: 1, scan: 1, status: 204, phrase: "No Content", contentType: "", bodyLen: 0, timeMs: 55, title: "",
			reqAuth:    "Bearer shop-api-token-abc123",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Authorization": {"Bearer shop-api-token-abc123"}}, respHeaders: map[string][]string{},
		},
		{method: "PATCH", path: "/api/v1/products/42", host: 1, scan: 1, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 620, timeMs: 78, title: "",
			reqCT: "application/json", reqBody: []byte(`{"price":39.99}`),
			params:     []database.EmbeddedParam{{Name: "price", Value: "39.99", Type: "json"}},
			reqAuth:    "Bearer shop-api-token-abc123",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Content-Type": {"application/json"}, "Authorization": {"Bearer shop-api-token-abc123"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}},
		},
		{method: "GET", path: "/api/v1/orders?status=pending&limit=10", host: 1, scan: 1, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 8900, timeMs: 110, title: "",
			params:     []database.EmbeddedParam{{Name: "status", Value: "pending", Type: "url"}, {Name: "limit", Value: "10", Type: "url"}},
			reqAuth:    "Bearer shop-api-token-abc123",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Authorization": {"Bearer shop-api-token-abc123"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}, "X-Total-Count": {"47"}},
		},
		{method: "POST", path: "/api/v1/orders", host: 1, scan: 1, status: 201, phrase: "Created", contentType: "application/json", bodyLen: 920, timeMs: 250, title: "",
			reqCT: "application/json", reqBody: []byte(`{"product_id":42,"quantity":2,"shipping":"express"}`),
			params:     []database.EmbeddedParam{{Name: "product_id", Value: "42", Type: "json"}, {Name: "quantity", Value: "2", Type: "json"}, {Name: "shipping", Value: "express", Type: "json"}},
			reqAuth:    "Bearer shop-api-token-abc123",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Content-Type": {"application/json"}, "Authorization": {"Bearer shop-api-token-abc123"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}, "Location": {"/api/v1/orders/501"}},
		},
		{method: "GET", path: "/api/v1/users/me", host: 1, scan: 1, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 480, timeMs: 42, title: "",
			reqAuth:    "Bearer shop-api-token-abc123",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Authorization": {"Bearer shop-api-token-abc123"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}},
		},
		{method: "GET", path: "/api/v1/users/1' OR 1=1--", host: 1, scan: 1, status: 500, phrase: "Internal Server Error", contentType: "application/json", bodyLen: 320, timeMs: 1200, title: "",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}},
			remarks: []string{"sqli-error", "server-error", "high-response-time"},
		},
		{method: "GET", path: "/api/v1/health", host: 1, scan: 1, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 45, timeMs: 5, title: "",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}},
		},
		{method: "POST", path: "/api/v1/auth/login", host: 1, scan: 1, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 350, timeMs: 180, title: "",
			reqCT: "application/json", reqBody: []byte(`{"email":"user@shop.local","password":"s3cure!"}`),
			params:     []database.EmbeddedParam{{Name: "email", Value: "user@shop.local", Type: "json"}, {Name: "password", Value: "s3cure!", Type: "json"}},
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Content-Type": {"application/json"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}, "Set-Cookie": {"token=jwt-abc; HttpOnly; Secure; SameSite=Strict"}},
			remarks: []string{"auth-endpoint", "has-credentials", "sets-jwt"},
		},
		{method: "GET", path: "/api/v1/products?search='+UNION+SELECT+1,2,3--", host: 1, scan: 1, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 15000, timeMs: 850, title: "",
			params:     []database.EmbeddedParam{{Name: "search", Value: "'+UNION+SELECT+1,2,3--", Type: "url"}},
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}},
			remarks: []string{"sqli-union", "high-response-time", "data-leak"},
		},
		{method: "GET", path: "/api/v1/unauthorized-endpoint", host: 1, scan: 1, status: 401, phrase: "Unauthorized", contentType: "application/json", bodyLen: 85, timeMs: 12, title: "",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}, "WWW-Authenticate": {"Bearer"}},
		},
		{method: "OPTIONS", path: "/api/v1/products", host: 1, scan: 1, status: 204, phrase: "No Content", contentType: "", bodyLen: 0, timeMs: 3, title: "",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Origin": {"https://shop.local"}, "Access-Control-Request-Method": {"POST"}}, respHeaders: map[string][]string{"Access-Control-Allow-Origin": {"https://shop.local"}, "Access-Control-Allow-Methods": {"GET,POST,PUT,DELETE"}},
		},

		// ---- blog.test (scan 2) ----
		{method: "GET", path: "/", host: 2, scan: 2, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 18200, timeMs: 200, title: "Blog — Latest Posts",
			reqHeaders: map[string][]string{"Host": {"blog.test"}, "Accept": {"text/html"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}, "Server": {"Apache/2.4"}},
			technology: []string{"apache/2.4", "ruby-on-rails"},
		},
		{method: "GET", path: "/post/hello-world", host: 2, scan: 2, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 12400, timeMs: 175, title: "Hello World — Blog",
			reqHeaders: map[string][]string{"Host": {"blog.test"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
			parentPath: "/",
		},
		{method: "GET", path: "/post/sql-injection-101", host: 2, scan: 2, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 15800, timeMs: 190, title: "SQL Injection 101 — Blog",
			reqHeaders: map[string][]string{"Host": {"blog.test"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
			parentPath: "/",
		},
		{method: "POST", path: "/post/hello-world/comment", host: 2, scan: 2, status: 201, phrase: "Created", contentType: "text/html", bodyLen: 350, timeMs: 220, title: "",
			reqCT: "application/x-www-form-urlencoded", reqBody: []byte("author=Alice&body=Great+post!&email=alice@test.com"),
			params:     []database.EmbeddedParam{{Name: "author", Value: "Alice", Type: "body"}, {Name: "body", Value: "Great post!", Type: "body"}, {Name: "email", Value: "alice@test.com", Type: "body"}},
			reqHeaders: map[string][]string{"Host": {"blog.test"}, "Content-Type": {"application/x-www-form-urlencoded"}, "Cookie": {"session=blogsess123"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}, "Location": {"/post/hello-world#comment-5"}},
		},
		{method: "GET", path: "/tag/security", host: 2, scan: 2, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 9200, timeMs: 135, title: "Posts tagged 'security'",
			reqHeaders: map[string][]string{"Host": {"blog.test"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
		},
		{method: "GET", path: "/search?q=<img+src=x+onerror=alert(1)>", host: 2, scan: 2, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 5800, timeMs: 160, title: "Search Results",
			params:     []database.EmbeddedParam{{Name: "q", Value: "<img src=x onerror=alert(1)>", Type: "url"}},
			reqHeaders: map[string][]string{"Host": {"blog.test"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
			remarks: []string{"reflected-input", "xss-payload"},
		},
		{method: "GET", path: "/feed/rss", host: 2, scan: 2, status: 200, phrase: "OK", contentType: "application/rss+xml", bodyLen: 22000, timeMs: 80, title: "",
			reqHeaders: map[string][]string{"Host": {"blog.test"}, "Accept": {"application/rss+xml"}}, respHeaders: map[string][]string{"Content-Type": {"application/rss+xml; charset=UTF-8"}},
		},

		// ---- legacy.example.com (no scan — ingested traffic) ----
		{method: "GET", path: "/", host: 3, scan: -1, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 3500, timeMs: 350, title: "Legacy Portal",
			reqHeaders: map[string][]string{"Host": {"legacy.example.com"}, "Accept": {"text/html"}}, respHeaders: map[string][]string{"Content-Type": {"text/html"}, "Server": {"Apache/2.2"}, "X-Powered-By": {"PHP/5.6"}},
			technology: []string{"apache/2.2", "php/5.6"},
		},
		{method: "GET", path: "/index.php?page=../../../etc/passwd", host: 3, scan: -1, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 1800, timeMs: 280, title: "Legacy Portal",
			params:     []database.EmbeddedParam{{Name: "page", Value: "../../../etc/passwd", Type: "url"}},
			reqHeaders: map[string][]string{"Host": {"legacy.example.com"}}, respHeaders: map[string][]string{"Content-Type": {"text/html"}, "Server": {"Apache/2.2"}, "X-Powered-By": {"PHP/5.6"}},
			remarks: []string{"lfi-traversal", "legacy-stack"},
		},
		{method: "POST", path: "/cgi-bin/submit.cgi", host: 3, scan: -1, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 900, timeMs: 420, title: "Form Submitted",
			reqCT: "application/x-www-form-urlencoded", reqBody: []byte("name=test&value=data&token=abc123"),
			params:     []database.EmbeddedParam{{Name: "name", Value: "test", Type: "body"}, {Name: "value", Value: "data", Type: "body"}, {Name: "token", Value: "abc123", Type: "body"}},
			reqHeaders: map[string][]string{"Host": {"legacy.example.com"}, "Content-Type": {"application/x-www-form-urlencoded"}}, respHeaders: map[string][]string{"Content-Type": {"text/html"}, "Server": {"Apache/2.2"}},
		},
		{method: "GET", path: "/old-page", host: 3, scan: -1, status: 301, phrase: "Moved Permanently", contentType: "text/html", bodyLen: 0, timeMs: 25, title: "",
			reqHeaders: map[string][]string{"Host": {"legacy.example.com"}}, respHeaders: map[string][]string{"Location": {"https://example.com/old-page"}, "Server": {"Apache/2.2"}},
		},
		{method: "GET", path: "/redirect?url=https://evil.com", host: 3, scan: -1, status: 302, phrase: "Found", contentType: "text/html", bodyLen: 0, timeMs: 15, title: "",
			params:     []database.EmbeddedParam{{Name: "url", Value: "https://evil.com", Type: "url"}},
			reqHeaders: map[string][]string{"Host": {"legacy.example.com"}}, respHeaders: map[string][]string{"Location": {"https://evil.com"}, "Server": {"Apache/2.2"}},
			remarks: []string{"open-redirect"},
		},

		// ---- cdn.example.com (no scan — static assets) ----
		{method: "GET", path: "/images/logo.png", host: 4, scan: -1, status: 200, phrase: "OK", contentType: "image/png", bodyLen: 45000, timeMs: 8, title: "",
			reqHeaders: map[string][]string{"Host": {"cdn.example.com"}}, respHeaders: map[string][]string{"Content-Type": {"image/png"}, "Cache-Control": {"public, max-age=86400"}, "CDN-Cache-Status": {"HIT"}},
		},
		{method: "GET", path: "/fonts/roboto.woff2", host: 4, scan: -1, status: 200, phrase: "OK", contentType: "font/woff2", bodyLen: 67000, timeMs: 6, title: "",
			reqHeaders: map[string][]string{"Host": {"cdn.example.com"}}, respHeaders: map[string][]string{"Content-Type": {"font/woff2"}, "Cache-Control": {"public, max-age=31536000"}, "CDN-Cache-Status": {"HIT"}},
		},
		{method: "GET", path: "/videos/intro.mp4", host: 4, scan: -1, status: 206, phrase: "Partial Content", contentType: "video/mp4", bodyLen: 1048576, timeMs: 45, title: "",
			reqHeaders: map[string][]string{"Host": {"cdn.example.com"}, "Range": {"bytes=0-1048575"}}, respHeaders: map[string][]string{"Content-Type": {"video/mp4"}, "Content-Range": {"bytes 0-1048575/5242880"}, "Accept-Ranges": {"bytes"}},
		},
		{method: "HEAD", path: "/images/logo.png", host: 4, scan: -1, status: 200, phrase: "OK", contentType: "image/png", bodyLen: 0, timeMs: 3, title: "",
			reqHeaders: map[string][]string{"Host": {"cdn.example.com"}}, respHeaders: map[string][]string{"Content-Type": {"image/png"}, "Content-Length": {"45000"}},
		},

		// ---- admin.example.com:8443 (scan 0) ----
		{method: "GET", path: "/admin/", host: 5, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 5600, timeMs: 90, title: "Admin Panel",
			reqAuth:    "Basic YWRtaW46cGFzc3dvcmQ=",
			reqHeaders: map[string][]string{"Host": {"admin.example.com:8443"}, "Authorization": {"Basic YWRtaW46cGFzc3dvcmQ="}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}, "X-Frame-Options": {"DENY"}},
			remarks: []string{"admin-panel", "basic-auth"},
		},
		{method: "GET", path: "/admin/settings", host: 5, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 8400, timeMs: 105, title: "Settings — Admin",
			reqAuth:    "Basic YWRtaW46cGFzc3dvcmQ=",
			reqHeaders: map[string][]string{"Host": {"admin.example.com:8443"}, "Authorization": {"Basic YWRtaW46cGFzc3dvcmQ="}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
		},
		{method: "POST", path: "/admin/settings", host: 5, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 8600, timeMs: 150, title: "Settings Saved — Admin",
			reqCT: "application/x-www-form-urlencoded", reqBody: []byte("smtp_host=mail.example.com&smtp_port=587&debug={{7*7}}"),
			params:     []database.EmbeddedParam{{Name: "smtp_host", Value: "mail.example.com", Type: "body"}, {Name: "smtp_port", Value: "587", Type: "body"}, {Name: "debug", Value: "{{7*7}}", Type: "body"}},
			reqAuth:    "Basic YWRtaW46cGFzc3dvcmQ=",
			reqHeaders: map[string][]string{"Host": {"admin.example.com:8443"}, "Content-Type": {"application/x-www-form-urlencoded"}, "Authorization": {"Basic YWRtaW46cGFzc3dvcmQ="}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
			remarks: []string{"ssti-payload", "admin-panel"},
		},
		{method: "GET", path: "/admin/logs?file=../../../etc/shadow", host: 5, scan: 0, status: 200, phrase: "OK", contentType: "text/plain", bodyLen: 2800, timeMs: 60, title: "",
			params:     []database.EmbeddedParam{{Name: "file", Value: "../../../etc/shadow", Type: "url"}},
			reqAuth:    "Basic YWRtaW46cGFzc3dvcmQ=",
			reqHeaders: map[string][]string{"Host": {"admin.example.com:8443"}, "Authorization": {"Basic YWRtaW46cGFzc3dvcmQ="}}, respHeaders: map[string][]string{"Content-Type": {"text/plain"}},
			remarks: []string{"lfi-traversal", "sensitive-file"},
		},
		{method: "GET", path: "/admin/export?format=csv\r\nInjected-Header: evil", host: 5, scan: 0, status: 200, phrase: "OK", contentType: "text/csv", bodyLen: 15000, timeMs: 200, title: "",
			params:     []database.EmbeddedParam{{Name: "format", Value: "csv\r\nInjected-Header: evil", Type: "url"}},
			reqAuth:    "Basic YWRtaW46cGFzc3dvcmQ=",
			reqHeaders: map[string][]string{"Host": {"admin.example.com:8443"}, "Authorization": {"Basic YWRtaW46cGFzc3dvcmQ="}}, respHeaders: map[string][]string{"Content-Type": {"text/csv"}, "Content-Disposition": {"attachment; filename=export.csv"}},
			remarks: []string{"crlf-injection"},
		},

		// ---- Miscellaneous: no-response record, timeout, large body ----
		{method: "GET", path: "/api/v1/slow-endpoint", host: 1, scan: 1, status: 504, phrase: "Gateway Timeout", contentType: "text/html", bodyLen: 250, timeMs: 30000, title: "504 Gateway Timeout",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}}, respHeaders: map[string][]string{"Content-Type": {"text/html"}, "Server": {"nginx"}},
			remarks: []string{"timeout", "server-error"},
		},
		{method: "POST", path: "/api/v1/upload", host: 1, scan: 1, status: 413, phrase: "Payload Too Large", contentType: "application/json", bodyLen: 95, timeMs: 10, title: "",
			reqCT:      "multipart/form-data",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Content-Type": {"multipart/form-data; boundary=----formdata"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}},
		},
		{method: "GET", path: "/api/v2/beta/experimental", host: 1, scan: -1, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 120, timeMs: 25, title: "",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "X-Beta-Feature": {"true"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}, "X-Experimental": {"true"}},
		},

		// ---- Cookie-heavy request ----
		{method: "GET", path: "/account/preferences", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 6800, timeMs: 110, title: "Preferences",
			reqHeaders: map[string][]string{"Host": {"example.com"}, "Cookie": {"session=xyz789; theme=dark; lang=en; _ga=GA1.2.123456"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
		},

		// ---- WebSocket upgrade ----
		{method: "GET", path: "/ws/notifications", host: 0, scan: -1, status: 101, phrase: "Switching Protocols", contentType: "", bodyLen: 0, timeMs: 5, title: "",
			reqHeaders: map[string][]string{"Host": {"example.com"}, "Upgrade": {"websocket"}, "Connection": {"Upgrade"}, "Sec-WebSocket-Key": {"dGhlIHNhbXBsZSBub25jZQ=="}}, respHeaders: map[string][]string{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}, "Sec-WebSocket-Accept": {"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="}},
		},

		// ---- GraphQL ----
		{method: "POST", path: "/graphql", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 2400, timeMs: 180, title: "",
			reqCT: "application/json", reqBody: []byte(`{"query":"{ user(id: 1) { name email role } }"}`),
			reqHeaders: map[string][]string{"Host": {"example.com"}, "Content-Type": {"application/json"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}},
		},

		// ---- XML/SOAP ----
		{method: "POST", path: "/api/soap/UserService", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/xml", bodyLen: 1800, timeMs: 250, title: "",
			reqCT: "text/xml", reqBody: []byte(`<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetUser><ID>1</ID></GetUser></soap:Body></soap:Envelope>`),
			reqHeaders: map[string][]string{"Host": {"example.com"}, "Content-Type": {"text/xml; charset=UTF-8"}, "SOAPAction": {"GetUser"}}, respHeaders: map[string][]string{"Content-Type": {"text/xml; charset=UTF-8"}},
		},

		// ---- CORS preflight that got blocked ----
		{method: "OPTIONS", path: "/api/v1/admin/config", host: 1, scan: -1, status: 403, phrase: "Forbidden", contentType: "text/plain", bodyLen: 25, timeMs: 4, title: "",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Origin": {"https://evil-site.com"}, "Access-Control-Request-Method": {"DELETE"}}, respHeaders: map[string][]string{"Content-Type": {"text/plain"}},
		},
	}

	records := make([]*database.HTTPRecord, 0, len(endpoints))
	for i, ep := range endpoints {
		h := seedHosts[ep.host]
		baseURL := fmt.Sprintf("%s://%s", h.scheme, h.hostname)
		if (h.scheme == "https" && h.port != 443) || (h.scheme == "http" && h.port != 80) {
			baseURL += fmt.Sprintf(":%d", h.port)
		}

		uuid := fmt.Sprintf("rec-%04d-seed-aaaa-bbbb-cccc%04x", i+1, i+1)
		sentAt := now.Add(-time.Duration(len(endpoints)-i) * 30 * time.Second)

		rawReq := buildRawRequest(ep.method, ep.path, h.hostname, h.port, h.scheme, ep.reqHeaders, ep.reqBody)
		respBody := generateSeedBody(ep, h)
		rawResp := buildRawResponse(ep.status, ep.phrase, ep.respHeaders, ep.contentType, respBody)

		scanUUID := ""
		if ep.scan >= 0 && ep.scan < len(scans) {
			scanUUID = scans[ep.scan].UUID
		}

		parentUUID := ""
		if ep.parentPath != "" {
			for _, prev := range records {
				if prev.Hostname == h.hostname && prev.Path == ep.parentPath {
					parentUUID = prev.UUID
					break
				}
			}
		}

		rec := &database.HTTPRecord{
			UUID:     uuid,
			ScanUUID: scanUUID,
			Scheme:   h.scheme,
			Hostname: h.hostname,
			Port:     h.port,
			IP:       h.ip,

			Method:               ep.method,
			Path:                 ep.path,
			URL:                  baseURL + ep.path,
			HTTPVersion:          "HTTP/1.1",
			RequestContentType:   ep.reqCT,
			RequestContentLength: int64(len(ep.reqBody)),
			RawRequest:           rawReq,
			RequestHash:          hashStr(rawReq),
			RequestAuthorization: ep.reqAuth,

			StatusCode:            ep.status,
			StatusPhrase:          ep.phrase,
			ResponseHTTPVersion:   "HTTP/1.1",
			ResponseContentType:   ep.contentType,
			ResponseContentLength: int64(len(respBody)),
			RawResponse:           rawResp,
			ResponseHash:          hashStr(rawResp),
			ResponseTimeMs:        ep.timeMs,
			ResponseWords:         int64(len(respBody) / 5), // approximate word count
			HasResponse:           ep.status > 0,
			ResponseTitle:         ep.title,

			Parameters: ep.params,

			SentAt:     sentAt,
			ReceivedAt: sentAt.Add(time.Duration(ep.timeMs) * time.Millisecond),
			CreatedAt:  sentAt,

			Source:          "seed",
			Remarks:         ep.remarks,
			Technology:      ep.technology,
			ContentHash:     hashStr(respBody),
			IsAuthenticated: ep.reqAuth != "" || hasAuthHeader(ep.reqHeaders),
			ParentUUID:      parentUUID,
			RiskScore:       computeRiskScore(ep.remarks, ep.status),
		}
		records = append(records, rec)
	}

	// Add one record with no response (connection failed)
	noRespUUID := fmt.Sprintf("rec-%04d-seed-aaaa-bbbb-ccccnrsp", len(endpoints)+1)
	noRespRaw := []byte("GET /timeout-endpoint HTTP/1.1\r\nHost: unreachable.internal\r\n\r\n")
	records = append(records, &database.HTTPRecord{
		UUID:        noRespUUID,
		Scheme:      "https",
		Hostname:    "unreachable.internal",
		Port:        443,
		Method:      "GET",
		Path:        "/timeout-endpoint",
		URL:         "https://unreachable.internal/timeout-endpoint",
		HTTPVersion: "HTTP/1.1",
		RawRequest:  noRespRaw,
		RequestHash: hashStr(noRespRaw),
		HasResponse: false,
		SentAt:      now.Add(-25 * time.Hour),
		CreatedAt:   now.Add(-25 * time.Hour),
		Source:      "seed",
	})

	return records
}

// ---------------------------------------------------------------------------
// Response body generators — produce realistic content for seed data
// ---------------------------------------------------------------------------

// generateSeedBody produces a realistic response body based on the endpoint.
func generateSeedBody(ep seedEndpoint, h seedHost) []byte {
	if ep.bodyLen == 0 {
		return nil
	}

	hostPort := h.hostname
	if (h.scheme == "https" && h.port != 443) || (h.scheme == "http" && h.port != 80) {
		hostPort = fmt.Sprintf("%s:%d", h.hostname, h.port)
	}

	// --- Vulnerability-specific responses (order matters: check specific paths first) ---

	if strings.Contains(ep.path, "script>alert(1)") {
		return []byte(`<!DOCTYPE html>
<html><head><title>Search Results</title></head>
<body>
<h1>Search Results</h1>
<p>You searched for: <script>alert(1)</script></p>
<p>No results found for your query.</p>
<form action="/search" method="GET"><input type="text" name="q" value="<script>alert(1)</script>"><button>Search</button></form>
</body></html>`)
	}

	if strings.Contains(ep.path, "onerror=alert") {
		return []byte(`<!DOCTYPE html>
<html><head><title>Search Results</title></head>
<body>
<h1>Search Results</h1>
<p>You searched for: <img src=x onerror=alert(1)></p>
<p>No results found for your query.</p>
</body></html>`)
	}

	if strings.Contains(ep.path, "UNION+SELECT") {
		return []byte(`{"results":[{"id":1,"name":"admin","price":"s3cr3t_p@ssw0rd"},{"id":2,"name":"root","price":"r00t_p@ss!"},{"id":3,"name":"db_version","price":"PostgreSQL 14.2"}],"total":3}`)
	}

	if strings.Contains(ep.path, "' OR 1=1--") {
		return []byte(`{"error":"near \"OR\": syntax error","detail":"SELECT * FROM users WHERE id = '1' OR 1=1--'","code":"SQLITE_ERROR"}`)
	}

	if strings.Contains(ep.path, "file=../../../etc/shadow") {
		return []byte("root:$6$rounds=656000$ABC123$XYZhashvalue:18000:0:99999:7:::\ndaemon:*:18000:0:99999:7:::\nbin:*:18000:0:99999:7:::\nsys:*:18000:0:99999:7:::\nwww-data:$6$rounds=656000$DEF456$ABChashvalue:18200:0:99999:7:::\npostgres:$6$rounds=656000$GHI789$DEFhashvalue:18300:0:99999:7:::\n")
	}

	if strings.Contains(ep.path, "page=../../../etc/passwd") {
		return []byte(`<!DOCTYPE html>
<html><head><title>Legacy Portal</title></head>
<body>
<div class="content">root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
postgres:x:109:117:PostgreSQL administrator:/var/lib/postgresql:/bin/bash</div>
</body></html>`)
	}

	if strings.Contains(ep.path, "/admin/settings") && ep.method == "POST" {
		return []byte(`<!DOCTYPE html>
<html><head><title>Settings Saved — Admin</title></head>
<body>
<h1>Settings Updated</h1>
<div class="flash success">Settings saved successfully.</div>
<table>
<tr><td>SMTP Host</td><td>mail.example.com</td></tr>
<tr><td>SMTP Port</td><td>587</td></tr>
<tr><td>Debug</td><td>49</td></tr>
</table>
<a href="/admin/settings">Back to Settings</a>
</body></html>`)
	}

	if strings.Contains(ep.path, "Injected-Header") {
		return []byte("id,name,email,role\n1,admin,admin@example.com,administrator\n2,john,john@example.com,user\n3,jane,jane@example.com,editor\n4,bob,bob@example.com,user\n5,alice,alice@example.com,moderator\n")
	}

	if strings.Contains(ep.path, "url=https://evil.com") {
		return nil
	}

	if strings.Contains(ep.path, "/users/me") {
		return []byte(`{"id":1,"email":"user@shop.local","name":"Shop Admin","role":"admin","api_key":"sk-live-abc123xyz789def456","created_at":"2025-11-15T09:00:00Z","last_login":"2026-02-25T08:30:00Z"}`)
	}

	// --- JSON API responses ---
	if ep.contentType == "application/json" {
		return generateJSONSeedBody(ep)
	}

	// --- HTML responses ---
	if strings.Contains(ep.contentType, "text/html") {
		return generateHTMLSeedBody(ep, hostPort)
	}

	// --- Other content types ---
	switch ep.contentType {
	case "text/css":
		return []byte(`/* Main stylesheet */
:root { --primary: #2563eb; --bg: #ffffff; --text: #1e293b; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: var(--text); background: var(--bg); line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 0 1rem; }
nav { background: var(--primary); padding: 1rem; }
nav a { color: #fff; text-decoration: none; margin-right: 1rem; }
.btn { display: inline-block; padding: 0.5rem 1rem; background: var(--primary); color: #fff; border: none; border-radius: 4px; cursor: pointer; }
.btn:hover { opacity: 0.9; }`)
	case "application/javascript":
		return []byte(`(function(){"use strict";const APP_VERSION="2.1.0";const api={baseUrl:"/api",async get(path){const r=await fetch(this.baseUrl+path,{headers:{"Accept":"application/json"}});if(!r.ok)throw new Error(r.statusText);return r.json()},async post(path,data){const r=await fetch(this.baseUrl+path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)});return r.json()}};document.addEventListener("DOMContentLoaded",()=>{console.log("App "+APP_VERSION+" loaded");const nav=document.querySelector("nav");if(nav){nav.querySelectorAll("a").forEach(a=>{if(a.href===location.href)a.classList.add("active")})}});window.App={api,version:APP_VERSION};})();`)
	case "text/plain":
		if strings.Contains(ep.path, "robots.txt") {
			return []byte("User-agent: *\nDisallow: /admin/\nDisallow: /cgi-bin/\nDisallow: /api/\nAllow: /api/v1/products\nSitemap: https://example.com/sitemap.xml\n")
		}
		return []byte(fmt.Sprintf("%s %s — plain text response", ep.method, ep.path))
	case "application/xml":
		if strings.Contains(ep.path, "sitemap") {
			return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc><lastmod>2026-02-25</lastmod><priority>1.0</priority></url>
  <url><loc>https://example.com/about</loc><lastmod>2026-02-20</lastmod><priority>0.8</priority></url>
  <url><loc>https://example.com/contact</loc><lastmod>2026-02-18</lastmod><priority>0.7</priority></url>
  <url><loc>https://example.com/login</loc><lastmod>2026-02-15</lastmod><priority>0.6</priority></url>
  <url><loc>https://example.com/search</loc><lastmod>2026-02-25</lastmod><priority>0.9</priority></url>
</urlset>`)
		}
		return []byte(fmt.Sprintf(`<?xml version="1.0"?><response><status>%d</status><path>%s</path></response>`, ep.status, ep.path))
	case "application/rss+xml":
		return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Blog — Latest Posts</title>
    <link>https://blog.test</link>
    <description>Security research and tutorials</description>
    <item>
      <title>Hello World</title>
      <link>https://blog.test/post/hello-world</link>
      <description>Welcome to the blog! This is our first post covering the basics of web security.</description>
      <pubDate>Mon, 24 Feb 2026 10:00:00 GMT</pubDate>
    </item>
    <item>
      <title>SQL Injection 101</title>
      <link>https://blog.test/post/sql-injection-101</link>
      <description>A comprehensive guide to understanding and preventing SQL injection vulnerabilities.</description>
      <pubDate>Sun, 23 Feb 2026 14:30:00 GMT</pubDate>
    </item>
  </channel>
</rss>`)
	case "text/xml":
		return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUserResponse>
      <User>
        <ID>1</ID>
        <Name>John Doe</Name>
        <Email>john@example.com</Email>
        <Role>admin</Role>
        <LastLogin>2026-02-25T08:15:00Z</LastLogin>
      </User>
    </GetUserResponse>
  </soap:Body>
</soap:Envelope>`)
	case "text/csv":
		return []byte("id,name,email,role\n1,admin,admin@example.com,administrator\n2,john,john@example.com,user\n3,jane,jane@example.com,editor\n")
	}

	// Binary/media types
	if strings.HasPrefix(ep.contentType, "image/") || strings.HasPrefix(ep.contentType, "font/") || strings.HasPrefix(ep.contentType, "video/") {
		return []byte(fmt.Sprintf("[binary %s data — %d bytes]", ep.contentType, ep.bodyLen))
	}

	return []byte(fmt.Sprintf("[%d %s — response body for %s]", ep.status, ep.phrase, ep.path))
}

func generateJSONSeedBody(ep seedEndpoint) []byte {
	path := ep.path

	// Product list
	if strings.Contains(path, "/products") && ep.method == "GET" && !strings.Contains(path, "/42") && !strings.Contains(path, "/99") && !strings.Contains(path, "search=") {
		return []byte(`{"data":[{"id":1,"name":"Wireless Mouse","price":24.99,"category":"electronics","in_stock":true},{"id":2,"name":"USB-C Cable","price":12.99,"category":"electronics","in_stock":true},{"id":42,"name":"Widget Pro","price":29.99,"category":"electronics","in_stock":true},{"id":43,"name":"Ergonomic Keyboard","price":79.99,"category":"electronics","in_stock":false}],"total":47,"limit":20,"offset":0}`)
	}

	// Single product GET
	if strings.Contains(path, "/products/42") && ep.method == "GET" {
		return []byte(`{"id":42,"name":"Widget Pro","price":29.99,"category":"electronics","description":"Professional-grade widget with enhanced features","sku":"WP-042","in_stock":true,"created_at":"2026-01-10T12:00:00Z","updated_at":"2026-02-20T09:30:00Z"}`)
	}

	// Product PUT
	if strings.Contains(path, "/products/42") && ep.method == "PUT" {
		return []byte(`{"id":42,"name":"Widget Pro v2","price":34.99,"category":"electronics","description":"Professional-grade widget with enhanced features","sku":"WP-042","in_stock":true,"updated_at":"2026-02-25T10:00:00Z"}`)
	}

	// Product PATCH
	if strings.Contains(path, "/products/42") && ep.method == "PATCH" {
		return []byte(`{"id":42,"name":"Widget Pro v2","price":39.99,"category":"electronics","sku":"WP-042","in_stock":true,"updated_at":"2026-02-25T10:15:00Z"}`)
	}

	// Product POST (create)
	if strings.Contains(path, "/products") && ep.method == "POST" {
		return []byte(`{"id":101,"name":"Widget Pro","price":29.99,"category":"electronics","sku":"WP-101","in_stock":true,"created_at":"2026-02-25T10:05:00Z"}`)
	}

	// Orders list
	if strings.Contains(path, "/orders") && ep.method == "GET" {
		return []byte(`{"data":[{"id":497,"product_id":12,"quantity":1,"status":"pending","total":24.99,"created_at":"2026-02-24T16:00:00Z"},{"id":498,"product_id":42,"quantity":3,"status":"pending","total":89.97,"created_at":"2026-02-24T18:30:00Z"},{"id":499,"product_id":7,"quantity":1,"status":"pending","total":149.00,"created_at":"2026-02-25T08:00:00Z"}],"total":47,"limit":10,"offset":0}`)
	}

	// Order POST (create)
	if strings.Contains(path, "/orders") && ep.method == "POST" {
		return []byte(`{"id":501,"product_id":42,"quantity":2,"shipping":"express","status":"confirmed","total":69.98,"estimated_delivery":"2026-02-28T12:00:00Z","created_at":"2026-02-25T10:10:00Z"}`)
	}

	// Health
	if strings.Contains(path, "/health") {
		return []byte(`{"status":"healthy","uptime":"47h23m","version":"2.1.0"}`)
	}

	// Auth login
	if strings.Contains(path, "/auth/login") {
		return []byte(`{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZW1haWwiOiJ1c2VyQHNob3AubG9jYWwiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3NDA0NjAwMDAsImV4cCI6MTc0MDU0NjQwMH0.abc123","expires_in":86400,"token_type":"Bearer"}`)
	}

	// 401 Unauthorized
	if ep.status == 401 {
		return []byte(`{"error":"unauthorized","message":"Valid Bearer token required"}`)
	}

	// 413 Payload too large
	if ep.status == 413 {
		return []byte(`{"error":"payload_too_large","message":"Request body exceeds maximum size of 10MB","max_size":"10485760"}`)
	}

	// Beta/experimental
	if strings.Contains(path, "/beta/") || strings.Contains(path, "/experimental") {
		return []byte(`{"status":"ok","feature":"experimental-v2","enabled":true,"version":"0.1.0-beta"}`)
	}

	// GraphQL
	if strings.Contains(path, "/graphql") {
		return []byte(`{"data":{"user":{"id":1,"name":"John Doe","email":"john@example.com","role":"admin","created_at":"2025-11-15T09:00:00Z"}}}`)
	}

	// Default JSON
	return []byte(fmt.Sprintf(`{"status":"ok","path":"%s","timestamp":"2026-02-25T10:00:00Z"}`, path))
}

func generateHTMLSeedBody(ep seedEndpoint, hostPort string) []byte {
	title := ep.title
	if title == "" {
		title = fmt.Sprintf("%d %s", ep.status, ep.phrase)
	}

	// Error pages
	if ep.status == 403 {
		return []byte(fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>403 Forbidden</title></head>
<body>
<h1>403 Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<p>If you believe this is an error, contact the administrator.</p>
<hr><address>nginx/1.24 at %s</address>
</body></html>`, hostPort))
	}
	if ep.status == 404 {
		return []byte(fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>Page Not Found</title></head>
<body>
<h1>404 — Page Not Found</h1>
<p>The page you requested could not be found.</p>
<p><a href="/">Return to homepage</a></p>
<hr><address>nginx/1.24 at %s</address>
</body></html>`, hostPort))
	}
	if ep.status == 504 {
		return []byte(`<html><head><title>504 Gateway Timeout</title></head><body><h1>504 Gateway Timeout</h1><p>The upstream server did not respond in time.</p></body></html>`)
	}

	path := strings.SplitN(ep.path, "?", 2)[0]

	switch {
	// --- example.com ---
	case path == "/" && hostPort == "example.com":
		return []byte(`<!DOCTYPE html>
<html><head><title>Example Domain — Home</title><meta charset="UTF-8"></head>
<body>
<nav><a href="/">Home</a> <a href="/about">About</a> <a href="/contact">Contact</a> <a href="/login">Login</a></nav>
<main>
<h1>Welcome to Example Domain</h1>
<p>This is a demonstration website used for testing and development purposes.</p>
<div class="features">
  <div class="feature"><h3>Feature One</h3><p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p></div>
  <div class="feature"><h3>Feature Two</h3><p>Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p></div>
</div>
</main>
<footer><p>&copy; 2026 Example Domain</p></footer>
</body></html>`)

	case path == "/about":
		return []byte(`<!DOCTYPE html>
<html><head><title>About Us — Example</title></head>
<body>
<nav><a href="/">Home</a> <a href="/about">About</a> <a href="/contact">Contact</a></nav>
<main>
<h1>About Us</h1>
<p>We are a technology company focused on building secure web applications.</p>
<p>Founded in 2020, our team of engineers works on cutting-edge security solutions.</p>
<h2>Our Team</h2>
<ul><li>Jane Doe — CEO</li><li>John Smith — CTO</li><li>Alice Johnson — Lead Engineer</li></ul>
</main>
</body></html>`)

	case path == "/contact":
		return []byte(`<!DOCTYPE html>
<html><head><title>Contact — Example</title></head>
<body>
<nav><a href="/">Home</a> <a href="/about">About</a> <a href="/contact">Contact</a></nav>
<main>
<h1>Contact Us</h1>
<form action="/contact" method="POST">
  <label>Name: <input type="text" name="name" required></label>
  <label>Email: <input type="email" name="email" required></label>
  <label>Message: <textarea name="message" rows="4" required></textarea></label>
  <button type="submit">Send Message</button>
</form>
<p>Email: contact@example.com | Phone: +1 (555) 123-4567</p>
</main>
</body></html>`)

	case path == "/login" && ep.method == "GET":
		return []byte(`<!DOCTYPE html>
<html><head><title>Login</title></head>
<body>
<main>
<h1>Sign In</h1>
<form action="/login" method="POST">
  <label>Username: <input type="text" name="username" required autocomplete="username"></label>
  <label>Password: <input type="password" name="password" required autocomplete="current-password"></label>
  <label><input type="checkbox" name="remember"> Remember me</label>
  <button type="submit">Sign In</button>
</form>
<p><a href="/forgot-password">Forgot password?</a></p>
</main>
</body></html>`)

	case path == "/dashboard":
		return []byte(`<!DOCTYPE html>
<html><head><title>Dashboard — Example</title></head>
<body>
<nav><a href="/dashboard">Dashboard</a> <a href="/profile/1">Profile</a> <a href="/account/preferences">Settings</a> <a href="/logout">Logout</a></nav>
<main>
<h1>Dashboard</h1>
<div class="stats">
  <div class="stat"><h3>Total Requests</h3><span>1,542</span></div>
  <div class="stat"><h3>Active Users</h3><span>23</span></div>
  <div class="stat"><h3>Findings</h3><span>7</span></div>
</div>
<h2>Recent Activity</h2>
<table>
  <tr><td>2026-02-25 10:30</td><td>User admin logged in</td></tr>
  <tr><td>2026-02-25 10:28</td><td>Scan completed — 3 findings</td></tr>
  <tr><td>2026-02-25 09:15</td><td>New records imported — 50 URLs</td></tr>
</table>
</main>
</body></html>`)

	case strings.HasPrefix(path, "/search"):
		q := "test"
		for _, p := range ep.params {
			if p.Name == "q" {
				q = p.Value
				break
			}
		}
		return []byte(fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>Search Results — %s</title></head>
<body>
<h1>Search Results</h1>
<p>Showing results for: %s</p>
<form action="/search" method="GET"><input type="text" name="q" value="%s"><button>Search</button></form>
<div class="results">
  <div class="result"><a href="/page1">Result 1</a><p>First matching result for your search query.</p></div>
  <div class="result"><a href="/page2">Result 2</a><p>Another relevant page matching your search.</p></div>
</div>
<div class="pagination"><span>Page 1 of 1</span></div>
</body></html>`, q, q, q))

	case path == "/profile/1":
		return []byte(`<!DOCTYPE html>
<html><head><title>User Profile</title></head>
<body>
<h1>User Profile</h1>
<div class="profile">
  <div class="avatar"><img src="/images/avatar-1.png" alt="admin"></div>
  <table>
    <tr><td>Username</td><td>admin</td></tr>
    <tr><td>Email</td><td>admin@example.com</td></tr>
    <tr><td>Role</td><td>Administrator</td></tr>
    <tr><td>Joined</td><td>November 15, 2025</td></tr>
    <tr><td>Last Login</td><td>February 25, 2026 08:30</td></tr>
  </table>
</div>
</body></html>`)

	case path == "/account/preferences":
		return []byte(`<!DOCTYPE html>
<html><head><title>Preferences</title></head>
<body>
<h1>Account Preferences</h1>
<form action="/account/preferences" method="POST">
  <h2>Display</h2>
  <label>Theme: <select name="theme"><option value="dark" selected>Dark</option><option value="light">Light</option></select></label>
  <label>Language: <select name="lang"><option value="en" selected>English</option><option value="es">Español</option></select></label>
  <h2>Notifications</h2>
  <label><input type="checkbox" name="email_notify" checked> Email notifications</label>
  <label><input type="checkbox" name="scan_alerts" checked> Scan completion alerts</label>
  <button type="submit">Save Preferences</button>
</form>
</body></html>`)

	// --- blog.test ---
	case path == "/" && strings.Contains(hostPort, "blog"):
		return []byte(`<!DOCTYPE html>
<html><head><title>Blog — Latest Posts</title></head>
<body>
<header><h1>Security Blog</h1><nav><a href="/">Home</a> <a href="/feed/rss">RSS</a></nav></header>
<main>
  <article>
    <h2><a href="/post/hello-world">Hello World</a></h2>
    <time>February 24, 2026</time>
    <p>Welcome to the blog! This is our first post covering the basics of web security testing and vulnerability assessment.</p>
    <span class="tags"><a href="/tag/security">security</a> <a href="/tag/intro">intro</a></span>
  </article>
  <article>
    <h2><a href="/post/sql-injection-101">SQL Injection 101</a></h2>
    <time>February 23, 2026</time>
    <p>A comprehensive guide to understanding and preventing SQL injection vulnerabilities in modern web applications.</p>
    <span class="tags"><a href="/tag/security">security</a> <a href="/tag/sqli">sqli</a></span>
  </article>
</main>
</body></html>`)

	case path == "/post/hello-world" && ep.method == "GET":
		return []byte(`<!DOCTYPE html>
<html><head><title>Hello World — Blog</title></head>
<body>
<article>
<h1>Hello World</h1>
<time>February 24, 2026</time> <span class="author">by Admin</span>
<div class="content">
<p>Welcome to our security blog! In this first post, we'll cover the fundamentals of web application security testing.</p>
<p>Web security is a critical aspect of modern software development. Understanding common vulnerabilities helps developers build more secure applications.</p>
<h2>Topics We'll Cover</h2>
<ul>
  <li>Cross-Site Scripting (XSS)</li>
  <li>SQL Injection</li>
  <li>Path Traversal</li>
  <li>Authentication Flaws</li>
</ul>
<p>Stay tuned for more in-depth articles on each topic.</p>
</div>
<section class="comments">
  <h3>Comments (4)</h3>
  <div class="comment" id="comment-1"><strong>Alice</strong>: Great post! Very informative introduction.</div>
  <div class="comment" id="comment-2"><strong>Bob</strong>: Looking forward to the SQL injection article.</div>
  <div class="comment" id="comment-3"><strong>Charlie</strong>: Could you also cover CSRF?</div>
  <div class="comment" id="comment-4"><strong>Diana</strong>: Nice overview of the basics.</div>
</section>
</article>
</body></html>`)

	case path == "/post/sql-injection-101":
		return []byte(`<!DOCTYPE html>
<html><head><title>SQL Injection 101 — Blog</title></head>
<body>
<article>
<h1>SQL Injection 101</h1>
<time>February 23, 2026</time> <span class="author">by Admin</span>
<div class="content">
<p>SQL injection (SQLi) is one of the most critical web application vulnerabilities. It occurs when user input is incorporated into SQL queries without proper sanitization.</p>
<h2>How It Works</h2>
<p>Consider a vulnerable query: <code>SELECT * FROM users WHERE id = '$input'</code></p>
<p>An attacker can input <code>1' OR '1'='1</code> to bypass authentication or extract data.</p>
<h2>Prevention</h2>
<ul>
  <li>Use parameterized queries (prepared statements)</li>
  <li>Use ORM frameworks that handle escaping</li>
  <li>Validate and sanitize all user input</li>
  <li>Apply principle of least privilege to database accounts</li>
</ul>
</div>
</article>
</body></html>`)

	case strings.Contains(path, "/comment"):
		return []byte(`<!DOCTYPE html>
<html><head><title>Comment Posted</title></head>
<body><p>Your comment has been posted successfully.</p><a href="/post/hello-world#comment-5">View comment</a></body></html>`)

	case path == "/tag/security":
		return []byte(`<!DOCTYPE html>
<html><head><title>Posts tagged 'security'</title></head>
<body>
<h1>Posts tagged: security</h1>
<ul>
  <li><a href="/post/hello-world">Hello World</a> — February 24, 2026</li>
  <li><a href="/post/sql-injection-101">SQL Injection 101</a> — February 23, 2026</li>
</ul>
</body></html>`)

	// --- legacy.example.com ---
	case path == "/" && strings.Contains(hostPort, "legacy"):
		return []byte(`<html><head><title>Legacy Portal</title></head>
<body bgcolor="#ffffff">
<table width="100%"><tr><td><h1>Legacy Portal</h1></td></tr></table>
<p>Welcome to the legacy application portal. This system is scheduled for migration.</p>
<ul>
<li><a href="/index.php?page=home">Home</a></li>
<li><a href="/index.php?page=about">About</a></li>
<li><a href="/cgi-bin/submit.cgi">Submit Form</a></li>
</ul>
<hr><font size="2">Powered by PHP/5.6</font>
</body></html>`)

	case strings.Contains(path, "/cgi-bin/submit"):
		return []byte(`<html><head><title>Form Submitted</title></head>
<body>
<h1>Form Submitted Successfully</h1>
<p>Thank you for your submission.</p>
<p>Name: test</p>
<p>Value: data</p>
<p><a href="/">Return to portal</a></p>
</body></html>`)

	// --- admin.example.com ---
	case path == "/admin/" || path == "/admin":
		return []byte(`<!DOCTYPE html>
<html><head><title>Admin Panel</title></head>
<body>
<nav><a href="/admin/">Dashboard</a> <a href="/admin/settings">Settings</a> <a href="/admin/logs">Logs</a> <a href="/admin/export">Export</a></nav>
<main>
<h1>Admin Panel</h1>
<div class="stats">
  <div class="stat"><h3>Users</h3><span>156</span></div>
  <div class="stat"><h3>Sessions</h3><span>23</span></div>
  <div class="stat"><h3>Errors (24h)</h3><span>4</span></div>
</div>
<h2>System Status</h2>
<p>Server: admin.example.com:8443</p>
<p>Uptime: 14 days, 6 hours</p>
<p>Database: PostgreSQL 14.2</p>
</main>
</body></html>`)

	case path == "/admin/settings" && ep.method == "GET":
		return []byte(`<!DOCTYPE html>
<html><head><title>Settings — Admin</title></head>
<body>
<nav><a href="/admin/">Dashboard</a> <a href="/admin/settings">Settings</a> <a href="/admin/logs">Logs</a></nav>
<main>
<h1>Server Settings</h1>
<form action="/admin/settings" method="POST">
  <h2>Email (SMTP)</h2>
  <label>SMTP Host: <input type="text" name="smtp_host" value="mail.example.com"></label>
  <label>SMTP Port: <input type="number" name="smtp_port" value="587"></label>
  <h2>Debug</h2>
  <label>Debug Value: <input type="text" name="debug" value=""></label>
  <button type="submit">Save Settings</button>
</form>
</main>
</body></html>`)
	}

	// Generic HTML fallback
	return []byte(fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>%s</title></head>
<body>
<h1>%s</h1>
<p>Page content for %s on %s.</p>
</body></html>`, title, title, path, hostPort))
}
