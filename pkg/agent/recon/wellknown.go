package recon

// Conservative recon path catalog. GET-only, no payloads, no method
// fuzzing beyond a single OPTIONS / probe. Paths here are chosen to
// produce strong stack/spec signals while avoiding anything a typical
// WAF treats as scanning behavior.

// apiSpecPath is a well-known location that, if it returns a 2xx with a
// recognizable body, identifies the API surface (OpenAPI, Swagger,
// GraphQL, Postman, AsyncAPI).
type apiSpecPath struct {
	Path string
	Kind string // "openapi" | "swagger" | "graphql" | "postman" | "asyncapi"
}

// apiSpecPaths is the conservative list of API-spec discovery paths.
// GraphQL is in stackProbePaths instead because it needs a follow-up
// introspection POST.
var apiSpecPaths = []apiSpecPath{
	{"/openapi.json", "openapi"},
	{"/openapi.yaml", "openapi"},
	{"/v3/api-docs", "openapi"}, // springdoc default
	{"/v2/api-docs", "swagger"}, // springfox legacy
	{"/swagger.json", "swagger"},
	{"/swagger.yaml", "swagger"},
	{"/swagger/v1/swagger.json", "swagger"},
	{"/api-docs", "swagger"},
	{"/api-docs.json", "swagger"},
	{"/api/swagger.json", "swagger"},
	{"/docs/openapi.json", "openapi"},
	{"/docs/swagger.json", "swagger"},
	{"/postman_collection.json", "postman"},
	{"/asyncapi.json", "asyncapi"},
}

// graphqlProbePaths are POSTed with an introspection query to detect
// GraphQL endpoints. The introspection POST is the only "active" probe
// in the conservative set besides OPTIONS — needed because GET /graphql
// often returns a generic 200 GraphiQL HTML that doesn't confirm an
// actual endpoint.
var graphqlProbePaths = []string{
	"/graphql",
	"/api/graphql",
	"/v1/graphql",
}

// wellKnownPaths are RFC 8615 well-known URIs and adjacent
// always-safe-to-fetch metadata locations.
var wellKnownPaths = []string{
	"/robots.txt",
	"/sitemap.xml",
	"/sitemap_index.xml",
	"/humans.txt",
	"/.well-known/security.txt",
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
	"/.well-known/host-meta",
	"/.well-known/host-meta.json",
	"/.well-known/webfinger",
	"/.well-known/change-password",
	"/.well-known/apple-app-site-association",
	"/.well-known/assetlinks.json",
	"/.well-known/nodeinfo",
	"/crossdomain.xml",
	"/clientaccesspolicy.xml",
}

// stackProbePath is a path whose mere reachability (200/3xx) indicates a
// stack. The Tag is the module tag the planner can emit to focus the
// native scanner; Name and Category populate the StackDetection.
type stackProbePath struct {
	Path     string
	Name     string
	Category string
	Tag      string
	Reason   string // human-readable evidence line written into StackDetection.Evidence
}

// stackProbePaths are conservative reachability probes used to confirm a
// stack independently of header/body signals. We treat 2xx/3xx (not
// 401/403/404) as a positive signal so authenticated admin paths still
// count.
var stackProbePaths = []stackProbePath{
	// Spring Boot Actuator surface — strong signal even when only /health is exposed.
	{"/actuator", "spring-boot", "framework", "spring", "actuator root reachable"},
	{"/actuator/health", "spring-boot", "framework", "spring", "actuator health endpoint reachable"},
	{"/actuator/info", "spring-boot", "framework", "spring", "actuator info endpoint reachable"},
	{"/actuator/env", "spring-boot", "framework", "spring", "actuator env endpoint reachable (sensitive)"},
	{"/actuator/mappings", "spring-boot", "framework", "spring", "actuator mappings reachable (sensitive)"},
	// WordPress.
	{"/wp-login.php", "wordpress", "cms", "wordpress", "wp-login.php reachable"},
	{"/wp-admin/", "wordpress", "cms", "wordpress", "wp-admin reachable"},
	{"/wp-json/", "wordpress", "cms", "wordpress", "wp-json REST API reachable"},
	// Drupal.
	{"/user/login", "drupal", "cms", "drupal", "drupal user/login reachable"},
	{"/core/install.php", "drupal", "cms", "drupal", "drupal core install reachable"},
	// Joomla.
	{"/administrator/", "joomla", "cms", "joomla", "joomla administrator panel reachable"},
	// Apache server-status / Tomcat.
	{"/server-status", "apache", "server", "apache", "Apache server-status reachable"},
	{"/server-info", "apache", "server", "apache", "Apache server-info reachable"},
	{"/manager/html", "tomcat", "server", "tomcat", "Tomcat manager reachable"},
	{"/host-manager/html", "tomcat", "server", "tomcat", "Tomcat host-manager reachable"},
	// PHP info / generic dev surface.
	{"/phpinfo.php", "php", "language", "php", "phpinfo.php reachable"},
	{"/info.php", "php", "language", "php", "info.php reachable"},
	// Go / Prometheus debug surface.
	{"/debug/pprof/", "go", "language", "go", "Go pprof debug endpoint reachable"},
	{"/metrics", "prometheus", "framework", "metrics", "Prometheus /metrics reachable"},
}

// sensitivePath is a path whose reachability is itself a finding,
// independent of stack detection. Body contents are deliberately NOT
// captured — only status code is recorded.
type sensitivePath struct {
	Path   string
	Reason string
}

var sensitivePaths = []sensitivePath{
	{"/.env", "environment file reachable"},
	{"/.env.production", "production environment file reachable"},
	{"/.env.local", "local environment file reachable"},
	{"/.git/HEAD", "git metadata exposed"},
	{"/.git/config", "git config exposed"},
	{"/.svn/entries", "subversion metadata exposed"},
	{"/.DS_Store", "macOS metadata file exposed"},
	{"/web.config", "IIS web.config exposed"},
	{"/.htaccess", "htaccess reachable (should be 403)"},
	{"/config.php.bak", "config backup reachable"},
	{"/wp-config.php.bak", "wordpress config backup reachable"},
}

// optionsProbePaths are the paths we send OPTIONS to in order to collect
// the Allow header. We deliberately keep this list very small to avoid
// looking like method-fuzzing.
var optionsProbePaths = []string{"/", "/api"}

// trackedSecurityHeaders are response headers we audit on the base URL.
// Missing entries are flagged in SecurityHeadersAudit.Missing.
var trackedSecurityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
}
