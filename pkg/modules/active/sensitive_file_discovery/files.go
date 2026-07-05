package sensitive_file_discovery

import "github.com/vigolium/vigolium/pkg/types/severity"

// sensitiveFile defines a file to probe with its expected content markers.
type sensitiveFile struct {
	path        string
	name        string
	markers     []string // at least one must match in the response body
	antiMarkers []string // if any matches, skip (false positive indicator)
	sev         severity.Severity
	desc        string
}

var sensitiveFiles = []sensitiveFile{
	// Git
	{
		path:    "/.git/config",
		name:    "Git Configuration",
		markers: []string{"[core]", "[remote", "repositoryformatversion"},
		sev:     severity.High,
		desc:    "Git repository configuration file exposed, potentially allowing source code disclosure",
	},
	{
		path:    "/.git/HEAD",
		name:    "Git HEAD Reference",
		markers: []string{"ref: refs/"},
		sev:     severity.High,
		desc:    "Git HEAD file exposed, indicating an accessible .git directory",
	},
	{
		// The staging index magic ("DIRC"), reflog, and packed-refs confirm the whole
		// .git tree is walkable — i.e. full source (and any committed secrets) can be
		// reconstructed with git-dumper, not just the config leaked.
		path:    "/.git/index",
		name:    "Git Index (tree walkable)",
		markers: []string{"DIRC"},
		sev:     severity.High,
		desc:    "Git index file exposed — the .git object tree is walkable, allowing full source reconstruction",
	},
	{
		path:    "/.git/logs/HEAD",
		name:    "Git Reflog",
		markers: []string{"clone:", "commit:", "checkout:", "commit (initial)"},
		sev:     severity.High,
		desc:    "Git reflog exposed, disclosing commit history and enabling full source reconstruction",
	},
	{
		path:    "/.git/packed-refs",
		name:    "Git Packed Refs",
		markers: []string{"# pack-refs", "refs/heads/", "refs/tags/"},
		sev:     severity.High,
		desc:    "Git packed-refs exposed, disclosing branch/tag object IDs for source reconstruction",
	},
	// Infrastructure-as-Code state (plaintext secrets + full resource/IP map)
	{
		path:        "/terraform.tfstate",
		name:        "Terraform State File",
		markers:     []string{`"terraform_version"`, `"lineage"`, `"serial"`},
		antiMarkers: []string{"<html", "<HTML", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Terraform state file exposed — contains plaintext secrets, resource IDs, and the full infrastructure/IP map",
	},
	{
		path:        "/terraform.tfstate.backup",
		name:        "Terraform State Backup",
		markers:     []string{`"terraform_version"`, `"lineage"`, `"serial"`},
		antiMarkers: []string{"<html", "<HTML", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Terraform state backup exposed — contains plaintext secrets and the full infrastructure map",
	},
	{
		path:        "/docker-compose.yml",
		name:        "Docker Compose File",
		markers:     []string{"services:"},
		antiMarkers: []string{"<html", "<HTML", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "docker-compose file exposed, revealing service topology, image tags, and often embedded credentials",
	},
	{
		path:        "/docker-compose.yaml",
		name:        "Docker Compose File",
		markers:     []string{"services:"},
		antiMarkers: []string{"<html", "<HTML", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "docker-compose file exposed, revealing service topology, image tags, and often embedded credentials",
	},
	// CI/CD pipeline definitions (secrets, internal infra, runner topology)
	{
		path:        "/.gitlab-ci.yml",
		name:        "GitLab CI Config",
		markers:     []string{"stages:", "script:"},
		antiMarkers: []string{"<html", "<HTML", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "GitLab CI configuration exposed, revealing pipeline stages, scripts, and internal infrastructure",
	},
	{
		path:        "/.circleci/config.yml",
		name:        "CircleCI Config",
		markers:     []string{"jobs:", "workflows:"},
		antiMarkers: []string{"<html", "<HTML", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "CircleCI configuration exposed, revealing pipeline jobs and internal infrastructure",
	},
	{
		path:        "/.travis.yml",
		name:        "Travis CI Config",
		markers:     []string{"language:", "script:", "install:"},
		antiMarkers: []string{"<html", "<HTML", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Travis CI configuration exposed, revealing build steps and internal infrastructure",
	},
	{
		path:        "/Jenkinsfile",
		name:        "Jenkinsfile",
		markers:     []string{"pipeline {", "stage(", "agent {", "node {"},
		antiMarkers: []string{"<html", "<HTML", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Jenkinsfile exposed, revealing build pipeline, credentials references, and internal infrastructure",
	},
	{
		path:        "/.npmrc",
		name:        "npm Config",
		markers:     []string{"_authToken", "//registry", "_auth="},
		antiMarkers: []string{"<html", "<HTML", "<!DOCTYPE"},
		sev:         severity.High,
		desc:        "npm configuration exposed, potentially containing a registry auth token",
	},
	{
		path:        "/.pypirc",
		name:        "PyPI Config",
		markers:     []string{"[pypi]", "[distutils]", "password"},
		antiMarkers: []string{"<html", "<HTML", "<!DOCTYPE"},
		sev:         severity.High,
		desc:        "PyPI configuration exposed, potentially containing package-index credentials",
	},
	// Environment files
	{
		path:        "/.env",
		name:        "Environment File",
		markers:     []string{"DB_", "API_", "SECRET", "KEY", "PASSWORD", "TOKEN"},
		antiMarkers: []string{"<html", "<HTML", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Environment configuration file exposed, potentially containing credentials and API keys",
	},
	{
		path:        "/.env.local",
		name:        "Local Environment File",
		markers:     []string{"DB_", "API_", "SECRET", "KEY"},
		antiMarkers: []string{"<html", "<HTML", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Local environment file exposed with potential secrets",
	},
	{
		path:        "/.env.production",
		name:        "Production Environment File",
		markers:     []string{"DB_", "API_", "SECRET", "KEY"},
		antiMarkers: []string{"<html", "<HTML", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Production environment file exposed with potential secrets",
	},
	// Debug and monitoring
	{
		path:    "/debug/pprof/",
		name:    "Go pprof Debug",
		markers: []string{"Types of profiles available", "goroutine", "heap"},
		sev:     severity.Medium,
		desc:    "Go pprof debug endpoint exposed, revealing server internals",
	},
	{
		path:    "/metrics",
		name:    "Prometheus Metrics",
		markers: []string{"# HELP", "# TYPE", "process_"},
		sev:     severity.Low,
		desc:    "Prometheus metrics endpoint exposed, revealing server performance data",
	},
	{
		path:    "/server-status",
		name:    "Apache Server Status",
		markers: []string{"Apache Server Status", "Total Accesses", "Server uptime"},
		sev:     severity.Medium,
		desc:    "Apache server-status page exposed, revealing server configuration",
	},
	{
		path:    "/server-info",
		name:    "Apache Server Info",
		markers: []string{"Apache Server Information", "Server Settings"},
		sev:     severity.Medium,
		desc:    "Apache server-info page exposed, revealing module configuration",
	},
	// Configuration files
	{
		path:        "/wp-config.php.bak",
		name:        "WordPress Config Backup",
		markers:     []string{"DB_NAME", "DB_USER", "DB_PASSWORD"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "WordPress configuration backup file exposed with database credentials",
	},
	{
		path:    "/phpinfo.php",
		name:    "PHP Info Page",
		markers: []string{"phpinfo()", "PHP Version", "System"},
		sev:     severity.Medium,
		desc:    "phpinfo() page exposed, revealing PHP configuration and server details",
	},
	{
		path:    "/.htpasswd",
		name:    "Apache Password File",
		markers: []string{":$apr1$", ":$2y$", ":{SHA}"},
		sev:     severity.Critical,
		desc:    "Apache htpasswd file exposed, containing hashed credentials",
	},
	{
		path:        "/.htaccess",
		name:        "Apache htaccess",
		markers:     []string{"RewriteEngine", "RewriteRule", "AuthType", "Require"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Apache .htaccess file exposed, revealing URL rewrite rules and access controls",
	},
	// Backup and temp files
	{
		path:    "/backup.sql",
		name:    "SQL Backup",
		markers: []string{"CREATE TABLE", "INSERT INTO", "DROP TABLE"},
		sev:     severity.Critical,
		desc:    "SQL backup file exposed, potentially containing full database dump",
	},
	{
		path:    "/database.sql",
		name:    "SQL Dump",
		markers: []string{"CREATE TABLE", "INSERT INTO", "DROP TABLE"},
		sev:     severity.Critical,
		desc:    "SQL dump file exposed, potentially containing full database",
	},
	// Docker/Container
	{
		path:    "/Dockerfile",
		name:    "Dockerfile",
		markers: []string{"FROM", "RUN", "EXPOSE", "CMD", "ENTRYPOINT"},
		sev:     severity.Medium,
		desc:    "Dockerfile exposed, revealing build configuration and potentially secrets",
	},
	{
		path:    "/docker-compose.yml",
		name:    "Docker Compose",
		markers: []string{"version:", "services:", "image:"},
		sev:     severity.Medium,
		desc:    "Docker Compose file exposed, revealing service architecture",
	},
	// IDE and editor files
	{
		path: "/.vscode/settings.json",
		name: "VS Code Settings",
		// Bare "{"/"}" matched ANY JSON body (a catch-all could also serve JSON to
		// the decoy round). Require a VS Code setting-key prefix, which a generic
		// JSON payload does not carry.
		markers: []string{`"editor.`, `"workbench.`, `"files.`, `"python.`, `"[json]"`, `"terminal.`},
		sev:     severity.Low,
		desc:    "VS Code settings file exposed, potentially revealing project configuration",
	},
	{
		path:    "/.idea/workspace.xml",
		name:    "IntelliJ IDEA Workspace",
		markers: []string{"<?xml", "<project"},
		sev:     severity.Low,
		desc:    "IntelliJ IDEA workspace file exposed",
	},
	// Source maps
	{
		path:    "/main.js.map",
		name:    "JavaScript Source Map",
		markers: []string{`"version"`, `"sources"`, `"mappings"`},
		sev:     severity.Low,
		desc:    "JavaScript source map exposed, enabling source code reconstruction",
	},
	// API documentation
	{
		path:    "/swagger.json",
		name:    "Swagger API Documentation",
		markers: []string{`"swagger"`, `"paths"`, `"info"`},
		sev:     severity.Low,
		desc:    "Swagger API documentation exposed, revealing all API endpoints",
	},
	{
		path:    "/openapi.json",
		name:    "OpenAPI Specification",
		markers: []string{`"openapi"`, `"paths"`, `"info"`},
		sev:     severity.Low,
		desc:    "OpenAPI specification exposed, revealing all API endpoints",
	},
	// Error logs
	{
		path:        "/error.log",
		name:        "Error Log",
		markers:     []string{"[error]", "stack trace", "Exception", "Fatal"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Error log file exposed, potentially containing stack traces and internal paths",
	},
	// Admin panels
	{
		path:    "/adminer.php",
		name:    "Adminer Database Manager",
		markers: []string{"Adminer", "adminer.org", "Login"},
		sev:     severity.High,
		desc:    "Adminer database management tool exposed",
	},
	{
		path:    "/elmah.axd",
		name:    "ELMAH Error Log",
		markers: []string{"Error Log for", "ELMAH", "Error Filtering"},
		sev:     severity.Medium,
		desc:    "ELMAH error logging handler exposed, revealing application errors",
	},
	// JS Framework — Next.js
	{
		path:        "/api/preview",
		name:        "Next.js Preview Mode",
		markers:     []string{"preview", "previewData"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Next.js Preview Mode API endpoint exposed, may allow access to draft content",
	},
	{
		path:        "/api/draft",
		name:        "Next.js Draft Mode",
		markers:     []string{"draft", "draftMode"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Next.js Draft Mode API endpoint exposed, may allow access to draft content",
	},
	{
		path:        "/api/revalidate",
		name:        "Next.js ISR Revalidation",
		markers:     []string{"revalidated"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Next.js ISR revalidation endpoint exposed, may allow cache manipulation",
	},
	{
		path:        "/.next/build-manifest.json",
		name:        "Next.js Build Manifest",
		markers:     []string{`"pages"`, `"devFiles"`},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Next.js build manifest exposed, revealing all application pages and asset structure",
	},
	{
		path:        "/.next/server/pages-manifest.json",
		name:        "Next.js Pages Manifest",
		markers:     []string{`"/"`},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.High,
		desc:        "Next.js server pages manifest exposed, revealing all server-side page routes",
	},
	// JS Framework — React CRA
	{
		path:        "/asset-manifest.json",
		name:        "React CRA Asset Manifest",
		markers:     []string{`"files"`, `"entrypoints"`},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "React CRA asset manifest exposed, revealing build structure and entry points",
	},
	// JS Framework — Next.js Dev
	{
		path:    "/_next/static/development/_buildManifest.js",
		name:    "Next.js Dev Build Manifest",
		markers: []string{"self.__BUILD_MANIFEST"},
		sev:     severity.Medium,
		desc:    "Next.js development build manifest exposed, indicating dev mode in production",
	},
	// SVN
	{
		path:    "/.svn/entries",
		name:    "SVN Entries",
		markers: []string{"dir", "svn:"},
		sev:     severity.High,
		desc:    "SVN entries file exposed, indicating an accessible .svn directory",
	},
	// Mercurial
	{
		path:    "/.hg/store",
		name:    "Mercurial Store",
		markers: []string{"data/", "fncache"},
		sev:     severity.High,
		desc:    "Mercurial store directory exposed, indicating an accessible .hg directory",
	},
	// Environment backups
	{
		path:        "/.env.bak",
		name:        "Environment Backup",
		markers:     []string{"DB_", "API_", "SECRET", "KEY"},
		antiMarkers: []string{"<html", "<HTML", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Environment backup file exposed with potential secrets",
	},
	{
		path:        "/.env.old",
		name:        "Old Environment File",
		markers:     []string{"DB_", "API_", "SECRET", "KEY"},
		antiMarkers: []string{"<html", "<HTML", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Old environment file exposed with potential secrets",
	},
}
