package rails_sensitive_files

import "github.com/vigolium/vigolium/pkg/types/severity"

type sensitiveFile struct {
	path        string
	name        string
	markers     []string
	antiMarkers []string
	sev         severity.Severity
	desc        string
}

var sensitiveFiles = []sensitiveFile{
	{
		path:    "/config/master.key",
		name:    "Rails Master Key",
		markers: []string{},
		sev:     severity.Critical,
		desc:    "Rails master key is exposed. This key decrypts all credentials and can be used to forge session cookies, potentially leading to full application compromise",
	},
	{
		path:    "/config/credentials.yml.enc",
		name:    "Rails Encrypted Credentials",
		markers: []string{},
		sev:     severity.Medium,
		desc:    "Rails encrypted credentials file is exposed. Combined with a leaked master key, this allows full secret disclosure",
	},
	{
		path:    "/config/credentials/production.yml.enc",
		name:    "Rails Production Encrypted Credentials",
		markers: []string{},
		sev:     severity.Medium,
		desc:    "Rails production encrypted credentials file is exposed",
	},
	{
		path:    "/config/secrets.yml",
		name:    "Rails Secrets (Legacy)",
		markers: []string{"secret_key_base"},
		sev:     severity.Critical,
		desc:    "Legacy Rails secrets.yml is exposed, containing secret_key_base which enables session/cookie forgery",
	},
	{
		path:    "/config/database.yml",
		name:    "Rails Database Config",
		markers: []string{"adapter:", "database:"},
		sev:     severity.Critical,
		desc:    "Rails database configuration is exposed, potentially containing database credentials and hostnames",
	},
	{
		path:        "/Gemfile",
		name:        "Gemfile",
		markers:     []string{"source", "gem "},
		antiMarkers: []string{"<!DOCTYPE", "<html"},
		sev:         severity.Medium,
		desc:        "Ruby Gemfile is exposed, revealing application dependencies",
	},
	{
		path:    "/Gemfile.lock",
		name:    "Gemfile.lock",
		markers: []string{"GEM", "specs:", "DEPENDENCIES"},
		sev:     severity.Medium,
		desc:    "Ruby Gemfile.lock is exposed, revealing exact dependency versions which can be mapped to known CVEs",
	},
	{
		path:        "/config/puma.rb",
		name:        "Puma Config",
		markers:     []string{"workers", "threads", "bind", "port"},
		antiMarkers: []string{"<!DOCTYPE", "<html"},
		sev:         severity.Low,
		desc:        "Puma web server configuration is exposed, revealing server settings and potentially internal network details",
	},
	{
		path:        "/config/unicorn.rb",
		name:        "Unicorn Config",
		markers:     []string{"worker_processes", "listen", "preload_app"},
		antiMarkers: []string{"<!DOCTYPE", "<html"},
		sev:         severity.Low,
		desc:        "Unicorn web server configuration is exposed",
	},
	{
		path:    "/db/schema.rb",
		name:    "Database Schema",
		markers: []string{"ActiveRecord::Schema", "create_table"},
		sev:     severity.Medium,
		desc:    "Rails database schema is exposed, revealing table structures and column definitions",
	},
	{
		path:        "/db/seeds.rb",
		name:        "Database Seeds",
		markers:     []string{"create", "User", "find_or_create"},
		antiMarkers: []string{"<!DOCTYPE", "<html"},
		sev:         severity.Medium,
		desc:        "Rails database seed file is exposed, potentially containing default credentials or test data",
	},
	{
		path:    "/log/production.log",
		name:    "Production Log",
		markers: []string{"Started GET", "Processing by", "Completed"},
		sev:     severity.High,
		desc:    "Rails production log is exposed, potentially containing PII, session tokens, and internal routes",
	},
	{
		path:    "/log/development.log",
		name:    "Development Log",
		markers: []string{"Started GET", "Processing by", "Completed"},
		sev:     severity.High,
		desc:    "Rails development log is exposed, indicating development environment and potentially containing sensitive data",
	},
	{
		path:    "/tmp/local_secret.txt",
		name:    "Rails Local Secret",
		markers: []string{},
		sev:     severity.High,
		desc:    "Rails local secret file is exposed, containing secret_key_base for development which may indicate dev mode in production",
	},
	{
		path:    "/db/development.sqlite3",
		name:    "SQLite Development DB",
		markers: []string{"SQLite format 3"},
		sev:     severity.Critical,
		desc:    "SQLite development database is exposed, potentially containing full application data including user credentials",
	},
	{
		path:    "/db/production.sqlite3",
		name:    "SQLite Production DB",
		markers: []string{"SQLite format 3"},
		sev:     severity.Critical,
		desc:    "SQLite production database is exposed, containing all production data",
	},
}
