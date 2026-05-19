package wp_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

type wpProbe struct {
	path        string
	name        string
	markers     []string // at least one must match
	antiMarkers []string // if any match, skip (FP indicator)
	sev         severity.Severity
	desc        string
}

var wpProbes = []wpProbe{
	// wp-config.php direct access
	{
		path:        "/wp-config.php",
		name:        "wp-config.php Exposed",
		markers:     []string{"DB_NAME", "DB_USER", "AUTH_KEY", "LOGGED_IN_SALT", "DB_PASSWORD"},
		antiMarkers: []string{"<html", "<!DOCTYPE", "<HTML"},
		sev:         severity.Critical,
		desc:        "WordPress configuration file served as plaintext, exposing database credentials and auth salts",
	},
	// wp-config.php backup variants
	{
		path:        "/wp-config.php~",
		name:        "wp-config.php Backup (~)",
		markers:     []string{"DB_NAME", "DB_USER", "AUTH_KEY"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Editor backup of wp-config.php exposed with database credentials",
	},
	{
		path:        "/wp-config.php.old",
		name:        "wp-config.php Backup (.old)",
		markers:     []string{"DB_NAME", "DB_USER", "AUTH_KEY"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Old backup of wp-config.php exposed with database credentials",
	},
	{
		path:        "/wp-config.php.save",
		name:        "wp-config.php Backup (.save)",
		markers:     []string{"DB_NAME", "DB_USER", "AUTH_KEY"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Save file of wp-config.php exposed with database credentials",
	},
	{
		path:        "/wp-config.php.swp",
		name:        "wp-config.php Vim Swap",
		markers:     []string{"DB_NAME", "DB_USER", "AUTH_KEY"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Vim swap file of wp-config.php exposed with database credentials",
	},
	{
		path:        "/wp-config.php.txt",
		name:        "wp-config.php Plaintext Copy",
		markers:     []string{"DB_NAME", "DB_USER", "AUTH_KEY"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Plaintext copy of wp-config.php exposed with database credentials",
	},
	{
		path:        "/wp-config.php.bak",
		name:        "wp-config.php Backup (.bak)",
		markers:     []string{"DB_NAME", "DB_USER", "AUTH_KEY"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Backup copy of wp-config.php exposed with database credentials",
	},
	// Debug log
	{
		path:        "/wp-content/debug.log",
		name:        "WordPress Debug Log",
		markers:     []string{"PHP Warning", "PHP Fatal error", "Stack trace", "wpdb", "PHP Notice"},
		antiMarkers: []string{"<html", "<!DOCTYPE", "Index of"},
		sev:         severity.High,
		desc:        "WordPress debug log exposed, potentially containing stack traces, SQL queries, filesystem paths, and plugin versions",
	},
	// Informational files
	{
		path:    "/readme.html",
		name:    "WordPress Readme",
		markers: []string{"WordPress", "wordpress.org"},
		sev:     severity.Info,
		desc:    "WordPress readme.html exposed, disclosing WordPress version",
	},
	{
		path:    "/license.txt",
		name:    "WordPress License File",
		markers: []string{"WordPress", "GNU General Public License"},
		sev:     severity.Info,
		desc:    "WordPress license.txt exposed, confirming WordPress installation",
	},
	// Installer/repair endpoints
	{
		path:    "/wp-admin/install.php",
		name:    "WordPress Installer",
		markers: []string{"wp-install", "installation", "WordPress"},
		sev:     severity.Critical,
		desc:    "WordPress installer endpoint accessible — site may be in an unfinished installation state",
	},
	{
		path:    "/wp-admin/maint/repair.php",
		name:    "WordPress DB Repair",
		markers: []string{"repair", "Repair Database", "WP_ALLOW_REPAIR"},
		sev:     severity.High,
		desc:    "WordPress database repair endpoint is accessible, indicating WP_ALLOW_REPAIR is enabled",
	},
	// Directory listings
	{
		path:    "/wp-content/uploads/",
		name:    "WordPress Uploads Directory Listing",
		markers: []string{"Index of /wp-content/uploads", "Parent Directory"},
		sev:     severity.Medium,
		desc:    "WordPress uploads directory listing enabled, exposing uploaded files",
	},
	{
		path:    "/wp-content/plugins/",
		name:    "WordPress Plugins Directory Listing",
		markers: []string{"Index of /wp-content/plugins", "Parent Directory"},
		sev:     severity.Medium,
		desc:    "WordPress plugins directory listing enabled, exposing installed plugin slugs",
	},
	{
		path:    "/wp-content/",
		name:    "WordPress Content Directory Listing",
		markers: []string{"Index of /wp-content", "Parent Directory"},
		sev:     severity.Medium,
		desc:    "WordPress content directory listing enabled",
	},
	// Cron
	{
		path:    "/wp-cron.php",
		name:    "WordPress Cron Externally Triggerable",
		markers: []string{}, // 200 with empty body is the expected "success" for wp-cron
		sev:     severity.Low,
		desc:    "WordPress cron endpoint is externally triggerable, which can be abused for DoS or resource exhaustion",
	},
	// Common backup archives
	{
		path:    "/wp.sql",
		name:    "WordPress SQL Dump",
		markers: []string{"CREATE TABLE", "INSERT INTO", "wp_users", "wp_options"},
		sev:     severity.Critical,
		desc:    "WordPress SQL dump exposed, potentially containing full database with user credentials",
	},
	{
		path:    "/dump.sql",
		name:    "SQL Dump (WordPress)",
		markers: []string{"wp_users", "wp_options", "wp_posts"},
		sev:     severity.Critical,
		desc:    "SQL dump with WordPress tables exposed",
	},
}
