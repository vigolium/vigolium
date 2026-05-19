package backup_file_discovery

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// staticStems are common backup filename bases that don't depend on the hostname.
var staticStems = []string{
	"www", "upload", "sql", "dump", "update", "test", "tmp",
	"backup", "db", "database", "site", "web", "admin",
	"data", "files", "htdocs", "html", "old", "archive",
}

// backupExtensions are common backup/archive file extensions.
var backupExtensions = []string{
	".zip", ".tar.gz", ".tar.bz2", ".gz", ".rar", ".7z", ".tgz",
	".bak", ".backup", ".old",
	".sql", ".sql.gz", ".sql.zip",
	".db", ".sqlite", ".dump", ".dump.sql",
}

// pathPatterns are format strings for generating URL paths from stems and extensions.
// %s is the stem, applied via fmt.Sprintf.
var pathPatterns = []string{
	"/%s%s",        // /example.zip
	"/%s-backup%s", // /example-backup.zip
	"/backup-%s%s", // /backup-example.zip
}

// generateStems produces filename stems from the hostname.
// For "sub.example.com" it produces: example, sub, sub.example,
// sub-example, sub-example-com, example2025, example2026, example-2025, etc.
func generateStems(hostname string) []string {
	seen := make(map[string]struct{})
	var stems []string

	add := func(s string) {
		s = strings.ToLower(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		stems = append(stems, s)
	}

	// Strip port if present
	host := hostname
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		// Only strip if it looks like a port (not IPv6)
		if !strings.Contains(host, "[") {
			host = host[:idx]
		}
	}

	// Parse domain parts using public suffix list
	eTLD1, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		// Fallback: treat whole hostname as the domain
		eTLD1 = host
	}

	suffix, _ := publicsuffix.PublicSuffix(host)
	sld := strings.TrimSuffix(eTLD1, "."+suffix) // e.g., "example"

	// Subdomain part
	subdomain := ""
	if len(host) > len(eTLD1) {
		subdomain = strings.TrimSuffix(host[:len(host)-len(eTLD1)-1], ".")
	}

	// 1. SLD (e.g., "example")
	add(sld)

	// 2. Subdomain parts (e.g., "sub", "api")
	if subdomain != "" {
		for _, part := range strings.Split(subdomain, ".") {
			add(part)
		}
	}

	// 3. Subdomain + SLD combos
	if subdomain != "" {
		// sub.example → sub-example
		add(strings.ReplaceAll(subdomain+"."+sld, ".", "-"))
		// sub.example → sub.example (dotted)
		add(subdomain + "." + sld)
	}

	// 4. Full hostname with dots replaced by hyphens: sub-example-com
	add(strings.ReplaceAll(host, ".", "-"))

	// 5. Full hostname as-is: sub.example.com
	add(host)

	// 6. Year variants for SLD
	now := time.Now()
	currentYear := now.Year()
	for _, y := range []int{currentYear - 1, currentYear} {
		ys := fmt.Sprintf("%d", y)
		add(sld + ys)                      // example2025
		add(sld + "-" + ys)                // example-2025
		add(fmt.Sprintf("%s_%s", sld, ys)) // example_2025
		if subdomain != "" {
			combo := strings.ReplaceAll(subdomain+"."+sld, ".", "-")
			add(combo + "-" + ys) // sub-example-2025
		}
	}

	// 7. Static common stems
	for _, s := range staticStems {
		add(s)
	}

	return stems
}

// generatePaths produces all candidate backup file paths for a given hostname.
func generatePaths(hostname string) []string {
	stems := generateStems(hostname)

	seen := make(map[string]struct{})
	var paths []string

	for _, stem := range stems {
		for _, ext := range backupExtensions {
			for _, pattern := range pathPatterns {
				p := fmt.Sprintf(pattern, stem, ext)
				if _, ok := seen[p]; ok {
					continue
				}
				seen[p] = struct{}{}
				paths = append(paths, p)
			}
		}
	}

	return paths
}
