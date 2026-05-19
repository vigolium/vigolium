package error_message_detect

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// errorCategory groups related error patterns under a common label.
type errorCategory struct {
	name       string
	severity   severity.Severity
	confidence severity.Confidence
	patterns   []*regexp.Regexp
}

var categories = []errorCategory{
	{
		name:       "Debug Page",
		severity:   severity.Low,
		confidence: severity.Certain,
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(Application-Trace|Routing Error|DEBUG"? ?[=:] ?True|Caused by:|stack trace:|Microsoft \.NET Framework|Traceback|[0-9]:in ` + "`" + `|#!/us|WebApplicationException|java\.lang\.|phpinfo|swaggerUi|on line [0-9]|SQLSTATE)`),
			regexp.MustCompile(`mod_[\w]+:`),
		},
	},
	{
		name:       "Apache Error",
		severity:   severity.Info,
		confidence: severity.Firm,
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`AH[0-9]{5}`),
			regexp.MustCompile(`mod_[\w]+:`),
		},
	},
	{
		name:       "ASP Error",
		severity:   severity.Info,
		confidence: severity.Firm,
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`([A-Za-z]{1,32}\.)+[A-Za-z]{0,32}\(([A-Za-z0-9]+\s+[A-Za-z0-9]+[,\s]*)*\)\s+\+{1}\d+`),
			regexp.MustCompile(`Message":"Invalid web service call`),
			regexp.MustCompile(`Exception of type`),
			regexp.MustCompile(`Server Error in '`),
			regexp.MustCompile(`Server Error in Application`),
			regexp.MustCompile(`--- End of inner exception stack trace ---`),
			regexp.MustCompile(`Microsoft OLE DB Provider`),
			regexp.MustCompile(`Error ([\d-]+) \([\dA-Fa-f]+\)`),
			regexp.MustCompile(`in [A-Za-z]:\\([A-Za-z0-9_]+\\)+[A-Za-z0-9_\-]+(\.aspx)?\.cs:line [\d]+`),
			regexp.MustCompile(`[A-Za-z\.]+\(([A-Za-z0-9, ]+)?\) \+[0-9]+`),
			regexp.MustCompile(`Syntax error in string in query expression`),
		},
	},
	{
		name:       "Java Error",
		severity:   severity.Info,
		confidence: severity.Firm,
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`\.java:[0-9]+`),
			regexp.MustCompile(`\.java\((Inlined )?Compiled Code\)`),
			regexp.MustCompile(`\.invoke\(Unknown Source\)`),
			regexp.MustCompile(`nested exception`),
			regexp.MustCompile(`java\.lang\.([A-Za-z0-9_]*)Exception`),
			regexp.MustCompile(`java\.io\.FileNotFoundException:`),
			regexp.MustCompile(`\bORA-[0-9]{5}`),
			regexp.MustCompile(`Oracle.*Driver\]`),
			regexp.MustCompile(`quoted string not properly terminated`),
			regexp.MustCompile(`(?i)Warning.*\Woci_.*`),
			regexp.MustCompile(`(?i)Warning.*\Wora_.*`),
			regexp.MustCompile(`Warning: oci_parse\(\)`),
			regexp.MustCompile(`JBWEB[0-9]{6}:`),
		},
	},
	{
		name:       "Generic Error",
		severity:   severity.Info,
		confidence: severity.Firm,
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`NameError:`),
			regexp.MustCompile(`ImportError:`),
			regexp.MustCompile(`IndentationError:`),
			regexp.MustCompile(`Traceback \(most recent call last\):`),
			regexp.MustCompile(`File "[A-Za-z0-9\-_\./]*", line [0-9]+`),
			regexp.MustCompile(`Fatal error:`),
			regexp.MustCompile(`\.php on line [0-9]+`),
			regexp.MustCompile(`\.php</b> on line <b>[0-9]+`),
			regexp.MustCompile(`at (/[A-Za-z0-9\.]+)*\.pm line [0-9]+`),
			regexp.MustCompile(`\.groovy:[0-9]+`),
			regexp.MustCompile(`\.rb:[0-9]+:in`),
			regexp.MustCompile(`\.scala:[0-9]+`),
			regexp.MustCompile(`client intended to address`),
			regexp.MustCompile(`could not build optimal proxy_headers_hash`),
			regexp.MustCompile(`UnhandledPromiseRejectionWarning:`),
			regexp.MustCompile(`TypeError:`),
			regexp.MustCompile(`runtime error:.*invalid`),
			regexp.MustCompile(`ReferenceError:`),
		},
	},
	{
		name:       "SQL Error",
		severity:   severity.Low,
		confidence: severity.Firm,
		patterns: []*regexp.Regexp{
			// MySQL
			regexp.MustCompile(`You have an error in your SQL syntax`),
			regexp.MustCompile(`Error: Unknown column`),
			regexp.MustCompile(`MySqlClient\.`),
			regexp.MustCompile(`com\.mysql\.jdbc\.exceptions`),
			regexp.MustCompile(`Illegal mix of collations \([\w\s,]+\) and \([\w\s,]+\) for operation`),
			regexp.MustCompile(`valid MySQL result`),
			regexp.MustCompile(`(?i)warning mysql_`),
			// DB2
			regexp.MustCompile(`CLI Driver.*DB2`),
			regexp.MustCompile(`\bdb2_\w+\(`),
			regexp.MustCompile(`DB2 SQL error`),
			// MSSQL
			regexp.MustCompile(`\[(ODBC SQL Server Driver|SQL Server|ODBC Driver Manager)\]`),
			regexp.MustCompile(`Unclosed quotation mark`),
			regexp.MustCompile(`(?i)warning.*mssql_.*`),
			regexp.MustCompile(`Driver.* SQL[-_]*Server`),
			regexp.MustCompile(`(\W|\A)SQL Server.*Driver`),
			regexp.MustCompile(`Conversion failed when converting the`),
			regexp.MustCompile(`Cannot initialize the data source object of OLE DB provider`),
			// MongoDB
			regexp.MustCompile(`QUERY\s+\[thread1\] SyntaxError:`),
			regexp.MustCompile(`uncaught exception:`),
			// PostgreSQL
			regexp.MustCompile(`PostgreSQL.*ERROR`),
			regexp.MustCompile(`(?i)Warning.*\Wpg_.*`),
			regexp.MustCompile(`(?i)valid PostgreSQL result`),
			regexp.MustCompile(`Npgsql\.`),
			regexp.MustCompile(`org\.postgresql\.util\.PSQLException`),
			// SQLite
			regexp.MustCompile(`SQLite/JDBCDriver`),
			regexp.MustCompile(`SQLite\.Exception`),
			regexp.MustCompile(`System\.Data\.SQLite\.SQLiteException`),
			regexp.MustCompile(`(?i)Warning.*sqlite_.*`),
			regexp.MustCompile(`(?i)Warning.*SQLite3::`),
			regexp.MustCompile(`\[SQLITE_ERROR\]`),
			// HSQLDB
			regexp.MustCompile(`org\.hsqldb\.jdbc`),
			// Firebird
			regexp.MustCompile(`Dynamic SQL Error`),
			regexp.MustCompile(`\[function\.ibase\.query\]`),
			// Other
			regexp.MustCompile(`(?i)Warning.*maxdb.*`),
			regexp.MustCompile(`(?i)Warning.*ingre_`),
			regexp.MustCompile(`(?i)Warning.*ibase_.*`),
			regexp.MustCompile(`(?i)Warning.*sybase.*`),
			regexp.MustCompile(`SQL error.*POS([0-9]+).*`),
			regexp.MustCompile(`Ingres SQLSTATE`),
			regexp.MustCompile(`Ingres\W.*Driver`),
			regexp.MustCompile(`DB Error:`),
		},
	},
}

// Module implements the Error Message Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Error Message Detect module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("passive_error_message_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes response body for error messages.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	if ctx.Response() == nil {
		return nil, nil
	}

	// Skip binary content
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if strings.Contains(ct, "image/") || strings.Contains(ct, "audio/") ||
		strings.Contains(ct, "video/") || strings.Contains(ct, "octet-stream") {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if body == "" {
		return nil, nil
	}

	// Dedup by host+path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	var results []*output.ResultEvent

	for _, cat := range categories {
		var matches []string
		for _, pat := range cat.patterns {
			if match := pat.FindString(body); match != "" {
				matches = append(matches, truncate(match, 120))
			}
		}

		if len(matches) == 0 {
			continue
		}

		extracted := []string{
			fmt.Sprintf("Category: %s", cat.name),
		}
		for _, match := range matches {
			extracted = append(extracted, fmt.Sprintf("Matched: %s", match))
		}

		results = append(results, &output.ResultEvent{
			ModuleID:         ModuleID,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(ctx.Request().Raw()),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        fmt.Sprintf("%s in Response", cat.name),
				Description: fmt.Sprintf("Intriguing error response worth checking out at %s", urlx.String()),
				Severity:    cat.severity,
				Confidence:  cat.confidence,
				Tags:        []string{"passive", "error", "interesting", cat.tagName()},
			},
		})
	}

	return results, nil
}

func (c *errorCategory) tagName() string {
	return strings.ToLower(strings.ReplaceAll(c.name, " ", "-"))
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
