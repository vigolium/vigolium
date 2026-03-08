package sqli_error_based

import "regexp"

var (
	errorsRegexp = map[string][]*regexp.Regexp{
		"MySQL": {
			regexp.MustCompile("SQL syntax.*?MySQL"),
			regexp.MustCompile(`Warning.*?\Wmysqli?_`),
			regexp.MustCompile("MySQLSyntaxErrorException"),
			regexp.MustCompile("valid MySQL result"),
			regexp.MustCompile("check the manual that (corresponds to|fits) your MySQL server version"),
			regexp.MustCompile("check the manual that (corresponds to|fits) your MariaDB server version"),
			regexp.MustCompile("check the manual that (corresponds to|fits) your Drizzle server version"),
			regexp.MustCompile("Unknown column '[^ ]+' in 'field list'"),
			regexp.MustCompile(`MySqlClient\.`),
			regexp.MustCompile(`com\.mysql\.jdbc`),
			regexp.MustCompile("Zend_Db_(Adapter|Statement)_Mysqli_Exception"),
			regexp.MustCompile(`Pdo[./_\\]Mysql`),
			regexp.MustCompile("MySqlException"),
			regexp.MustCompile(`SQLSTATE\[\d+\]: Syntax error or access violation`),
			regexp.MustCompile("MemSQL does not support this type of query"),
			regexp.MustCompile("is not supported by MemSQL"),
			regexp.MustCompile("unsupported nested scalar subselect"),
		},
		"PostgreSQL": {
			regexp.MustCompile("PostgreSQL.*?ERROR"),
			regexp.MustCompile(`Warning.*?\Wpg_`),
			regexp.MustCompile("valid PostgreSQL result"),
			regexp.MustCompile(`Npgsql\.`),
			regexp.MustCompile("PG::SyntaxError:"),
			regexp.MustCompile(`org\.postgresql\.util\.PSQLException`),
			regexp.MustCompile(`ERROR:\s\ssyntax error at or near`),
			regexp.MustCompile("ERROR: parser: parse error at or near"),
			regexp.MustCompile("PostgreSQL query failed"),
			regexp.MustCompile(`org\.postgresql\.jdbc`),
			regexp.MustCompile(`Pdo[./_\\]Pgsql`),
			regexp.MustCompile("PSQLException"),
		},
		"Microsoft SQL Server": {
			regexp.MustCompile(`Driver.*? SQL[\-\_\ ]*Server`),
			regexp.MustCompile("OLE DB.*? SQL Server"),
			regexp.MustCompile(`\bSQL Server[^<"]+Driver`),
			regexp.MustCompile(`Warning.*?\W(mssql|sqlsrv)_`),
			regexp.MustCompile(`\bSQL Server[^<"]+[0-9a-fA-F]{8}`),
			regexp.MustCompile(`System\.Data\.SqlClient\.(SqlException|SqlConnection\.OnError)`),
			regexp.MustCompile(`(?s)Exception.*?\bRoadhouse\.Cms\.`),
			regexp.MustCompile("Microsoft SQL Native Client error '[0-9a-fA-F]{8}"),
			regexp.MustCompile(`\[SQL Server\]`),
			regexp.MustCompile("ODBC SQL Server Driver"),
			regexp.MustCompile(`ODBC Driver \d+ for SQL Server`),
			regexp.MustCompile("SQLServer JDBC Driver"),
			regexp.MustCompile(`com\.jnetdirect\.jsql`),
			regexp.MustCompile(`macromedia\.jdbc\.sqlserver`),
			regexp.MustCompile("Zend_Db_(Adapter|Statement)_Sqlsrv_Exception"),
			regexp.MustCompile(`com\.microsoft\.sqlserver\.jdbc`),
			regexp.MustCompile(`Pdo[./_\\](Mssql|SqlSrv)`),
			regexp.MustCompile("SQL(Srv|Server)Exception"),
			regexp.MustCompile("Unclosed quotation mark after the character string"),
		},
		"Microsoft Access": {
			regexp.MustCompile(`Microsoft Access (\d+ )?Driver`),
			regexp.MustCompile("JET Database Engine"),
			regexp.MustCompile("Access Database Engine"),
			regexp.MustCompile("ODBC Microsoft Access"),
			regexp.MustCompile(`Syntax error \(missing operator\) in query expression`),
		},
		"Oracle": {
			regexp.MustCompile(`\bORA-\d{5}`),
			regexp.MustCompile("Oracle error"),
			regexp.MustCompile("Oracle.*?Driver"),
			regexp.MustCompile(`Warning.*?\W(oci|ora)_`),
			regexp.MustCompile("quoted string not properly terminated"),
			regexp.MustCompile("SQL command not properly ended"),
			regexp.MustCompile(`macromedia\.jdbc\.oracle`),
			regexp.MustCompile(`oracle\.jdbc`),
			regexp.MustCompile("Zend_Db_(Adapter|Statement)_Oracle_Exception"),
			regexp.MustCompile(`Pdo[./_\\](Oracle|OCI)`),
			regexp.MustCompile("OracleException"),
		},
		"IBM DB2": {
			regexp.MustCompile("CLI Driver.*?DB2"),
			regexp.MustCompile("DB2 SQL error"),
			regexp.MustCompile(`\bdb2_\w+\(`),
			regexp.MustCompile(`SQLCODE[=:\d, -]+SQLSTATE`),
			regexp.MustCompile(`com\.ibm\.db2\.jcc`),
			regexp.MustCompile("Zend_Db_(Adapter|Statement)_Db2_Exception"),
			regexp.MustCompile(`Pdo[./_\\]Ibm`),
			regexp.MustCompile("DB2Exception"),
			regexp.MustCompile(`ibm_db_dbi\.ProgrammingError`),
		},
		"Informix": {
			regexp.MustCompile(`Warning.*?\Wifx_`),
			regexp.MustCompile("Exception.*?Informix"),
			regexp.MustCompile("Informix ODBC Driver"),
			regexp.MustCompile("ODBC Informix driver"),
			regexp.MustCompile(`com\.informix\.jdbc`),
			regexp.MustCompile(`weblogic\.jdbc\.informix`),
			regexp.MustCompile(`Pdo[./_\\]Informix`),
			regexp.MustCompile("IfxException"),
		},
		"Firebird": {
			regexp.MustCompile("Dynamic SQL Error"),
			regexp.MustCompile(`Warning.*?\Wibase_`),
			regexp.MustCompile(`org\.firebirdsql\.jdbc`),
			regexp.MustCompile(`Pdo[./_\\]Firebird`),
		},
		"SQLite": {
			regexp.MustCompile("SQLite/JDBCDriver"),
			regexp.MustCompile(`SQLite\.Exception`),
			regexp.MustCompile(`(Microsoft|System)\.Data\.SQLite\.SQLiteException`),
			regexp.MustCompile(`Warning.*?\W(sqlite_|SQLite3::)`),
			regexp.MustCompile(`\[SQLITE_ERROR\]`),
			regexp.MustCompile(`SQLite error \d+:`),
			regexp.MustCompile("sqlite3.OperationalError:"),
			regexp.MustCompile("SQLite3::SQLException"),
			regexp.MustCompile(`org\.sqlite\.JDBC`),
			regexp.MustCompile(`Pdo[./_\\]Sqlite`),
			regexp.MustCompile("SQLiteException"),
		},
		"SAP MaxDB": {
			regexp.MustCompile("SQL error.*?POS([0-9]+)"),
			regexp.MustCompile(`Warning.*?\Wmaxdb_`),
			regexp.MustCompile("DriverSapDB"),
			regexp.MustCompile("-3014.*?Invalid end of SQL statement"),
			regexp.MustCompile(`com\.sap\.dbtech\.jdbc`),
			regexp.MustCompile(`\[-3008\].*?: Invalid keyword or missing delimiter`),
		},
		"Sybase": {
			regexp.MustCompile(`Warning.*?\Wsybase_`),
			regexp.MustCompile("Sybase message"),
			regexp.MustCompile("Sybase.*?Server message"),
			regexp.MustCompile("SybSQLException"),
			regexp.MustCompile(`Sybase\.Data\.AseClient`),
			regexp.MustCompile(`com\.sybase\.jdbc`),
		},
		"Ingres": {
			regexp.MustCompile(`Warning.*?\Wingres_`),
			regexp.MustCompile("Ingres SQLSTATE"),
			regexp.MustCompile(`Ingres\W.*?Driver`),
			regexp.MustCompile(`com\.ingres\.gcf\.jdbc`),
		},
		"FrontBase": {
			regexp.MustCompile(`Exception (condition )?\d+\. Transaction rollback`),
			regexp.MustCompile(`com\.frontbase\.jdbc`),
			regexp.MustCompile("Syntax error 1. Missing"),
			regexp.MustCompile(`(Semantic|Syntax) error [1-4]\d{2}\.`),
		},
		"HSQLDB": {
			regexp.MustCompile(`Unexpected end of command in statement \[`),
			regexp.MustCompile(`Unexpected token.*?in statement \[`),
			regexp.MustCompile(`org\.hsqldb\.jdbc`),
		},
		"H2": {
			regexp.MustCompile(`org\.h2\.jdbc`),
			regexp.MustCompile(`\[42000-192\]`),
		},
		"MonetDB": {
			regexp.MustCompile(`![0-9]{5}![^\n]+(failed|unexpected|error|syntax|expected|violation|exception)`),
			regexp.MustCompile(`\[MonetDB\]\[ODBC Driver`),
			regexp.MustCompile(`nl\.cwi\.monetdb\.jdbc`),
		},
		"Apache Derby": {
			regexp.MustCompile("Syntax error: Encountered"),
			regexp.MustCompile(`org\.apache\.derby`),
			regexp.MustCompile("ERROR 42X01"),
		},
		"Vertica": {
			regexp.MustCompile(", Sqlstate: (3F|42).{3}, (Routine|Hint|Position):"),
			regexp.MustCompile("/vertica/Parser/scan"),
			regexp.MustCompile(`com\.vertica\.jdbc`),
			regexp.MustCompile(`org\.jkiss\.dbeaver\.ext\.vertica`),
			regexp.MustCompile(`com\.vertica\.dsi\.dataengine`),
		},
		"Mckoi": {
			regexp.MustCompile(`com\.mckoi\.JDBCDriver`),
			regexp.MustCompile(`com\.mckoi\.database\.jdbc`),
			regexp.MustCompile("<REGEX_LITERAL>"),
		},
		"Presto": {
			regexp.MustCompile(`com\.facebook\.presto\.jdbc`),
			regexp.MustCompile(`io\.prestosql\.jdbc`),
			regexp.MustCompile(`com\.simba\.presto\.jdbc`),
			regexp.MustCompile(`UNION query has different number of fields: \d+, \d+`),
		},
		"Altibase": {
			regexp.MustCompile(`com\.mimer\.jdbc`),
			regexp.MustCompile(`Syntax error,[^\n]+assumed to mean`),
		},
		"CrateDB": {
			regexp.MustCompile(`io\.crate\.client\.jdbc`),
		},
		"Cache": {
			regexp.MustCompile("encountered after end of query"),
			regexp.MustCompile("A comparison operator is required here"),
		},
		"Raima Database Manager": {
			regexp.MustCompile("-10048: Syntax error"),
			regexp.MustCompile(`rdmStmtPrepare\(.+?\) returned`),
		},
		"Virtuoso": {
			regexp.MustCompile(`SQ074: Line \d+:`),
			regexp.MustCompile("SR185: Undefined procedure"),
			regexp.MustCompile("SQ200: No table"),
			regexp.MustCompile("Virtuoso S0002 Error"),
			regexp.MustCompile(`\[(Virtuoso Driver|Virtuoso iODBC Driver)\]\[Virtuoso Server\]`),
		},
		"CockroachDB": {
			regexp.MustCompile(`(?i)(?:node is not ready|CockroachDB|crdb_internal)`),
		},
		"YugabyteDB": {
			regexp.MustCompile(`(?i)(?:com\.yugabyte|YBClient|yb_catalog)`),
		},
		"ClickHouse": {
			regexp.MustCompile(`(?i)(?:Code: \d+\. DB::Exception|clickhouse-server)`),
		},
		"TiDB": {
			regexp.MustCompile(`(?i)(?:TiDB server|tidb_version|TiKV)`),
		},
	}
)

func checkBodyContainsErrorMsg(body string) (string, *regexp.Regexp, bool) {
	for name, rgExpList := range errorsRegexp {
		for _, regExp := range rgExpList {
			matched := regExp.MatchString(body)
			if matched {
				return name, regExp, true
			}
		}
	}
	return "", nil, false
}
