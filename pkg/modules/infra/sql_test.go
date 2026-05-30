package infra

import "testing"

func TestNormalizeDBMS(t *testing.T) {
	cases := map[string]string{
		"MySQL":                "mysql",
		"MariaDB":              "mysql",
		"TiDB":                 "mysql",
		"PostgreSQL":           "postgres",
		"CockroachDB":          "postgres",
		"Microsoft SQL Server": "mssql",
		"Oracle":               "oracle",
		"SQLite":               "sqlite",
		"IBM DB2":              "",
		"":                     "",
	}
	for in, want := range cases {
		if got := NormalizeDBMS(in); got != want {
			t.Errorf("NormalizeDBMS(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsNumericValue(t *testing.T) {
	cases := map[string]bool{
		"123": true, "-42": true, "3.14": true,
		"": false, "abc": false, "12abc": false, "john@example.com": false,
	}
	for in, want := range cases {
		if got := IsNumericValue(in); got != want {
			t.Errorf("IsNumericValue(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestDBMSTechTag(t *testing.T) {
	if got := DBMSTechTag("mysql"); got != "dbms:mysql" {
		t.Errorf("DBMSTechTag = %q", got)
	}
}

func TestSQLWAFMutators(t *testing.T) {
	muts := SQLWAFMutators("generic")
	if len(muts) == 0 {
		t.Fatal("expected at least one mutator")
	}
	in := "' UNION SELECT NULL,NULL-- -"
	// space→comment must remove raw spaces; case-flip must change AND/OR/UNION casing.
	if got := muts[0](in); got == in || containsRaw(got, " ") {
		t.Errorf("space-to-comment mutator did not remove spaces: %q", got)
	}
	if got := muts[1]("AND OR UNION SELECT"); got == "AND OR UNION SELECT" {
		t.Errorf("case-flip mutator did not change keyword casing: %q", got)
	}
}

func containsRaw(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
