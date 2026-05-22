package sqli_error_based

import "testing"

func TestCheckBodyContainsErrorMsg_SequelizeSQLite(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantDB  string
		wantHit bool
	}{
		{
			name:    "SQLITE_ERROR colon format",
			body:    `{"message":"SQLITE_ERROR: near \"z\": syntax error"}`,
			wantDB:  "SQLite",
			wantHit: true,
		},
		{
			name:    "SequelizeDatabaseError",
			body:    `{"name":"SequelizeDatabaseError","message":"near \"z\": syntax error","sql":"SELECT * FROM Users WHERE email = 'admin'z'' AND password = '123'"}`,
			wantDB:  "SQLite",
			wantHit: true,
		},
		{
			name:    "SQLITE_ERROR bracket format (existing pattern)",
			body:    `[SQLITE_ERROR] near "z": syntax error`,
			wantDB:  "SQLite",
			wantHit: true,
		},
		{
			name:    "SQLAlchemy-wrapped sqlite3 OperationalError (parenthesized, no colon)",
			body:    `sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) unrecognized token: "'admin''" [SQL: SELECT * FROM users WHERE username = 'admin'']`,
			wantDB:  "SQLite",
			wantHit: true,
		},
		{
			name:    "no match",
			body:    `{"status":"ok"}`,
			wantDB:  "",
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbName, _, hit := checkBodyContainsErrorMsg(tt.body)
			if hit != tt.wantHit {
				t.Errorf("hit = %v, want %v", hit, tt.wantHit)
			}
			if hit && dbName != tt.wantDB {
				t.Errorf("dbName = %q, want %q", dbName, tt.wantDB)
			}
		})
	}
}
