package database

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestSchemaListTablesAndColumns(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	tables, err := ListTables(ctx, db)
	if err != nil {
		t.Fatalf("ListTables: %v", err)
	}
	if len(tables) == 0 {
		t.Fatal("ListTables returned no tables")
	}
	found := false
	for _, tbl := range tables {
		if tbl == "http_records" {
			found = true
		}
	}
	if !found {
		t.Errorf("http_records not in ListTables: %v", tables)
	}

	cols, err := ListColumns(ctx, db, "http_records")
	if err != nil {
		t.Fatalf("ListColumns: %v", err)
	}
	if !isValidColumn("uuid", cols) {
		t.Error("uuid column not found in http_records")
	}
	if isValidColumn("nonexistent_col", cols) {
		t.Error("isValidColumn returned true for missing column")
	}

	withCounts, err := ListTablesWithCounts(ctx, db)
	if err != nil {
		t.Fatalf("ListTablesWithCounts: %v", err)
	}
	if len(withCounts) != len(tables) {
		t.Errorf("ListTablesWithCounts = %d, want %d", len(withCounts), len(tables))
	}

	// ValidateTableName.
	if err := ValidateTableName(ctx, db, "http_records"); err != nil {
		t.Errorf("ValidateTableName(http_records): %v", err)
	}
	if err := ValidateTableName(ctx, db, "no_such_table"); !errors.Is(err, ErrTableNotFound) {
		t.Errorf("ValidateTableName(missing) = %v, want ErrTableNotFound", err)
	}
}

func TestSchemaDetectPrimaryKey(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	pk, err := DetectPrimaryKey(ctx, db, "http_records")
	if err != nil {
		t.Fatalf("DetectPrimaryKey: %v", err)
	}
	if len(pk.Columns) != 1 || pk.Columns[0] != "uuid" {
		t.Errorf("http_records PK = %v, want [uuid]", pk.Columns)
	}

	// Findings PK is the autoincrement id.
	pk, err = DetectPrimaryKey(ctx, db, "findings")
	if err != nil {
		t.Fatalf("DetectPrimaryKey(findings): %v", err)
	}
	if len(pk.Columns) != 1 || pk.Columns[0] != "id" {
		t.Errorf("findings PK = %v, want [id]", pk.Columns)
	}
}

func TestGenericRecordCRUD(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	recUUID := insertRecordP(t, repo, DefaultProjectUUID, "GET", "generic.example.com", "/x", 200)

	// QueryGenericTable.
	rows, cols, total, err := QueryGenericTable(ctx, db, "http_records", 100, 0)
	if err != nil {
		t.Fatalf("QueryGenericTable: %v", err)
	}
	if total != 1 || len(rows) != 1 || len(cols) == 0 {
		t.Errorf("QueryGenericTable total=%d rows=%d cols=%d", total, len(rows), len(cols))
	}

	// GetGenericRecord by PK.
	rec, err := GetGenericRecord(ctx, db, "http_records", recUUID)
	if err != nil {
		t.Fatalf("GetGenericRecord: %v", err)
	}
	if rec["uuid"] != recUUID {
		t.Errorf("GetGenericRecord uuid = %v, want %s", rec["uuid"], recUUID)
	}
	// Missing PK → ErrNoRows.
	if _, err := GetGenericRecord(ctx, db, "http_records", "no-such-uuid"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("GetGenericRecord(missing) = %v", err)
	}

	// InsertGenericRecord (into a simple table — scopes).
	newID := uuid.NewString()
	if err := InsertGenericRecord(ctx, db, "scopes", map[string]interface{}{
		"project_uuid": DefaultProjectUUID,
		"name":         "gen-" + newID,
		"rule_type":    "include",
	}); err != nil {
		t.Fatalf("InsertGenericRecord: %v", err)
	}
	// Invalid column rejected.
	if err := InsertGenericRecord(ctx, db, "scopes", map[string]interface{}{"bogus_col": 1}); !errors.Is(err, ErrInvalidColumn) {
		t.Errorf("InsertGenericRecord(bad col) = %v, want ErrInvalidColumn", err)
	}
	// Empty fields rejected.
	if err := InsertGenericRecord(ctx, db, "scopes", map[string]interface{}{}); !errors.Is(err, ErrNoValidFields) {
		t.Errorf("InsertGenericRecord(empty) = %v, want ErrNoValidFields", err)
	}

	// UpdateGenericRecord on http_records.
	if err := UpdateGenericRecord(ctx, db, "http_records", recUUID, map[string]interface{}{
		"risk_score": 99,
	}); err != nil {
		t.Fatalf("UpdateGenericRecord: %v", err)
	}
	updated, _ := repo.GetRecordByUUID(ctx, recUUID)
	if updated.RiskScore != 99 {
		t.Errorf("UpdateGenericRecord did not apply: risk=%d", updated.RiskScore)
	}
	// Updating the PK column is rejected.
	if err := UpdateGenericRecord(ctx, db, "http_records", recUUID, map[string]interface{}{
		"uuid": "new-uuid",
	}); !errors.Is(err, ErrImmutablePrimaryKey) {
		t.Errorf("UpdateGenericRecord(pk) = %v, want ErrImmutablePrimaryKey", err)
	}
	// Updating a missing row → ErrNoRows.
	if err := UpdateGenericRecord(ctx, db, "http_records", "no-such", map[string]interface{}{
		"risk_score": 1,
	}); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("UpdateGenericRecord(missing) = %v", err)
	}

	// DeleteGenericRecord.
	if err := DeleteGenericRecord(ctx, db, "http_records", recUUID); err != nil {
		t.Fatalf("DeleteGenericRecord: %v", err)
	}
	if err := DeleteGenericRecord(ctx, db, "http_records", recUUID); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("DeleteGenericRecord(missing) = %v", err)
	}

	// Unknown table is rejected across the API.
	if _, err := GetGenericRecord(ctx, db, "no_table", "x"); !errors.Is(err, ErrTableNotFound) {
		t.Errorf("GetGenericRecord(no table) = %v", err)
	}
}

func TestQueryGenericTableFiltered(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	insertRecordP(t, repo, DefaultProjectUUID, "GET", "filt.example.com", "/a", 200)
	insertRecordP(t, repo, DefaultProjectUUID, "POST", "filt.example.com", "/b", 404)

	// Filter status_code = 404 via eq operator.
	rows, _, total, err := QueryGenericTableFiltered(ctx, db, "http_records", GenericQueryOptions{
		Filters: []GenericFilter{{Column: "status_code", Operator: "eq", Value: "404"}},
		SortBy:  "created_at",
		SortAsc: true,
		Limit:   10,
	})
	if err != nil {
		t.Fatalf("QueryGenericTableFiltered: %v", err)
	}
	if total != 1 || len(rows) != 1 {
		t.Errorf("filtered total=%d rows=%d, want 1/1", total, len(rows))
	}

	// gt operator.
	_, _, total, err = QueryGenericTableFiltered(ctx, db, "http_records", GenericQueryOptions{
		Filters: []GenericFilter{{Column: "status_code", Operator: "gt", Value: "300"}},
	})
	if err != nil {
		t.Fatalf("QueryGenericTableFiltered(gt): %v", err)
	}
	if total != 1 {
		t.Errorf("gt filter total = %d, want 1", total)
	}

	// Invalid filter column errors.
	if _, _, _, err := QueryGenericTableFiltered(ctx, db, "http_records", GenericQueryOptions{
		Filters: []GenericFilter{{Column: "bogus", Operator: "eq", Value: "x"}},
	}); err == nil {
		t.Error("QueryGenericTableFiltered(bad col) should error")
	}

	// Search term across text columns.
	_, _, total, err = QueryGenericTableFiltered(ctx, db, "http_records", GenericQueryOptions{
		SearchTerm: "filt.example.com",
	})
	if err != nil {
		t.Fatalf("QueryGenericTableFiltered(search): %v", err)
	}
	if total != 2 {
		t.Errorf("search total = %d, want 2", total)
	}
}
