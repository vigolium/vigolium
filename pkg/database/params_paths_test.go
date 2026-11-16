package database

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func jsonPost(t *testing.T, path, body string) *httpmsg.HttpRequestResponse {
	t.Helper()
	raw := "POST " + path + " HTTP/1.1\r\nHost: api.test\r\nContent-Type: application/json\r\n\r\n" + body
	rr, err := httpmsg.ParseRawRequestWithURL(raw, "https://api.test"+path)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func pathView(res ParamPathResult, method, key string) (ParamPathView, bool) {
	for _, p := range res.Paths {
		if p.Method == method && p.KeyPath == key {
			return p, true
		}
	}
	return ParamPathView{}, false
}

// A JSON body parameter is stored with its key path and JSON type.
func TestEnrichStoresJSONKeyPaths(t *testing.T) {
	rec := &HTTPRecord{}
	if err := rec.FromHttpRequestResponse(jsonPost(t, "/api/users/1", `{"user":{"name":"alice","age":31},"tags":["x"]}`)); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range rec.Parameters {
		if p.Type == "json" {
			got[p.Metadata] = p.JSONType
		}
	}
	want := map[string]string{"user.name": "string", "user.age": "number", "tags": "string"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("path %q: type %q, want %q (stored %v)", k, got[k], v, got)
		}
	}
}

// params --paths: per operation, the union of key paths with types and sample
// counts, values never emitted.
func TestParamPathsUnionPerOperation(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	for i, body := range []string{
		`{"user":{"name":"alice-secret","age":31},"items":[{"id":1},{"id":2}]}`,
		`{"user":{"name":"bob-secret","age":null}}`,
	} {
		if _, err := repo.SaveRecord(ctx, jsonPost(t, "/api/users/"+string(rune('1'+i)), body), RecordSourceIngestCLI, "p"); err != nil {
			t.Fatal(err)
		}
	}
	// A form body for the same template contributes nothing.
	form, _ := httpmsg.ParseRawRequestWithURL("POST /api/users/3 HTTP/1.1\r\nHost: api.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=1", "https://api.test/api/users/3")
	if _, err := repo.SaveRecord(ctx, form, RecordSourceIngestCLI, "p"); err != nil {
		t.Fatal(err)
	}

	res, err := NewQueryBuilder(db, QueryFilters{ProjectUUID: "p"}).ParamPaths(ctx, ParamPathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	name, ok := pathView(res, "POST", "user.name")
	if !ok || name.Template != "/api/users/{int}" || name.JSONType != "string" || name.SampleCount != 2 || name.OperationRecords != 2 {
		t.Errorf("user.name: %+v (found %v)", name, ok)
	}
	age, _ := pathView(res, "POST", "user.age")
	if age.JSONTypes["number"] != 1 || age.JSONTypes["null"] != 1 || age.SampleCount != 2 {
		t.Errorf("user.age types %v, samples %d", age.JSONTypes, age.SampleCount)
	}
	// Two array elements in one record count as one sample.
	id, _ := pathView(res, "POST", "items.id")
	if id.SampleCount != 1 || id.JSONTypes["number"] != 2 || id.OperationRecords != 2 {
		t.Errorf("items.id: %+v", id)
	}
	if res.Total != 3 {
		t.Errorf("total %d, want 3 paths: %+v", res.Total, res.Paths)
	}
	out, _ := json.Marshal(res.Paths)
	for _, v := range []string{"alice-secret", "bob-secret", "31"} {
		if strings.Contains(string(out), v) {
			t.Errorf("a value (%s) reached the body-shape view: %s", v, out)
		}
	}
	// --min-occurrences maps to MinSamples.
	res, _ = NewQueryBuilder(db, QueryFilters{ProjectUUID: "p"}).ParamPaths(ctx, ParamPathOptions{MinSamples: 2})
	if _, ok := pathView(res, "POST", "items.id"); ok || res.Total != 2 {
		t.Errorf("MinSamples 2 kept %+v", res.Paths)
	}
}

// Rows stored before key paths were recorded are counted, then given paths by
// the one-time backfill.
func TestParamPathsBackfill(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	uuid, err := repo.SaveRecord(ctx, jsonPost(t, "/api/orders", `{"order":{"qty":2}}`), RecordSourceIngestCLI, "p")
	if err != nil {
		t.Fatal(err)
	}
	// As an older binary stored it: leaf name only, plus a param-mined key.
	legacy := &HTTPRecord{Parameters: []EmbeddedParam{
		{Name: "qty", Value: "2", Type: "json"},
		{Name: "debug", Type: "url", Hidden: true},
	}}
	if _, err := db.NewUpdate().Model(legacy).Column("parameters").Where("uuid = ?", uuid).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	qb := NewQueryBuilder(db, QueryFilters{ProjectUUID: "p"})
	res, _ := qb.ParamPaths(ctx, ParamPathOptions{})
	if res.Total != 0 || res.RecordsWithoutPaths != 1 {
		t.Fatalf("before backfill: %d paths, %d without paths", res.Total, res.RecordsWithoutPaths)
	}
	if n, err := db.backfillJSONParamPaths(ctx); err != nil || n != 1 {
		t.Fatalf("backfill updated %d, %v", n, err)
	}
	res, _ = qb.ParamPaths(ctx, ParamPathOptions{})
	if v, ok := pathView(res, "POST", "order.qty"); !ok || v.JSONType != "number" || res.RecordsWithoutPaths != 0 {
		t.Errorf("after backfill: %+v", res)
	}
	rec, _ := repo.GetRecordByUUID(ctx, uuid)
	hidden := false
	for _, p := range rec.Parameters {
		hidden = hidden || (p.Name == "debug" && p.Hidden)
	}
	if !hidden {
		t.Error("the backfill dropped a param-mined parameter")
	}
	if n, _ := db.backfillJSONParamPaths(ctx); n != 0 {
		t.Errorf("second backfill updated %d rows", n)
	}
}
