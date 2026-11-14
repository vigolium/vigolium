package database

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// Candidate selection caps rows per origin, not globally, so a large
// high-risk host cannot crowd every other host out.
func TestParamMiningCandidatesPerHost(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	const scanID = "pm-per-host"
	if err := repo.CreateScan(ctx, &Scan{UUID: scanID, ProjectUUID: DefaultProjectUUID, Status: "running", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	save := func(host string, i int) {
		rr, err := httpmsg.GetRawRequestFromURL(fmt.Sprintf("https://%s/p%d?x=1", host, i))
		if err != nil {
			t.Fatal(err)
		}
		resp := httpmsg.NewHttpResponse(httpmsg.BuildRawResponse(200, map[string]string{"Content-Type": "text/html"}, "<html>ok</html>"))
		if _, err := repo.SaveRecord(ctx, rr.WithResponse(resp), "discovery", DefaultProjectUUID); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 10; i++ {
		save("big.test", i)
	}
	for i := 0; i < 2; i++ {
		save("small.test", i)
	}
	if _, err := db.NewUpdate().Model((*HTTPRecord)(nil)).Set("risk_score = 90").Where("hostname = ?", "big.test").Exec(ctx); err != nil {
		t.Fatal(err)
	}

	rows, err := repo.ParamMiningCandidates(ctx, scanID, nil, 3)
	if err != nil {
		t.Fatal(err)
	}
	per := map[string]int{}
	for _, row := range rows {
		per[row.Hostname]++
	}
	if per["big.test"] != 3 || per["small.test"] != 2 {
		t.Fatalf("rows per host = %v, want big.test 3, small.test 2", per)
	}
	if rows[0].Hostname != "big.test" {
		t.Errorf("risk order lost: first row %s", rows[0].Hostname)
	}
}
