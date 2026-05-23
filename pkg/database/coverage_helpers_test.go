package database

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// insertRecordP saves one HTTP record under an explicit project and returns its UUID.
func insertRecordP(t *testing.T, repo *Repository, projectUUID, method, host, path string, status int) string {
	t.Helper()
	ctx := context.Background()
	raw := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n\r\n", method, path, host)
	rr, err := httpmsg.ParseRawRequest(raw)
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}
	resp := httpmsg.NewHttpResponse([]byte(fmt.Sprintf("HTTP/1.1 %d X\r\nContent-Type: text/html\r\n\r\nbody body body", status)))
	rr = rr.WithResponse(resp)
	u, err := repo.SaveRecord(ctx, rr, "test", projectUUID)
	if err != nil {
		t.Fatalf("SaveRecord: %v", err)
	}
	return u
}

// saveFindingP saves a unique finding under an explicit project.
func saveFindingP(t *testing.T, repo *Repository, projectUUID, moduleID, sev string) {
	t.Helper()
	ctx := context.Background()
	f := &Finding{
		ProjectUUID: projectUUID,
		ModuleID:    moduleID,
		ModuleName:  moduleID,
		Severity:    sev,
		Confidence:  "firm",
		FindingHash: uuid.New().String(),
		Status:      StatusTriaged,
	}
	if err := repo.SaveFindingDirect(ctx, f); err != nil {
		t.Fatalf("SaveFindingDirect: %v", err)
	}
}
