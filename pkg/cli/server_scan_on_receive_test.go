package cli

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

type fakeReceiver struct{ closed *atomic.Int64 }

func (f fakeReceiver) Close() { f.closed.Add(1) }

// TestProjectReceivers_OnePerProject: scan-on-receive starts one receiver per
// project once it holds ingested traffic, never two for the same project, and
// stops them all on shutdown.
func TestProjectReceivers_OnePerProject(t *testing.T) {
	repo := newC2bTestRepo(t)
	ctx := context.Background()
	require.NoError(t, repo.CreateProject(ctx, &database.Project{UUID: "proj-a", Name: "a", OwnerUUID: database.DefaultUserUUID}))
	require.NoError(t, repo.CreateProject(ctx, &database.Project{UUID: "proj-b", Name: "b", OwnerUUID: database.DefaultUserUUID}))

	var closed atomic.Int64
	started := map[string]int{}
	p := newProjectReceivers(func(project string) (receiver, error) {
		started[project]++
		return fakeReceiver{&closed}, nil
	})
	ingest := func(project, path, source string) {
		rr, err := httpmsg.GetRawRequestFromURL("http://app.test" + path)
		require.NoError(t, err)
		_, err = repo.SaveRecord(ctx, rr, source, project)
		require.NoError(t, err)
	}
	p.add(database.DefaultProjectUUID, fakeReceiver{&closed})
	ingest("proj-a", "/a", database.RecordSourceIngestServer)
	ingest("proj-b", "/b", database.RecordSourceScanner) // not ingested traffic
	p.sync(ctx, repo)
	require.Equal(t, 1, started["proj-a"])
	require.Zero(t, started["proj-b"], "a project with no ingested traffic gets no receiver")

	ingest("proj-b", "/c", database.RecordSourceIngestProxy)
	p.sync(ctx, repo)
	p.sync(ctx, repo)

	require.Equal(t, 1, started["proj-a"])
	require.Equal(t, 1, started["proj-b"])
	require.Zero(t, started[database.DefaultProjectUUID], "the default project's receiver is not duplicated")
	p.closeAll()
	require.EqualValues(t, 3, closed.Load())
}
