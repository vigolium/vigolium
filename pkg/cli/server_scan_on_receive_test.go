package cli

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
)

type fakeReceiver struct{ closed *atomic.Int64 }

func (f fakeReceiver) Close() { f.closed.Add(1) }

// TestProjectReceivers_OnePerProject is MISS-34: scan-on-receive starts one
// receiver per project (it used to watch only the default project), never two
// for the same project, and stops them all on shutdown.
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
	p.add(database.DefaultProjectUUID, fakeReceiver{&closed})
	p.sync(ctx, repo)
	p.sync(ctx, repo)

	require.Equal(t, 1, started["proj-a"])
	require.Equal(t, 1, started["proj-b"])
	require.Zero(t, started[database.DefaultProjectUUID], "the default project's receiver is not duplicated")
	p.closeAll()
	require.EqualValues(t, 3, closed.Load())
}
