package cli

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

func TestCheckFollowUpArgv(t *testing.T) {
	root := preparedMachineTree(t)
	db := "/tmp/x.sqlite"
	require.NoError(t, CheckFollowUpArgv(root, []string{"vigolium", "--db", db, "finding", "--id", "5", "--json"}, db))
	require.NoError(t, CheckFollowUpArgv(root, []string{"vigolium", "--db", db, "traffic", "--uuid", "abc", "--json", "--full-body"}, db))

	require.Error(t, CheckFollowUpArgv(root, []string{"vigolium", "finding", "--id", "5"}, db), "the source's --db is missing")
	require.Error(t, CheckFollowUpArgv(root, []string{"vigolium", "--db", db, "scan-request", "-i", "http://x/", "-j"}, db), "a scan is not a read")
	require.Error(t, CheckFollowUpArgv(root, []string{"vigolium", "--db", db, "replay", "-u", "x"}, db), "replay sends traffic")
	require.Error(t, CheckFollowUpArgv(root, []string{"vigolium", "--db", db, "finding", "--bogus"}, db), "does not parse")
}

// The --db a caller passed is repeated even when the command opened its store
// without the recorded opener.
func TestFollowUpDBFlagFallsBackToGlobalDB(t *testing.T) {
	resetDBCacheForTest()
	t.Cleanup(resetDBCacheForTest)
	prevOpened := clicommon.OpenedDBPath()
	clicommon.SetOpenedDBPath("")
	t.Cleanup(func() { clicommon.SetOpenedDBPath(prevOpened) })
	swapGlobal(t, &globalStateless, false)
	swapGlobal(t, &globalDB, "/tmp/pinned.sqlite")
	require.Equal(t, "/tmp/pinned.sqlite", followUpDBFlag())
}

func TestSendsTrafficStamp(t *testing.T) {
	env := newAgentEnvelope("fuzz", "", nil, 0, 0, 0)
	stampSendsTraffic(env)
	require.Equal(t, true, env.extra["sends_traffic"])
	env = newAgentEnvelope("finding", "", nil, 0, 0, 0)
	stampSendsTraffic(env)
	require.NotContains(t, env.extra, "sends_traffic")
}
