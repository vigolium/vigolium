//go:build e2e

package e2eexpect

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	dockercontainer "github.com/moby/moby/api/types/container"
	dockernetwork "github.com/moby/moby/api/types/network"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/vigolium/vigolium/pkg/cftbrowser"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/test/e2e-expect/lab"
)

// The live half of the kit: real vulnerable apps in Docker, driven through
// the binary the way an operator runs them (`vigolium scan`, `vigolium run
// <phase>`), with results read back from the run's own database file. Every
// test gets a fresh container — a scan mutates and can exhaust the app (Juice
// Shop runs out of heap after a discovery pass), and a shared container would
// make one test's results depend on another's.

type liveSpec struct {
	Name  string
	Image string
	Env   map[string]string
	Port  string // container port
	Ready string // path that answers 200 once the app is up
	// Setup runs once the app answers (e.g. VAmPI's /createdb).
	Setup func(t *testing.T, base string)
}

var (
	// Juice Shop keeps per-path metrics and grows ~110 MB per 1k requests; at
	// Node's default 4 GB heap a scan's discovery pass exhausts it, and then
	// the run measures the app's leak instead of the scanner. 8 GB of heap
	// keeps it standing through a full scan. Pinned to a release: `latest`
	// follows the development snapshots, which the golden paths do not track.
	juiceShop = liveSpec{Name: "juice-shop", Image: "bkimminich/juice-shop:v20.4.0", Port: "3000", Ready: "/",
		Env: map[string]string{"NODE_OPTIONS": "--max-old-space-size=8192"}}
	vampi = liveSpec{Name: "vampi", Image: "erev0s/vampi:latest", Port: "5000", Ready: "/",
		Setup: func(t *testing.T, base string) {
			// The app answers / before its database layer is ready; retry.
			var last string
			for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
				resp, err := http.Get(base + "/createdb")
				if err != nil {
					last = err.Error()
					continue
				}
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return
				}
				last = resp.Status
			}
			t.Fatalf("VAmPI /createdb never succeeded: %s", last)
		}}
)

// liveApp is a running target. Scans are pointed at Base, a lab reverse
// proxy in front of the container, so every request the scanner sends is in
// Lab.Ledger (counts, peak concurrency, per-path traffic) exactly as for a lab
// server; Direct is the container itself, for health checks.
type liveApp struct {
	spec      liveSpec
	Base      string
	Direct    string
	Lab       *lab.Lab
	container testcontainers.Container
}

// proxyName is the ledger name of a live app's proxy.
const proxyName = "live"

// startLive starts a fresh container for spec, bound to 127.0.0.1 only, and
// tears it down with the test. Skips when Docker is not available.
func startLive(t *testing.T, spec liveSpec) *liveApp {
	t.Helper()
	if testing.Short() {
		t.Skip("live Docker targets are skipped in -short mode")
	}
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	natPort, err := dockernetwork.ParsePort(spec.Port + "/tcp")
	require.NoError(t, err)
	hostPort := lab.FreePort()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        spec.Image,
			ExposedPorts: []string{spec.Port + "/tcp"},
			Env:          spec.Env,
			WaitingFor:   wait.ForHTTP(spec.Ready).WithPort(spec.Port + "/tcp").WithStartupTimeout(3 * time.Minute),
			HostConfigModifier: func(hc *dockercontainer.HostConfig) {
				hc.PortBindings = dockernetwork.PortMap{natPort: []dockernetwork.PortBinding{{
					HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: strconv.Itoa(hostPort),
				}}}
			},
		},
		Started: true,
	})
	if c != nil {
		t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	}
	require.NoErrorf(t, err, "start %s", spec.Image)
	direct := fmt.Sprintf("http://127.0.0.1:%d", hostPort)
	if spec.Setup != nil {
		spec.Setup(t, direct)
	}
	l := newLab(t)
	proxy := l.Serve(proxyName, lab.ReverseProxy(direct))
	app := &liveApp{spec: spec, Base: proxy.URL, Direct: direct, Lab: l, container: c}
	t.Logf("%s up at %s (proxied as %s)", spec.Name, direct, app.Base)
	return app
}

// alive reports whether the app still answers its ready path within d.
func (a *liveApp) alive(d time.Duration) bool {
	c := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(d)
	for {
		resp, err := c.Get(a.Direct + a.spec.Ready)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 500 {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Second)
	}
}

// memMiB is the container's current memory use, or -1 when the docker CLI
// cannot say.
func (a *liveApp) memMiB() int {
	out, err := exec.Command("docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", a.container.GetContainerID()).Output()
	if err != nil {
		return -1
	}
	used, _, _ := strings.Cut(strings.TrimSpace(string(out)), "/")
	used = strings.TrimSpace(used)
	for _, u := range []struct {
		suffix string
		mul    float64
	}{{"GiB", 1024}, {"MiB", 1}, {"KiB", 1.0 / 1024}, {"B", 1.0 / (1 << 20)}} {
		if strings.HasSuffix(used, u.suffix) {
			f, err := strconv.ParseFloat(strings.TrimSuffix(used, u.suffix), 64)
			if err != nil {
				return -1
			}
			return int(f * u.mul)
		}
	}
	return -1
}

// running reports whether the container process is still up.
func (a *liveApp) running() bool {
	st, err := a.container.State(context.Background())
	return err == nil && st.Running
}

// --- reading a run's results back -----------------------------------------

// store opens the database file a binary run wrote.
type store struct {
	db   *database.DB
	repo *database.Repository
}

func openStore(t *testing.T, path string) *store {
	t.Helper()
	db := openDB(t, path)
	return &store{db: db, repo: database.NewRepository(db)}
}

// records returns the stored records matching f, without their request and
// response bodies (no expectation reads them).
func (s *store) records(t *testing.T, f database.QueryFilters) []*database.HTTPRecord {
	t.Helper()
	if f.Limit == 0 {
		f.Limit = 100000
	}
	recs, err := database.NewQueryBuilder(s.db, f).OmitBodies().Execute(context.Background())
	require.NoError(t, err)
	return recs
}

// findings returns record_kind=finding rows (candidates and observations are
// leads, not results, and are left out of expectations).
func (s *store) findings(t *testing.T) []*database.Finding {
	t.Helper()
	fs, err := database.NewFindingsQueryBuilder(s.db, database.QueryFilters{Limit: 100000}).Execute(context.Background())
	require.NoError(t, err)
	return fs
}

// answeredPaths is the sorted set of "METHOD /path" the run stored with a
// real response (status > 0; JS-derived requests that were never sent are
// left out).
func answeredPaths(recs []*database.HTTPRecord) []string {
	return sortedSet(recs, func(r *database.HTTPRecord) string {
		if r.StatusCode <= 0 {
			return ""
		}
		return r.Method + " " + urlPath(r.URL)
	})
}

// liveKeys renders findings as sorted "who@path" keys, normalized so a live
// app's legitimate run-to-run variation does not read as drift:
//   - who is the module's vuln class ("class:sqli") when it declares one —
//     which of sqli-error-based / sqli-boolean-blind claims a parameter first
//     is scheduling, not behavior (one finding per param and class);
//   - API version segments are generalized (/v2/api-docs ≡ /v3/api-docs).
func liveKeys(fs []*database.Finding) []string {
	return sortedSet(fs, func(f *database.Finding) string {
		return liveWho(f.ModuleID) + "@" + versionSeg.ReplaceAllString(findingPath(f), "/v*/")
	})
}

var versionSeg = regexp.MustCompile(`/v[0-9]+/`)

func liveWho(moduleID string) string {
	for _, m := range modules.DefaultRegistry.GetActiveModulesByIDs([]string{moduleID}) {
		if c := modules.ModuleVulnClass(m); c != "" {
			return "class:" + c
		}
	}
	return moduleID
}

// --- browser for spidering -------------------------------------------------

// findBrowser locates a Chromium the spider can drive without downloading
// one: E2E_EXPECT_BROWSER, then the Chrome for Testing cache
// (`make deps-chrome-cft`), then rod's cache under the real home, then a
// system Chrome. "" when none is found.
func findBrowser() string {
	if p := os.Getenv("E2E_EXPECT_BROWSER"); p != "" {
		return p
	}
	if p, err := cftbrowser.FindCachedBrowser(); err == nil {
		return p
	}
	home, _ := os.UserHomeDir()
	var candidates []string
	if runtime.GOOS == "darwin" {
		m, _ := filepath.Glob(filepath.Join(home, ".cache/rod/browser/*/Chromium.app/Contents/MacOS/Chromium"))
		sort.Sort(sort.Reverse(sort.StringSlice(m)))
		candidates = append(candidates, m...)
		candidates = append(candidates, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium")
	} else {
		m, _ := filepath.Glob(filepath.Join(home, ".cache/rod/browser/*/chrome"))
		sort.Sort(sort.Reverse(sort.StringSlice(m)))
		candidates = append(candidates, m...)
		for _, name := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable"} {
			if p, err := exec.LookPath(name); err == nil {
				candidates = append(candidates, p)
			}
		}
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

// withBrowser points the install's spider at a local browser, or skips.
func (c *cli) withBrowser(t *testing.T) *cli {
	t.Helper()
	b := findBrowser()
	if b == "" {
		t.Skip("no local Chromium/Chrome found (set E2E_EXPECT_BROWSER); spidering would download one")
	}
	r := c.run(t, time.Minute, "config", "set", "spidering.browser_path", b, "-j")
	require.Equalf(t, 0, r.code, "set browser_path\n%s", r)
	return c
}
