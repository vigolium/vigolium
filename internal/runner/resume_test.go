package runner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/types"
)

// resumeFixture is a store holding one finished scan of target with the plan
// and module list a real run would have stored, and a counter of requests
// reaching target.
type resumeFixture struct {
	repo   *database.Repository
	target string
	hits   *atomic.Int64
}

func newResumeFixture(t *testing.T, storedUUID string, opts *types.Options, settings *config.Settings) resumeFixture {
	t.Helper()
	hits := &atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	t.Cleanup(srv.Close)

	dbCfg := settings.Database
	dbCfg.Driver = "sqlite"
	dbCfg.SQLite.Path = filepath.Join(t.TempDir(), "resume.sqlite")
	db, err := database.NewDB(&dbCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.EnsureSchemaReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	repo := database.NewRepository(db)

	plan, _ := json.Marshal(map[string]any{"scope": planScope(settings.Scope)})
	sel := FilterModulesForRun(opts, settings)
	var ids []string
	for _, m := range sel.Active {
		ids = append(ids, m.ID())
	}
	for _, m := range sel.Passive {
		ids = append(ids, m.ID())
	}
	if err := repo.CreateScan(context.Background(), &database.Scan{
		UUID: storedUUID, ProjectUUID: database.DefaultProjectUUID, Status: "completed",
		Target: srv.URL, Modules: strings.Join(ids, ",") + ",ext-custom-check", Plan: plan,
		StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	return resumeFixture{repo: repo, target: srv.URL, hits: hits}
}

func resumeOptsSettings(t *testing.T) (*types.Options, *config.Settings) {
	t.Helper()
	opts := types.DefaultOptions()
	opts.Silent = true
	opts.Retries = 0
	opts.Timeout = 5 * time.Second
	opts.ProjectUUID = database.DefaultProjectUUID
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	settings := config.DefaultSettings()
	settings.OAST.Enabled = false
	settings.DynamicAssessment.Extensions.Enabled = false
	return opts, settings
}

func runResume(t *testing.T, fx resumeFixture, opts *types.Options, settings *config.Settings) error {
	t.Helper()
	r, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	r.SetSettings(settings)
	r.SetRepository(fx.repo)
	r.phaseRunners = map[NativePhase]phaseRunner{}
	defer r.Close()
	return r.RunNativeScan()
}

// A resume that cannot proceed is refused before anything is built or sent:
// no preflight GET, no login, no OAST registration reaches the network.
func TestResumeScanRefusedBeforeInfrastructure(t *testing.T) {
	const stored = "11111111-2222-3333-4444-555555555555"

	t.Run("unknown scan: scan_not_found", func(t *testing.T) {
		opts, settings := resumeOptsSettings(t)
		fx := newResumeFixture(t, stored, opts, settings)
		opts.Targets = []string{fx.target}
		opts.ResumeScanUUID = "99999999-0000-0000-0000-000000000000"
		err := runResume(t, fx, opts, settings)
		var re *ResumeError
		if !errors.As(err, &re) || re.Code() != apicontract.CodeScanNotFound {
			t.Fatalf("err = %v, want a scan_not_found ResumeError", err)
		}
		if n := fx.hits.Load(); n != 0 {
			t.Fatalf("a refused resume sent %d request(s) to the target", n)
		}
	})

	t.Run("different targets: resume_mismatch, nothing sent", func(t *testing.T) {
		opts, settings := resumeOptsSettings(t)
		fx := newResumeFixture(t, stored, opts, settings)
		opts.Targets = []string{fx.target + "/elsewhere"}
		opts.ResumeScanUUID = stored
		err := runResume(t, fx, opts, settings)
		var re *ResumeError
		if !errors.As(err, &re) || re.Code() != apicontract.CodeResumeMismatch {
			t.Fatalf("err = %v, want a resume_mismatch ResumeError", err)
		}
		if len(re.Diffs) != 1 || re.Diffs[0].Field != "targets" {
			t.Errorf("diffs = %+v, want one targets diff", re.Diffs)
		}
		if n := fx.hits.Load(); n != 0 {
			t.Fatalf("a refused resume sent %d request(s) to the target", n)
		}
		row, _ := fx.repo.GetScanByUUID(context.Background(), stored)
		if row.Status != "completed" {
			t.Errorf("a refused resume rewrote the row's status to %q", row.Status)
		}
	})
}

func TestResumeMismatch(t *testing.T) {
	const stored = "11111111-2222-3333-4444-555555555555"
	opts, settings := resumeOptsSettings(t)
	fx := newResumeFixture(t, stored, opts, settings)
	row, err := fx.repo.GetScanByUUID(context.Background(), stored)
	if err != nil {
		t.Fatal(err)
	}

	same := *opts
	same.Targets = []string{" " + fx.target + " "}
	if d := ResumeMismatch(row, &same, settings); len(d) != 0 {
		t.Fatalf("the same targets, scope and modules must match (extension ids are not compared); got %+v", d)
	}

	scoped := config.DefaultSettings()
	scoped.Scope.Host.Exclude = []string{"admin.example.com"}
	if d := ResumeMismatch(row, &same, scoped); len(d) != 1 || d[0].Field != "scope" || !strings.Contains(d[0].Requested, "admin.example.com") {
		t.Errorf("a changed scope must differ on scope; got %+v", d)
	}

	narrowed := same
	narrowed.Modules = []string{"sqli-error-based"}
	d := ResumeMismatch(row, &narrowed, settings)
	if len(d) != 1 || d[0].Field != "modules" {
		t.Fatalf("a narrowed module selection must differ on modules; got %+v", d)
	}

	// A row that never reached the assessment (no modules) or has no plan
	// compares on what it has.
	bare := &database.Scan{Target: fx.target}
	if d := ResumeMismatch(bare, &narrowed, scoped); len(d) != 0 {
		t.Errorf("a row with no plan and no module list compares targets only; got %+v", d)
	}
}

// --force resumes despite a mismatch (and only a mismatch: the row must
// exist).
func TestResumeForceOverridesMismatch(t *testing.T) {
	const stored = "11111111-2222-3333-4444-555555555555"
	opts, settings := resumeOptsSettings(t)
	fx := newResumeFixture(t, stored, opts, settings)
	opts.Targets = []string{fx.target + "/elsewhere"}
	opts.ResumeScanUUID = stored
	opts.ResumeForce = true
	r := &Runner{options: opts, settings: settings, repository: fx.repo}
	if err := r.checkResume(context.Background()); err != nil {
		t.Fatalf("--force must resume a mismatched scan: %v", err)
	}
	opts.ResumeScanUUID = "99999999-0000-0000-0000-000000000000"
	var re *ResumeError
	if err := r.checkResume(context.Background()); !errors.As(err, &re) || re.Code() != apicontract.CodeScanNotFound {
		t.Fatalf("--force never resumes a scan that does not exist: %v", err)
	}
}
