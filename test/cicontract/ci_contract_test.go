// Package cicontract checks the repository's CI wiring: which events run which
// jobs, and that a release cannot skip the unit suite. These are plain files,
// so the checks are static and need neither network nor Docker.
package cicontract

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

type workflow struct {
	On   map[string]yaml.Node `yaml:"on"`
	Jobs map[string]struct {
		If    string      `yaml:"if"`
		Needs any         `yaml:"needs"`
		Steps []yaml.Node `yaml:"steps"`
	} `yaml:"jobs"`
}

// fastGate are the jobs that run on every pull request and push to main.
var fastGate = []string{"lint", "unit"}

// prOnly / aggregate jobs have their own event logic.
var ownLogic = []string{"dependency-review", "ci-ok"}

func loadWorkflow(t *testing.T) workflow {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	var wf workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse ci.yml: %v", err)
	}
	return wf
}

func TestCIWorkflow_Triggers(t *testing.T) {
	wf := loadWorkflow(t)
	for _, ev := range []string{"pull_request", "push", "workflow_dispatch"} {
		if _, ok := wf.On[ev]; !ok {
			t.Errorf("ci.yml must trigger on %s", ev)
		}
	}
	// The heavy suite is dispatch-only by choice: a cron here would run the
	// whole nightly set (race, canary, benchmarks, cross compile) against the
	// single maintained branch every day. Re-add deliberately, not by accident.
	if _, ok := wf.On["schedule"]; ok {
		t.Error("ci.yml must not declare a schedule trigger; heavy jobs are workflow_dispatch only")
	}
	push := wf.On["push"]
	var p struct {
		Branches []string `yaml:"branches"`
	}
	_ = push.Decode(&p)
	if !slices.Contains(p.Branches, "main") {
		t.Errorf("push trigger must include branch main, got %v", p.Branches)
	}
}

// Every job outside the fast gate must be restricted to dispatched runs, so a
// pull request or a push to main runs lint + unit only.
func TestCIWorkflow_HeavyJobsAreDispatchOnly(t *testing.T) {
	wf := loadWorkflow(t)
	for _, name := range fastGate {
		job, ok := wf.Jobs[name]
		if !ok {
			t.Errorf("fast-gate job %q missing", name)
			continue
		}
		if job.If != "" {
			t.Errorf("fast-gate job %q must run on every event, has if: %s", name, job.If)
		}
	}
	for _, name := range []string{"race", "postgres", "canary", "benchmark-whitebox", "benchmark-blackbox"} {
		if _, ok := wf.Jobs[name]; !ok {
			t.Errorf("heavy job %q missing", name)
		}
	}
	for name, job := range wf.Jobs {
		if slices.Contains(fastGate, name) || slices.Contains(ownLogic, name) {
			continue
		}
		cond := job.If
		if !strings.Contains(cond, "schedule") && !strings.Contains(cond, "workflow_dispatch") {
			t.Errorf("job %q runs on pull_request/push; gate it with `if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'` (has %q)", name, cond)
		}
		if strings.Contains(cond, "pull_request") || strings.Contains(cond, "push") {
			t.Errorf("job %q condition mentions pull_request/push: %q", name, cond)
		}
	}
}

func TestMakefile_ReleaseRunsUnitTests(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	m := regexp.MustCompile(`(?m)^release:(.*)$`).FindSubmatch(data)
	if m == nil {
		t.Fatal("Makefile has no release: target")
	}
	if !slices.Contains(strings.Fields(string(m[1])), "test-unit") {
		t.Errorf("release must depend on test-unit, prerequisites: %s", m[1])
	}
}
