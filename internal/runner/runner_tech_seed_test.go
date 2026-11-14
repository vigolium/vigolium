package runner

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/agent/recon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types"
)

// The DA tech registry is seeded from the fingerprint phase's stored host
// facts: newest observation per endpoint, medium confidence or better, this
// project only, keyed like RegistryHostKey (MISS-21 (e)).
func TestSeedTechRegistryFromStoredFacts(t *testing.T) {
	repo, _ := newHarvestTestRepo(t)
	ctx := context.Background()
	const project = "proj-seed"
	save := func(proj, scan, host string, port int, stacks ...recon.StackDetection) {
		t.Helper()
		err := repo.SaveHostObservations(ctx, proj, scan, []database.HostObservationInput{{
			Hostname: host, Port: port, Complete: true,
			Fingerprint: &recon.TechStackReport{Hostname: host, Stacks: stacks},
		}})
		if err != nil {
			t.Fatalf("save: %v", err)
		}
	}
	save(project, "scan-old", "app.test", 443,
		recon.StackDetection{Name: "django", Tag: "django", Confidence: recon.ConfidenceHigh})
	// The newer observation of the same endpoint wins.
	save(project, "scan-new", "app.test", 443,
		recon.StackDetection{Name: "spring-boot", Tag: "spring", Confidence: recon.ConfidenceHigh},
		recon.StackDetection{Name: "nginx", Confidence: recon.ConfidenceMedium},
		recon.StackDetection{Name: "laravel", Tag: "laravel", Confidence: recon.ConfidenceLow})
	save(project, "scan-new", "admin.test", 8443,
		recon.StackDetection{Name: "rails", Tag: "rails", Confidence: recon.ConfidenceMedium})
	// Another project's facts never leak in.
	save("proj-other", "scan-x", "app.test", 443,
		recon.StackDetection{Name: "wordpress", Tag: "wordpress", Confidence: recon.ConfidenceHigh})

	r := &Runner{repository: repo, options: &types.Options{ProjectUUID: project}}
	reg := modkit.NewTechRegistry()
	r.seedTechRegistry(ctx, reg)

	for _, tc := range []struct {
		host, tag string
		want      bool
	}{
		{"app.test", "spring", true},
		{"app.test", "nginx", true},
		{"app.test", "django", false},    // superseded by the newer observation
		{"app.test", "laravel", false},   // low confidence
		{"app.test", "wordpress", false}, // other project
		{"admin.test:8443", "rails", true},
	} {
		if got := reg.Has(tc.host, tc.tag); got != tc.want {
			t.Errorf("Has(%s, %s) = %v, want %v", tc.host, tc.tag, got, tc.want)
		}
	}
	// The seeded stack gates: a Django module is skipped on the Spring host.
	if reg.Allows("app.test", []string{"django"}) {
		t.Error("seeded spring host must exclude a django-only module")
	}
}
