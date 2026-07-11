package secretscan

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	re2 "github.com/wasilibs/go-re2"
)

// TestEngineParity asserts the default engine (go-re2) is semantically identical
// to Go's stdlib RE2 across every rule and example. Because go-re2 runs the real
// RE2 engine, it must never diverge — guarding against the false-negative class
// that ruled out coregex.
func TestEngineParity(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]string{}
	for _, r := range cat.Rules {
		byID[r.ID] = r.Re
	}
	examples := loadExamples(t)

	var diverge []string
	for id, exs := range examples {
		re, ok := byID[id]
		if !ok {
			continue
		}
		std := regexp.MustCompile(re)
		r2 := re2.MustCompile(re)
		for _, ex := range exs {
			if std.MatchString(ex) != r2.MatchString(ex) {
				diverge = append(diverge, id)
				break
			}
		}
	}
	t.Logf("go-re2 divergence vs stdlib: %d rules %v", len(diverge), diverge)
	if len(diverge) > 0 {
		t.Errorf("go-re2 diverged from stdlib on %d rules — expected identical RE2 semantics", len(diverge))
	}
}

// syntheticBody builds a realistic-ish text body (a minified JS bundle shape)
// with a few embedded secrets, for benchmarking.
func syntheticBody(sizeKB int) []byte {
	var b strings.Builder
	filler := `function x(a,b){return a+b}var cfg={url:"https://api.example.com/v1",retries:3,timeout:30000};` +
		`const data=[1,2,3,4,5,6,7,8,9,10];window.__STATE__={user:{id:42,name:"anon"},flags:{a:true,b:false}};`
	secrets := []string{
		`aws_key="AKIA` + strings.Repeat("Q", 16) + `";`,
		`stripe="sk_live_f0` + `1c79xuuug7` + `yodgzj5ws0` + `h1x2kyvho3";`,
		`gh="ghp_123456` + `7890abcdef` + `ghijklmnop` + `qrstuvwxyz";`,
	}
	target := sizeKB * 1024
	i := 0
	for b.Len() < target {
		b.WriteString(filler)
		if i%12 == 0 && i > 0 {
			b.WriteString(secrets[(i/12)%len(secrets)])
		}
		i++
	}
	return []byte(b.String())
}

func benchmarkEngine(b *testing.B, engine Engine, sizeKB int) {
	cat, err := LoadCatalog()
	if err != nil {
		b.Fatal(err)
	}
	det, err := New(cat, Options{Engine: engine})
	if err != nil {
		b.Fatal(err)
	}
	body := syntheticBody(sizeKB)
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		det.Detect(body)
	}
}

func BenchmarkDetect(b *testing.B) {
	for _, size := range []int{16, 128, 512} {
		b.Run(fmt.Sprintf("stdlib/%dKB", size), func(b *testing.B) { benchmarkEngine(b, EngineStdlib, size) })
		b.Run(fmt.Sprintf("re2/%dKB", size), func(b *testing.B) { benchmarkEngine(b, EngineRE2, size) })
	}
}

// BenchmarkCompile measures one-time detector construction (regex compilation of
// the full catalog) per engine.
func BenchmarkCompile(b *testing.B) {
	cat, err := LoadCatalog()
	if err != nil {
		b.Fatal(err)
	}
	for _, e := range []struct {
		name   string
		engine Engine
	}{{"stdlib", EngineStdlib}, {"re2", EngineRE2}} {
		b.Run(e.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := New(cat, Options{Engine: e.engine}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestPrefilterSound verifies the coregx/ahocorasick keyword prefilter is a
// SOUND necessary filter: every keyword actually present in a body must be
// reported by the automaton. A miss here would silently drop a rule (false
// negative), so this guards the one remaining coregx dependency.
func TestPrefilterSound(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	det, err := New(cat, Options{IncludeInvisible: true})
	if err != nil {
		t.Fatal(err)
	}
	if det.ac == nil {
		t.Fatal("no prefilter built")
	}

	// Build a corpus that contains every keyword (concatenated) plus realistic
	// filler, lowercased exactly as Detect does.
	var sb strings.Builder
	kwByPattern := map[int]string{}
	for pid := range det.kwToRules {
		kw := det.kwList[pid]
		kwByPattern[pid] = kw
		sb.WriteString("x ")
		sb.WriteString(kw)
		sb.WriteString(" y\n")
	}
	corpus := strings.ToLower(sb.String())

	found := map[int]bool{}
	for _, m := range det.ac.FindAllOverlapping([]byte(corpus)) {
		found[m.PatternID] = true
	}

	missing := 0
	for pid, kw := range kwByPattern {
		if !strings.Contains(corpus, kw) {
			continue // shouldn't happen; corpus embeds all
		}
		if !found[pid] {
			missing++
			if missing <= 10 {
				t.Errorf("prefilter MISSED present keyword %q (pattern %d)", kw, pid)
			}
		}
	}
	if missing > 0 {
		t.Fatalf("prefilter unsound: %d present keywords not reported", missing)
	}
	t.Logf("prefilter sound: all %d keywords detected when present", len(kwByPattern))
}

// TestConcurrentDetect ensures the default (go-re2) Detector is safe for
// concurrent use, as the scan executor invokes it from a worker pool.
func TestConcurrentDetect(t *testing.T) {
	det, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`k1="sk_live_f0` + `1c79xuuug7` + `yodgzj5ws0` + `h1x2kyvho3" k2="GOCSPX-PUi` + `AMWsxZUxAS` + `-wpWpIgb6j` + `6arTD"`)
	want := len(det.Detect(body))
	if want == 0 {
		t.Fatal("expected findings in fixture")
	}
	const workers = 16
	errs := make(chan int, workers)
	for i := 0; i < workers; i++ {
		go func() {
			n := 0
			for j := 0; j < 50; j++ {
				n = len(det.Detect(body))
			}
			errs <- n
		}()
	}
	for i := 0; i < workers; i++ {
		if got := <-errs; got != want {
			t.Errorf("concurrent Detect returned %d, want %d", got, want)
		}
	}
}
