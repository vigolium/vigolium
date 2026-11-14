package tracker

import (
	"strconv"
	"testing"
)

// MISS-1: on a base-path target (https://host/app/) segments count relative to
// the start directory, so the primary wordlist does not share one "/app"
// bucket, and the base path itself never trips.
func TestPrefixBreaker_BasePathRelative(t *testing.T) {
	b := NewPrefixBreaker(BreakerConfig{
		Enabled: true, MinSamples: 5, TripRatio: 0.9, PrefixSegments: 1, LengthBucket: 256,
		BasePath: "/app/",
	})
	for i := 0; i < 50; i++ {
		u := mustURL(t, "http://h/app/word"+strconv.Itoa(i))
		if _, tripped := b.Observe(u, 403, "text/html", 120); tripped {
			t.Fatalf("distinct words under the base path must not share a bucket (tripped at %d)", i)
		}
	}
	for i := 0; i < 10; i++ {
		b.Observe(mustURL(t, "http://h/app/"), 403, "text/html", 120)
	}
	if b.IsDead(mustURL(t, "http://h/app/")) || b.IsDead(mustURL(t, "http://h/app/next")) {
		t.Fatal("the base path must never be dead")
	}
	// A uniform subtree under the base path still trips.
	for i := 0; i < 6; i++ {
		b.Observe(mustURL(t, "http://h/app/ftp/f"+strconv.Itoa(i)), 403, "text/html", 120)
	}
	if !b.IsDead(mustURL(t, "http://h/app/ftp/other")) {
		t.Fatal("a uniform /app/ftp/* subtree should trip")
	}
	if got := BasePathOf("/app/index.php"); got != "/app/" {
		t.Fatalf("BasePathOf = %q", got)
	}
	if got := BasePathOf("/#/../FUZZ"); got != "/" {
		t.Fatalf("BasePathOf(bypass) = %q", got)
	}
}
