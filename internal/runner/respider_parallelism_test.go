package runner

import "testing"

func TestReSpiderHostParallelism(t *testing.T) {
	cases := []struct {
		name      string
		env       string
		numGroups int
		want      int
	}{
		{"default sequential", "", 5, 1},
		{"opt-in 2", "2", 5, 2},
		{"clamped to hosts", "8", 3, 3},
		{"clamped to cap", "99", 20, reSpiderHostParallelismCap},
		{"zero falls back to 1", "0", 5, 1},
		{"garbage falls back to 1", "abc", 5, 1},
		{"never exceeds groups", "4", 1, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("VIGOLIUM_SPIDER_HOST_PARALLELISM", c.env)
			if got := reSpiderHostParallelism(c.numGroups); got != c.want {
				t.Errorf("reSpiderHostParallelism(%d) with env=%q = %d, want %d", c.numGroups, c.env, got, c.want)
			}
		})
	}
}
