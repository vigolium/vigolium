package core

import (
	"testing"
)

func TestModuleFilter(t *testing.T) {
	tests := []struct {
		name          string
		moduleID      string
		enableModules []string
		want          bool
	}{
		{"empty list enables all", "active-xss", nil, true},
		{"all keyword enables all", "active-xss", []string{"all"}, true},
		{"exact match", "active-xss", []string{"active-xss"}, true},
		{"no match", "active-xss", []string{"active-sqli"}, false},
		{"multiple with match", "active-xss", []string{"active-sqli", "active-xss"}, true},
		{"all among others", "active-xss", []string{"active-sqli", "all"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := newModuleFilter(tt.enableModules)
			if got := filter.allows(tt.moduleID); got != tt.want {
				t.Errorf("moduleFilter.allows() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestModuleFindingAllowed(t *testing.T) {
	t.Run("cap enforced", func(t *testing.T) {
		e := &Executor{cfg: ExecutorConfig{MaxFindingsPerModule: 3}}
		for i := 0; i < 3; i++ {
			if !e.moduleFindingAllowed("test-mod") {
				t.Fatalf("call %d should be allowed", i+1)
			}
		}
		for i := 0; i < 2; i++ {
			if e.moduleFindingAllowed("test-mod") {
				t.Fatalf("call %d past cap should be denied", i+4)
			}
		}
	})

	t.Run("independent modules", func(t *testing.T) {
		e := &Executor{cfg: ExecutorConfig{MaxFindingsPerModule: 1}}
		if !e.moduleFindingAllowed("mod-a") {
			t.Fatal("mod-a first call should be allowed")
		}
		if e.moduleFindingAllowed("mod-a") {
			t.Fatal("mod-a second call should be denied")
		}
		if !e.moduleFindingAllowed("mod-b") {
			t.Fatal("mod-b should be independent and allowed")
		}
	})

	t.Run("cap zero means unlimited", func(t *testing.T) {
		e := &Executor{cfg: ExecutorConfig{MaxFindingsPerModule: 0}}
		for i := 0; i < 100; i++ {
			if !e.moduleFindingAllowed("test-mod") {
				t.Fatalf("call %d should be allowed with cap 0", i+1)
			}
		}
	})
}
