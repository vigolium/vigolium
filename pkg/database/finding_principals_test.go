package database

import (
	"reflect"
	"testing"
)

// A cross-session result names its primary session first and the compare
// session that reached the object second; a single-session result names none.
func TestPrincipalsFromMetadata(t *testing.T) {
	cases := []struct {
		meta map[string]interface{}
		want []string
	}{
		{map[string]interface{}{"primary_session": "alice", "compare_session": "bob"}, []string{"alice", "bob"}},
		{map[string]interface{}{"compare_session": "bob"}, []string{"", "bob"}},
		{map[string]interface{}{"primary_session": "alice"}, nil},
		{nil, nil},
	}
	for _, c := range cases {
		if got := principalsFromMetadata(c.meta); !reflect.DeepEqual(got, c.want) {
			t.Errorf("principalsFromMetadata(%v) = %v, want %v", c.meta, got, c.want)
		}
	}
}
