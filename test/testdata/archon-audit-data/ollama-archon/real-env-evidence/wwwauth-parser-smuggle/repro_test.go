package server

import (
	"fmt"
	"testing"
)

// Reproduces the WWW-Authenticate parser smuggle claim.
func TestWWWAuthSmuggleRepro(t *testing.T) {
	hdr := `Bearer realm="https://auth.legit.com/token?service=attacker&scope=repository:all:*",service="legit",scope="repository:foo:pull"`
	c := parseRegistryChallenge(hdr)
	fmt.Printf("Realm:   %q\n", c.Realm)
	fmt.Printf("Service: %q\n", c.Service)
	fmt.Printf("Scope:   %q\n", c.Scope)

	u, err := c.URL()
	if err != nil {
		t.Fatalf("URL err: %v", err)
	}
	fmt.Printf("URL:     %s\n", u.String())
	fmt.Printf("Host:    %s\n", u.Host)

	q := u.Query()
	services := q["service"]
	scopes := q["scope"]
	fmt.Printf("Query service values: %q\n", services)
	fmt.Printf("Query scope values:   %q\n", scopes)
}
