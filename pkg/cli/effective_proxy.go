package cli

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/http/proxyenv"
)

// effectiveProxy summarises the proxy configuration the HTTP stack resolves
// for cliProxy (the --proxy value) and the environment: the first proxy route
// and the source of every proxy in use ("--proxy", "VIGOLIUM_PROXY",
// "HTTPS_PROXY", ...), comma-joined. (nil, "none") when nothing is proxied.
func effectiveProxy(cliProxy string) (*proxyenv.Route, string) {
	routes := proxyenv.FromEnvironment(cliProxy).Proxies()
	if len(routes) == 0 {
		return nil, "none"
	}
	sources := make([]string, 0, len(routes))
	for _, r := range routes {
		sources = append(sources, r.Source)
	}
	return routes[0], strings.Join(sources, ",")
}
