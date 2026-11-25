package httpmsg

import "strings"

// SafeMethods are the HTTP methods that read without changing server state.
// Every "may this be re-sent / clicked / replayed without --allow-writes"
// decision goes through this list.
var SafeMethods = []string{"GET", "HEAD", "OPTIONS"}

// IsSafeMethod reports whether method (any case) is one of SafeMethods.
func IsSafeMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS":
		return true
	}
	return false
}
