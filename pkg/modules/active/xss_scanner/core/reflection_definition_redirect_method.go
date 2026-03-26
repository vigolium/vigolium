package core

type RedirectType byte

const (
	// RedirectTypeLocationHeader indicates a redirect via HTTP Location header.
	RedirectTypeLocationHeader RedirectType = 0
	// RedirectTypeRefreshHeaderURL indicates a redirect via URL in HTTP Refresh header.
	RedirectTypeRefreshHeaderURL RedirectType = 1
	// RedirectTypeRefreshBodyURL indicates a redirect via URL in the body of an HTTP Refresh header.
	RedirectTypeRefreshBodyURL RedirectType = 2
	// RedirectTypeJavaScript indicates a redirect performed by JavaScript.
	RedirectTypeJavaScript RedirectType = 3
	// RedirectTypeUnknown indicates an unknown or unhandled redirect type.
	RedirectTypeUnknown RedirectType = 255
)
