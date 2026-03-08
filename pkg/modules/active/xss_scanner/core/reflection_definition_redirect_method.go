package core

type RedirectType byte

const (
	// RedirectTypeLocationHeader cho biết chuyển hướng từ HTTP Location header.
	RedirectTypeLocationHeader RedirectType = 0
	// RedirectTypeRefreshHeaderURL cho biết chuyển hướng từ URL trong HTTP Refresh header.
	RedirectTypeRefreshHeaderURL RedirectType = 1
	// RedirectTypeRefreshBodyURL cho biết chuyển hướng từ URL trong body của HTTP Refresh header.
	RedirectTypeRefreshBodyURL RedirectType = 2
	// RedirectTypeJavaScript cho biết chuyển hướng được thực hiện bởi JavaScript.
	RedirectTypeJavaScript RedirectType = 3
	// RedirectTypeUnknown để chỉ các trường hợp không xác định hoặc chưa được xử lý.
	RedirectTypeUnknown RedirectType = 255 // Hoặc một giá trị khác phù hợp
)
