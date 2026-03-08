package cloud_public_read

import "strings"

var sensitivePaths = []struct {
	path string
	desc string
}{
	{"/uploads/", "User uploads directory"},
	{"/backups/", "Backup files directory"},
	{"/data/", "Data files directory"},
	{"/logs/", "Log files directory"},
	{"/config/", "Configuration directory"},
	{"/private/", "Private files directory"},
	{"/exports/", "Data exports directory"},
	{"/dump/", "Database dump directory"},
	{"/internal/", "Internal files directory"},
	{"/admin/", "Admin files directory"},
}

var errorIndicators = []string{
	"<Error>",
	"AccessDenied",
	"NoSuchKey",
	"NoSuchBucket",
	"BlobNotFound",
	"ResourceNotFound",
	"The specified key does not exist",
	"The specified blob does not exist",
	"404 Not Found",
	"Page not found",
}

func isCloudStorageHost(host string) bool {
	h := strings.ToLower(host)
	return (strings.Contains(h, ".s3") && strings.Contains(h, "amazonaws.com")) ||
		(strings.Contains(h, "s3-website") && strings.Contains(h, "amazonaws.com")) ||
		strings.Contains(h, "storage.googleapis.com") ||
		strings.Contains(h, ".storage.googleapis.com") ||
		strings.Contains(h, ".blob.core.windows.net") ||
		strings.Contains(h, ".web.core.windows.net")
}

func isErrorResponse(body string) bool {
	lower := strings.ToLower(body)
	for _, indicator := range errorIndicators {
		if strings.Contains(lower, strings.ToLower(indicator)) {
			return true
		}
	}
	return false
}
