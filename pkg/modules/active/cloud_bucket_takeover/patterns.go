package cloud_bucket_takeover

import "strings"

type takeoverSignature struct {
	name     string
	markers  []string
	provider string
}

var takeoverSignatures = []takeoverSignature{
	{
		name:     "S3 NoSuchBucket",
		markers:  []string{"NoSuchBucket"},
		provider: "AWS S3",
	},
	{
		name:     "S3 Website NoSuchBucket",
		markers:  []string{"NoSuchBucket", "The specified bucket does not exist"},
		provider: "AWS S3",
	},
	{
		name:     "GCS Bucket Not Found",
		markers:  []string{"The specified bucket does not exist"},
		provider: "Google Cloud Storage",
	},
	{
		name:     "GCS Not Found JSON",
		markers:  []string{"\"code\"", "404", "\"not found\""},
		provider: "Google Cloud Storage",
	},
	{
		name:     "Azure ContainerNotFound",
		markers:  []string{"ContainerNotFound"},
		provider: "Azure Blob Storage",
	},
	{
		name:     "Azure BlobNotFound",
		markers:  []string{"The specified container does not exist"},
		provider: "Azure Blob Storage",
	},
}

func isCloudStorageHost(host string) bool {
	h := strings.ToLower(host)
	return (strings.Contains(h, ".s3") && strings.Contains(h, "amazonaws.com")) ||
		(strings.Contains(h, "s3-website") && strings.Contains(h, "amazonaws.com")) ||
		strings.Contains(h, "storage.googleapis.com") ||
		strings.Contains(h, ".storage.googleapis.com") ||
		strings.Contains(h, ".blob.core.windows.net") ||
		strings.Contains(h, ".web.core.windows.net") ||
		strings.Contains(h, "c.storage.googleapis.com")
}

func bodyMatchesSignature(body string, sig takeoverSignature) bool {
	lower := strings.ToLower(body)
	for _, marker := range sig.markers {
		if !strings.Contains(lower, strings.ToLower(marker)) {
			return false
		}
	}
	return true
}
