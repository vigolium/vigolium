package cloud_storage_fingerprint

import "regexp"

type cloudProvider string

const (
	providerS3    cloudProvider = "AWS S3"
	providerGCS   cloudProvider = "Google Cloud Storage"
	providerAzure cloudProvider = "Azure Blob Storage"
)

type headerPattern struct {
	header   string
	provider cloudProvider
}

var headerPatterns = []headerPattern{
	{"x-amz-request-id", providerS3},
	{"x-amz-id-2", providerS3},
	{"x-amz-bucket-region", providerS3},
	{"x-goog-hash", providerGCS},
	{"x-goog-generation", providerGCS},
	{"x-goog-storage-class", providerGCS},
	{"x-ms-request-id", providerAzure},
	{"x-ms-version", providerAzure},
	{"x-ms-blob-type", providerAzure},
}

var serverPatterns = []struct {
	match    string
	provider cloudProvider
}{
	{"AmazonS3", providerS3},
	{"Windows-Azure-Blob", providerAzure},
	{"Blob Service Version", providerAzure},
}

type urlPattern struct {
	re       *regexp.Regexp
	provider cloudProvider
}

var urlPatterns = []urlPattern{
	{regexp.MustCompile(`https?://[\w.-]+\.s3[.\-][\w.-]*amazonaws\.com`), providerS3},
	{regexp.MustCompile(`https?://s3[.\-][\w.-]*amazonaws\.com/[\w.-]+`), providerS3},
	{regexp.MustCompile(`https?://storage\.googleapis\.com/[\w.-]+`), providerGCS},
	{regexp.MustCompile(`https?://[\w.-]+\.storage\.googleapis\.com`), providerGCS},
	{regexp.MustCompile(`https?://[\w.-]+\.blob\.core\.windows\.net`), providerAzure},
	{regexp.MustCompile(`https?://[\w.-]+\.web\.core\.windows\.net`), providerAzure},
}

var hostPatterns = []struct {
	suffix   string
	provider cloudProvider
}{
	{".s3.amazonaws.com", providerS3},
	{".s3-website", providerS3},
	{"storage.googleapis.com", providerGCS},
	{".blob.core.windows.net", providerAzure},
	{".web.core.windows.net", providerAzure},
}
