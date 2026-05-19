package cloud_signed_url_leak

import "regexp"

type signedURLType string

const (
	typeAWSPresigned signedURLType = "AWS Presigned URL"
	typeGCSSigned    signedURLType = "GCS Signed URL"
	typeAzureSAS     signedURLType = "Azure SAS Token"
)

type signedURLPattern struct {
	re      *regexp.Regexp
	urlType signedURLType
}

var signedURLPatterns = []signedURLPattern{
	{
		re:      regexp.MustCompile(`https?://[^\s"'<>]+X-Amz-Signature=[0-9a-fA-F]+[^\s"'<>]*`),
		urlType: typeAWSPresigned,
	},
	{
		re:      regexp.MustCompile(`https?://[^\s"'<>]+X-Goog-Signature=[0-9a-fA-F]+[^\s"'<>]*`),
		urlType: typeGCSSigned,
	},
	{
		re:      regexp.MustCompile(`https?://[^\s"'<>]+[?&]sv=[^\s"'<>]*sig=[^\s"'<>]+`),
		urlType: typeAzureSAS,
	},
}

var (
	awsExpiresRe  = regexp.MustCompile(`X-Amz-Expires=(\d+)`)
	gcsExpiresRe  = regexp.MustCompile(`X-Goog-Expires=(\d+)`)
	azureExpiryRe = regexp.MustCompile(`se=([^&]+)`)
	azurePermsRe  = regexp.MustCompile(`sp=([^&]+)`)
)

var writePermissions = map[signedURLType][]string{
	typeAWSPresigned: {"PUT", "DELETE", "POST"},
	typeGCSSigned:    {"PUT", "DELETE", "POST"},
	typeAzureSAS:     {"w", "d", "c", "a"},
}
