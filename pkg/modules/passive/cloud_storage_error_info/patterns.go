package cloud_storage_error_info

import "regexp"

var (
	s3BucketNameRe = regexp.MustCompile(`<BucketName>([^<]+)</BucketName>`)
	s3RegionRe     = regexp.MustCompile(`<Region>([^<]+)</Region>`)
	s3ErrorCodeRe  = regexp.MustCompile(`<Code>([^<]+)</Code>`)
	s3EndpointRe   = regexp.MustCompile(`<Endpoint>([^<]+)</Endpoint>`)

	azureErrorCodeRe = regexp.MustCompile(`<Code>([^<]+)</Code>`)
	azureMessageRe   = regexp.MustCompile(`<Message>([^<]+)</Message>`)

	gcsErrorBucketRe = regexp.MustCompile(`"bucket"\s*:\s*"([^"]+)"`)
	gcsErrorCodeRe   = regexp.MustCompile(`"code"\s*:\s*(\d+)`)
	gcsErrorMsgRe    = regexp.MustCompile(`"message"\s*:\s*"([^"]+)"`)
)

var s3ErrorCodes = map[string]string{
	"NoSuchBucket":      "Bucket does not exist (takeover candidate)",
	"AccessDenied":      "Bucket exists but access is denied",
	"PermanentRedirect": "Bucket exists in a different region",
	"NoSuchKey":         "Object does not exist in bucket",
	"AllAccessDisabled": "All public access is blocked",
}
