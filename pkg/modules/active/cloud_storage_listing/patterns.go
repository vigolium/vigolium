package cloud_storage_listing

import "strings"

type listingProbe struct {
	name    string
	path    string
	markers []string
}

var s3ListingProbes = []listingProbe{
	{
		name:    "S3 ListObjectsV2",
		path:    "/?list-type=2",
		markers: []string{"<ListBucketResult", "<Contents>", "<Key>"},
	},
}

var azureListingProbes = []listingProbe{
	{
		name:    "Azure Account Container List",
		path:    "/?comp=list",
		markers: []string{"<Containers>", "<Container>", "<Name>"},
	},
}

func isCloudStorageHost(host string) (isS3, isAzure bool) {
	h := strings.ToLower(host)
	if strings.Contains(h, ".s3") && strings.Contains(h, "amazonaws.com") {
		isS3 = true
	}
	if strings.Contains(h, "s3-website") && strings.Contains(h, "amazonaws.com") {
		isS3 = true
	}
	if strings.Contains(h, ".blob.core.windows.net") || strings.Contains(h, ".web.core.windows.net") {
		isAzure = true
	}
	return
}

func getAzureContainerFromPath(path string) string {
	path = strings.TrimPrefix(path, "/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) > 0 && parts[0] != "" && parts[0] != "$web" {
		return parts[0]
	}
	return ""
}

func bodyContainsAll(body string, markers []string) bool {
	for _, m := range markers {
		if !strings.Contains(body, m) {
			return false
		}
	}
	return true
}
