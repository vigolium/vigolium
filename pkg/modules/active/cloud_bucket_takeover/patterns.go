package cloud_bucket_takeover

import (
	"encoding/json"
	"encoding/xml"
	"strings"
)

const (
	providerAWS   = "AWS S3"
	providerGCS   = "Google Cloud Storage"
	providerAzure = "Azure Blob Storage"
)

type takeoverSignature struct {
	name     string
	provider string
}

func cloudProviderForHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	switch {
	case strings.Contains(host, ".s3") && strings.HasSuffix(host, ".amazonaws.com"):
		return providerAWS
	case strings.HasSuffix(host, ".storage.googleapis.com") && host != "storage.googleapis.com":
		return providerGCS
	case strings.HasSuffix(host, ".blob.core.windows.net"), strings.HasSuffix(host, ".web.core.windows.net"):
		return providerAzure
	default:
		return ""
	}
}

func isCloudStorageHost(host string) bool { return cloudProviderForHost(host) != "" }

// matchCloudNotFound accepts only provider-bound, structured resource-level
// errors. A generic {code:404,message:not found}, missing blob/object, or a
// provider marker on an unrelated host is not bucket/container claimability.
func matchCloudNotFound(provider string, status int, body string) (takeoverSignature, bool) {
	if status != 404 {
		return takeoverSignature{}, false
	}
	switch provider {
	case providerAWS:
		code, message := parseXMLError(body)
		if code == "NoSuchBucket" && strings.Contains(strings.ToLower(message), "bucket") && strings.Contains(strings.ToLower(message), "does not exist") {
			return takeoverSignature{name: "S3 NoSuchBucket", provider: providerAWS}, true
		}
	case providerGCS:
		var response struct {
			Error struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal([]byte(body), &response) == nil && response.Error.Code == 404 {
			message := strings.ToLower(response.Error.Message)
			if strings.Contains(message, "bucket") && strings.Contains(message, "does not exist") {
				return takeoverSignature{name: "GCS bucket-not-found", provider: providerGCS}, true
			}
		}
		code, message := parseXMLError(body)
		if code == "NoSuchBucket" && strings.Contains(strings.ToLower(message), "bucket") {
			return takeoverSignature{name: "GCS NoSuchBucket", provider: providerGCS}, true
		}
	case providerAzure:
		code, message := parseXMLError(body)
		if code == "ContainerNotFound" && strings.Contains(strings.ToLower(message), "container") && strings.Contains(strings.ToLower(message), "does not exist") {
			return takeoverSignature{name: "Azure ContainerNotFound", provider: providerAzure}, true
		}
	}
	return takeoverSignature{}, false
}

func parseXMLError(body string) (code, message string) {
	var response struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
		Message string   `xml:"Message"`
	}
	if xml.Unmarshal([]byte(strings.TrimSpace(body)), &response) != nil || response.XMLName.Local != "Error" {
		return "", ""
	}
	return strings.TrimSpace(response.Code), strings.TrimSpace(response.Message)
}
