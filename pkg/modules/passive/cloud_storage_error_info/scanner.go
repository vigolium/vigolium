package cloud_storage_error_info

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("passive_cloud_storage_error_info"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	// Only process error responses (4xx, 5xx) or responses with cloud storage error indicators
	statusCode := ctx.Response().StatusCode()
	if statusCode >= 400 && statusCode < 600 {
		return true
	}
	// Also check for cloud storage error headers
	if ctx.Response().Header("x-ms-error-code") != "" {
		return true
	}
	if ctx.Response().Header("x-amz-request-id") != "" && statusCode != 200 {
		return true
	}
	return false
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	host := urlx.Host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if len(body) == 0 {
		return nil, nil
	}

	var evidence []string

	// Check S3 XML errors
	if strings.Contains(body, "<Error>") || strings.Contains(body, "<ListBucketResult") {
		evidence = append(evidence, extractS3Info(body)...)
	}

	// Check Azure errors
	azureErrorCode := ctx.Response().Header("x-ms-error-code")
	if azureErrorCode != "" {
		evidence = append(evidence, fmt.Sprintf("Azure Error Code: %s", azureErrorCode))
	}
	if strings.Contains(body, "<Error>") && ctx.Response().Header("x-ms-request-id") != "" {
		evidence = append(evidence, extractAzureInfo(body)...)
	}

	// Check GCS JSON errors
	if strings.Contains(body, `"error"`) && strings.Contains(body, "storage.googleapis.com") {
		evidence = append(evidence, extractGCSInfo(body)...)
	}

	if len(evidence) == 0 {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: evidence,
			Info: output.Info{
				Name:        "Cloud Storage Error Information Disclosure",
				Description: fmt.Sprintf("Cloud storage error response reveals %d piece(s) of internal information", len(evidence)),
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"cloud-storage", "information-disclosure", "error-message"},
			},
		},
	}, nil
}

func extractS3Info(body string) []string {
	var info []string

	if m := s3BucketNameRe.FindStringSubmatch(body); len(m) > 1 {
		info = append(info, fmt.Sprintf("S3 Bucket: %s", m[1]))
	}
	if m := s3RegionRe.FindStringSubmatch(body); len(m) > 1 {
		info = append(info, fmt.Sprintf("S3 Region: %s", m[1]))
	}
	if m := s3ErrorCodeRe.FindStringSubmatch(body); len(m) > 1 {
		desc := m[1]
		if detail, ok := s3ErrorCodes[m[1]]; ok {
			desc = fmt.Sprintf("%s (%s)", m[1], detail)
		}
		info = append(info, fmt.Sprintf("S3 Error: %s", desc))
	}
	if m := s3EndpointRe.FindStringSubmatch(body); len(m) > 1 {
		info = append(info, fmt.Sprintf("S3 Endpoint: %s", m[1]))
	}

	return info
}

func extractAzureInfo(body string) []string {
	var info []string

	if m := azureErrorCodeRe.FindStringSubmatch(body); len(m) > 1 {
		info = append(info, fmt.Sprintf("Azure XML Error: %s", m[1]))
	}
	if m := azureMessageRe.FindStringSubmatch(body); len(m) > 1 {
		info = append(info, fmt.Sprintf("Azure Message: %s", m[1]))
	}

	return info
}

func extractGCSInfo(body string) []string {
	var info []string

	if m := gcsErrorBucketRe.FindStringSubmatch(body); len(m) > 1 {
		info = append(info, fmt.Sprintf("GCS Bucket: %s", m[1]))
	}
	if m := gcsErrorCodeRe.FindStringSubmatch(body); len(m) > 1 {
		info = append(info, fmt.Sprintf("GCS Error Code: %s", m[1]))
	}
	if m := gcsErrorMsgRe.FindStringSubmatch(body); len(m) > 1 {
		info = append(info, fmt.Sprintf("GCS Message: %s", m[1]))
	}

	return info
}
