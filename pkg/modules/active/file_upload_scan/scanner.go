package file_upload_scan

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/pkg/errors"
)

type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		rhm: dedup.LazyDefaultRHM("file_upload_scan"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses custom CanProcess.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess returns true only for multipart/form-data requests with a filename.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}

	ct := strings.ToLower(ctx.Request().Header("Content-Type"))
	if !strings.Contains(ct, "multipart/form-data") {
		return false
	}

	// Check for filename in body
	body := ctx.Request().BodyToString()
	return strings.Contains(body, "filename=")
}

// ScanPerRequest tests file upload with various bypass probes.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	marker := generateMarker()
	probes := buildProbes(marker)

	for i, probe := range probes {
		modified, err := replaceFilePart(ctx.Request().Raw(), probe)
		if err != nil {
			continue
		}

		fuzzedReq, err := httpmsg.ParseRawRequest(string(modified))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		respStatus := 0
		respBody := ""
		if resp.Response() != nil {
			respStatus = resp.Response().StatusCode
			respBody = resp.FullResponse().String()
		}
		resp.Close()

		// Early abort on first probe: strict server validation
		if i == 0 && (respStatus == 400 || respStatus == 403 || respStatus == 415) {
			return results, nil
		}

		// Skip non-success responses
		if respStatus < 200 || respStatus >= 300 {
			continue
		}

		// Try to verify the uploaded file is accessible
		verified, verifyBody := m.verifyUpload(ctx, httpClient, respBody, probe, marker)

		sev := severity.High
		description := fmt.Sprintf("File upload accepted: %s (%s)", probe.name, probe.filename)
		confidence := severity.Firm

		if verified {
			description = fmt.Sprintf("File upload and execution confirmed: %s (%s)", probe.name, probe.filename)
			confidence = severity.Certain
		}

		results = append(results, &output.ResultEvent{
			URL:     urlx.String(),
			Request: string(modified),
			Response: func() string {
				if verified {
					return verifyBody
				}
				return respBody
			}(),
			FuzzingParameter: "file",
			ExtractedResults: []string{
				fmt.Sprintf("Probe: %s", probe.name),
				fmt.Sprintf("Filename: %s", probe.filename),
				fmt.Sprintf("Verified: %v", verified),
			},
			Info: output.Info{
				Name:        "Arbitrary File Upload",
				Description: description,
				Severity:    sev,
				Confidence:  confidence,
			},
		})

		return results, nil // One finding is enough
	}

	return results, nil
}

// verifyUpload attempts to access the uploaded file to confirm execution.
func (m *Module) verifyUpload(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	uploadResponse string,
	probe uploadProbe,
	marker string,
) (bool, string) {
	// Try to extract upload path from response
	uploadPath := extractUploadPath(uploadResponse)

	var pathsToTry []string
	if uploadPath != "" {
		pathsToTry = append(pathsToTry, uploadPath)
	}

	// Also try common upload directories
	for _, dir := range commonUploadDirs {
		pathsToTry = append(pathsToTry, dir+probe.filename)
	}

	for _, path := range pathsToTry {
		body, err := m.fetchPath(ctx, httpClient, path)
		if err != nil {
			continue
		}

		if strings.Contains(body, marker) {
			return true, body
		}
	}

	return false, ""
}

// fetchPath sends a GET request to the specified path.
func (m *Module) fetchPath(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path string,
) (string, error) {
	raw := ctx.Request().Raw()

	modified, err := httpmsg.SetPath(raw, path)
	if err != nil {
		return "", err
	}
	modified, err = httpmsg.SetMethod(modified, "GET")
	if err != nil {
		return "", err
	}
	// Remove Content-Type and body for GET request
	modified, err = httpmsg.ClearBody(modified)
	if err != nil {
		return "", err
	}

	getReq, err := httpmsg.ParseRawRequest(string(modified))
	if err != nil {
		return "", err
	}
	getReq = getReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(getReq, http.Options{})
	if err != nil {
		return "", err
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != 200 {
		return "", fmt.Errorf("non-200 response: %d", resp.Response().StatusCode)
	}

	return resp.FullResponse().String(), nil
}
