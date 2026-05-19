package infra

import (
	"fmt"
	"strings"
	"sync"

	httputil "github.com/projectdiscovery/utils/http"
)

var (
	ErrRateLimited       = fmt.Errorf("rate limited")
	ErrCloudflareCaptcha = fmt.Errorf("cloudflare captcha")
	ErrAkamaiIPBlocked   = fmt.Errorf("akamai IP address blocked")
	ErrCloudFrontError   = fmt.Errorf("amazon cloudfront error")
	ErrIncapsulaError    = fmt.Errorf("imperva incapsula error")
	ErrAwsElbError       = fmt.Errorf("aws elb error")
)

type BlockDetectionValidator struct{}

var (
	defaultValidator *BlockDetectionValidator
	blockDetectOnce  sync.Once
)

// GetBlockDetectionValidator returns the default BlockDetectionValidator instance (lazy loading)
func GetBlockDetectionValidator() *BlockDetectionValidator {
	blockDetectOnce.Do(func() {
		defaultValidator = &BlockDetectionValidator{}
	})
	return defaultValidator
}

func (v *BlockDetectionValidator) Validate(resp *httputil.ResponseChain) error {
	if v == nil || resp == nil {
		return nil
	}

	statusCode := resp.Response().StatusCode
	serverHeaderValue := resp.Response().Header.Get("Server")
	cdnHeaderValue := resp.Response().Header.Get("X-CDN")

	switch statusCode {
	case 429:
		return ErrRateLimited
	case 403:
		switch {
		case strings.HasPrefix(serverHeaderValue, "cloudflare"):
			return ErrCloudflareCaptcha
		case strings.HasPrefix(serverHeaderValue, "AkamaiGHost"):
			return ErrAkamaiIPBlocked
		case serverHeaderValue == "CloudFront":
			return ErrCloudFrontError
		case cdnHeaderValue == "Incapsula":
			return ErrIncapsulaError
		case strings.HasPrefix(serverHeaderValue, "awselb/"):
			return ErrAwsElbError
		}
	case 503:
		if strings.HasPrefix(serverHeaderValue, "cloudflare") {
			return ErrCloudflareCaptcha
		}
	}

	return nil
}
