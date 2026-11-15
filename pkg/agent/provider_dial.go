package agent

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/olium"
	"github.com/vigolium/vigolium/pkg/olium/provider"
)

// ProviderDialTimeout bounds the reachability dial. It is a TCP connect, not
// a model call: two seconds is generous for one round trip.
const ProviderDialTimeout = 2 * time.Second

// ProviderDialCheck dials the configured provider's endpoint (or the proxy a
// request to it would use) once, so a refused or unresolvable provider is
// reported at once as provider_unreachable instead of being retried until
// the run's deadline. It sends no request and needs no credentials; a
// provider without an HTTP endpoint (a CLI subprocess), or one that cannot be
// built from the configuration, is left to the later steps to report.
func ProviderDialCheck(ctx context.Context, cfg *config.OliumConfig) error {
	if cfg == nil {
		return nil
	}
	extraBody, _ := cfg.CustomProvider.EffectiveExtraBody()
	prov, name, _, err := olium.ResolveProvider(olium.Options{
		Provider:            cfg.Provider,
		OAuthCredPath:       cfg.OAuthCredPath,
		OAuthToken:          cfg.OAuthToken,
		LLMAPIKey:           cfg.LLMAPIKey,
		GoogleCloudProject:  cfg.GoogleCloudProject,
		GoogleCloudLocation: cfg.GoogleCloudLocation,
		Model:               cfg.Model,
		CustomBaseURL:       cfg.CustomProvider.BaseURL,
		CustomModelID:       cfg.CustomProvider.ModelID,
		CustomAPIKey:        firstNonEmpty(cfg.CustomProvider.APIKey, cfg.LLMAPIKey),
		CustomExtraHeaders:  cfg.CustomProvider.ExtraHeadersMap(),
		CustomExtraBody:     extraBody,
	})
	if err != nil || prov == nil {
		return nil
	}
	ep, ok := prov.(provider.Endpointer)
	if !ok || ep.Endpoint() == "" {
		return nil
	}
	return dialEndpoint(ctx, name, ep.Endpoint(), ProviderDialTimeout)
}

// dialEndpoint connects to the host:port a request to rawURL would reach
// first — the environment's proxy for that scheme when one applies.
func dialEndpoint(ctx context.Context, providerName, rawURL string, timeout time.Duration) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil
	}
	target := u
	if req, rerr := http.NewRequest(http.MethodPost, rawURL, nil); rerr == nil {
		if proxyURL, perr := http.ProxyFromEnvironment(req); perr == nil && proxyURL != nil {
			target = proxyURL
		}
	}
	host := target.Hostname()
	port := target.Port()
	if port == "" {
		port = "443"
		if target.Scheme == "http" {
			port = "80"
		}
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		via := ""
		if target != u {
			via = " via proxy " + target.Host
		}
		return &PreflightError{code: apicontract.CodeProviderUnreachable,
			err: fmt.Errorf("AI provider %q is unreachable at %s%s: %w (check agent.olium.custom_provider.base_url / the provider's network, or pick another with --provider)",
				providerName, u.Host, via, err)}
	}
	_ = conn.Close()
	return nil
}
