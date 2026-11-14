// Package powerpages holds shared detection and probing helpers for the
// powerpages_* scanner family (Microsoft Power Pages / Power Apps portals, backed
// by the Dataverse Web API at /_api/<entityset>).
//
// The exposure class is an over-permissive Table Permission granting the
// Anonymous Users web role read access to a Dataverse table, combined with a
// wildcard (or over-broad) Web API column allow-list — so an unauthenticated
// caller can read CRM records (contacts, accounts, custom tables) over OData with
// a plain GET and no token. This package centralizes the fail-closed presence
// gate (DataverseAPIMounted, which doubles as the catch-all negative control) and
// the OData/Dataverse response classification the active module keys on.
package powerpages

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra/saasprobe"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// Tag / TagDataverse are the tech-stack tags published for Power Pages hosts.
// Adding "powerpages" to modkit.techTagCategories makes every module tagged
// "powerpages" auto-gate on the fingerprint's MarkTech.
const (
	Tag          = "powerpages"
	TagDataverse = "dataverse"
)

// VendorHostSuffixes are the default Power Pages / Power Apps portal hostnames.
// A host under one of these is Power Pages by definition (no probe needed).
var VendorHostSuffixes = []string{
	".powerappsportals.com",
	".powerappsportals.us", // US Government cloud
	".microsoftcrmportals.com",
	".dynamics365portals.com",
	".crm.dynamics.com",
}

// strongBodyMarkers are single-hit Power Pages proofs. Each is specific to the
// portals runtime / its bundled Web API AJAX wrapper and does not appear on
// unrelated ASP.NET stacks.
var strongBodyMarkers = []string{
	"Dynamics365PortalAnalytics",
	"shell.getTokenDeferred",
	"webapi.safeAjax",
	"powerappsportals.com",
	"MsdynMkt", // Dynamics marketing tracking present on many portals
}

// mediumBodyMarkers are weaker on their own (a stray anti-forgery field or an
// adx_ reference could be echoed by a proxy), so Power Pages is only inferred
// from the body when at least two co-occur.
var mediumBodyMarkers = []string{
	"__RequestVerificationToken", // ASP.NET anti-forgery — common, not unique
	"/_layout/",
	"adx_",
	"msdyn_",
	"portal/customer-service",
}

// MatchResponse reports whether a response looks like Power Pages and which
// signals fired. setCookies is the newline-joined Set-Cookie names; body is the
// response body. ok is true on any strong signal, or at least two medium signals.
// Used by the passive fingerprint; the active module gates on the /_api/
// behavioral probe (DataverseAPIMounted), not on these markers.
func MatchResponse(setCookies, body string) (ok bool, signals []string) {
	sc := strings.ToLower(setCookies)
	strong := false

	if strings.Contains(sc, "dynamics365portalanalytics") {
		strong = true
		signals = append(signals, "cookie: Dynamics365PortalAnalytics")
	}

	mediumHits := 0
	if strings.Contains(sc, "arraffinity") {
		mediumHits++
		signals = append(signals, "cookie: ARRAffinity (Azure App Service)")
	}
	if strings.Contains(sc, "timezonecode") || strings.Contains(sc, "isdstsupport") || strings.Contains(sc, "isdstobserved") {
		mediumHits++
		signals = append(signals, "Power Pages locale cookie")
	}

	for _, m := range strongBodyMarkers {
		if strings.Contains(body, m) {
			strong = true
			signals = append(signals, "body marker: "+m)
		}
	}
	for _, m := range mediumBodyMarkers {
		if strings.Contains(body, m) {
			mediumHits++
			signals = append(signals, "body marker: "+m)
		}
	}

	return strong || mediumHits >= 2, signals
}

// DataverseAPIMounted probes /_api/<bogus-entity-set> and reports whether the
// response is a Dataverse OData error envelope for a non-existent resource. It is
// the active module's fail-closed presence gate AND its catch-all negative
// control in one probe: a real portal answers a bogus table with a JSON "resource
// not found" error (404), whereas a non-portal site returns HTML or a 200
// catch-all. A 200 with data for a bogus table means the endpoint is NOT a
// discriminating Dataverse API, so this returns false (fail closed).
func DataverseAPIMounted(ctx *httpmsg.HttpRequestResponse, client *http.Requester) bool {
	res := saasprobe.Get(ctx, client, "/_api/"+bogusEntitySet, nil)
	if !res.OK {
		return false
	}
	// A discriminating Dataverse API rejects an unknown entity set with a JSON
	// "not found" error (typically 404). Anything that returns records for a name
	// that cannot exist is a catch-all, not a real API.
	if res.Status == 200 {
		if list, ok := parseODataList(res.Body); ok && len(list.Value) > 0 {
			return false
		}
	}
	return isDataverseNotFound(res)
}

// MarkPowerPages records Power Pages in the tech registry for host.
func MarkPowerPages(sc *modkit.ScanContext, host string) {
	if sc == nil || host == "" {
		return
	}
	sc.MarkTech(host, Tag)
	sc.MarkTech(host, TagDataverse)
	sc.MarkTech(host, "aspnet")
}
