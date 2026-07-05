package unauth_service_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "unauth-service-exposure"
	ModuleName  = "Unauthenticated Infrastructure Service Exposure"
	ModuleShort = "Detects unauthenticated Docker/Kubernetes/datastore APIs exposed over HTTP"
)

var (
	ModuleDesc = `**What it means:** An infrastructure service is reachable over HTTP without authentication and serves its native API: a Docker Engine/Registry, Kubernetes apiserver/kubelet, or a datastore (Elasticsearch, CouchDB, Solr). Each is confirmed by a unique structural signature, so a normal web host never matches.

**How it's exploited:** An unauthenticated Docker API is root-on-host; a kubelet lists and execs workloads; an open Elasticsearch/CouchDB/Solr lets an attacker dump or modify all stored data.

**Fix:** Require authentication/mTLS, bind to localhost or a private network, and firewall management ports.`

	ModuleConfirmation = "Confirmed when the target returns an unauthenticated 200 whose body/header carries the service's unique structural signature, re-verified with a second request"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"exposure", "infrastructure", "misconfiguration", "moderate"}
)
