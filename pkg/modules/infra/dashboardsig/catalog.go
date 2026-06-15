package dashboardsig

import "github.com/vigolium/vigolium/pkg/types/severity"

// Catalog is the master list of detectable third-party dashboards / consoles /
// self-hosted products. Markers are lowercase (see package doc). Confirmers
// flagged Primary are probed at normal intensity; the rest only at --intensity
// deep. UnauthLeak confirmers escalate the finding to High when reachable
// without authentication.
var Catalog = []Product{
	// ─────────────────────────── Observability / metrics ───────────────────────────
	{
		ID: "grafana", Name: "Grafana", Category: CatObservability,
		Tags:        []string{"grafana", "observability", "dashboard"},
		Ref:         "https://grafana.com",
		Cookies:     []string{"grafana_session"},
		BodyMarkers: [][]string{{"grafanabootdata", "grafana-app", "<title>grafana"}},
		Mounts:      []string{"/grafana"},
		Confirmers: []Confirmer{
			{Path: "/api/health", Markers: [][]string{{`"database"`}, {`"version"`}},
				Primary: true, UnauthLeak: true, LeakName: "version + database status",
				VersionRe: `"version"\s*:\s*"([^"]+)"`},
		},
		Login: &LoginProbe{
			Paths:       []string{"/login"},
			ContentType: "application/json",
			Body:        `{"user":"{{user}}","password":"{{pass}}"}`,
			Creds:       [][2]string{{"admin", "admin"}, {"admin", "prom-operator"}},
			Success: LoginSuccess{
				Status:       []int{200},
				Headers:      []HeaderSig{{Name: "Set-Cookie", Contains: "grafana_session"}},
				BodyContains: []string{"logged in"},
			},
		},
	},
	{
		ID: "kibana", Name: "Kibana", Category: CatObservability,
		Tags:          []string{"kibana", "elastic", "observability", "dashboard"},
		Ref:           "https://www.elastic.co/kibana",
		Headers:       []HeaderSig{{Name: "kbn-name"}, {Name: "kbn-version"}},
		VersionHeader: "kbn-version",
		BodyMarkers:   [][]string{{"<title>kibana", "kbn-injected-metadata", "kibanawelcomeview"}},
		Confirmers: []Confirmer{
			{Path: "/api/status", Markers: [][]string{{`"version"`}, {`"status"`}},
				Primary: true, UnauthLeak: true, LeakName: "version + plugin status",
				VersionRe: `"number"\s*:\s*"([^"]+)"`},
		},
	},
	{
		ID: "elasticsearch", Name: "Elasticsearch", Category: CatData,
		Tags:        []string{"elasticsearch", "elastic", "datastore", "dashboard"},
		Ref:         "https://www.elastic.co/elasticsearch",
		BodyMarkers: [][]string{{"you know, for search"}}, // also recognised passively if the JSON root is crawled
		Confirmers: []Confirmer{
			{Path: "/", Markers: [][]string{{"you know, for search"}},
				Primary: true, UnauthLeak: true, LeakName: "cluster name + version",
				VersionRe: `"number"\s*:\s*"([^"]+)"`},
			{Path: "/_cluster/health", Markers: [][]string{{"cluster_name"}, {`"status"`, "number_of_nodes"}},
				UnauthLeak: true, LeakName: "cluster health"},
			{Path: "/_cat/indices?format=json", Markers: [][]string{{"docs.count", `"uuid"`}, {`"health"`, `"index"`}},
				UnauthLeak: true, LeakName: "index listing"},
		},
	},
	{
		ID: "prometheus", Name: "Prometheus", Category: CatObservability,
		Tags:        []string{"prometheus", "observability", "metrics", "dashboard"},
		Ref:         "https://prometheus.io",
		BodyMarkers: [][]string{{"<title>prometheus"}},
		Confirmers: []Confirmer{
			{Path: "/api/v1/status/buildinfo", Markers: [][]string{{`"version"`}, {`"status":"success"`}},
				Primary: true, UnauthLeak: true, LeakName: "build info",
				VersionRe: `"version"\s*:\s*"([^"]+)"`},
			{Path: "/api/v1/status/config", Markers: [][]string{{`"yaml"`}, {`"status":"success"`}},
				UnauthLeak: true, LeakName: "full scrape configuration"},
		},
	},

	{
		ID: "airflow", Name: "Apache Airflow", Category: CatData,
		Tags: []string{"airflow", "workflow", "data", "dashboard"},
		Ref:  "https://airflow.apache.org",
		// Anchored to the Airflow UI shell (title / FAB asset mount / JS namespace),
		// not the prose phrase "apache airflow" that any blog about it contains.
		BodyMarkers: [][]string{{"<title>airflow", "airflow.www", "/static/appbuilder"}},
		Mounts:      []string{"/airflow"},
		Confirmers: []Confirmer{
			{Path: "/health", Markers: [][]string{{"metadatabase"}, {"scheduler"}},
				Primary: true, UnauthLeak: true, LeakName: "scheduler/metadatabase health"},
			{Path: "/api/v1/version", Markers: [][]string{{`"version"`}, {"git_version"}},
				UnauthLeak: true, LeakName: "version (anonymous API)",
				VersionRe: `"version"\s*:\s*"([^"]+)"`},
		},
	},
	{
		ID: "alertmanager", Name: "Prometheus Alertmanager", Category: CatObservability,
		Tags:        []string{"alertmanager", "prometheus", "observability", "dashboard"},
		Ref:         "https://prometheus.io/docs/alerting/latest/alertmanager/",
		BodyMarkers: [][]string{{"<title>alertmanager"}},
		Confirmers: []Confirmer{
			{Path: "/api/v2/status", Markers: [][]string{{"versioninfo"}, {"uptime", "cluster"}},
				Primary: true, UnauthLeak: true, LeakName: "version + config + cluster peers",
				VersionRe: `"version"\s*:\s*"([^"]+)"`},
		},
	},
	{
		ID: "jaeger", Name: "Jaeger", Category: CatObservability,
		Tags:        []string{"jaeger", "tracing", "observability", "dashboard"},
		Ref:         "https://www.jaegertracing.io",
		BodyMarkers: [][]string{{"<title>jaeger ui", "jaeger ui"}},
		Mounts:      []string{"/jaeger"},
		Confirmers: []Confirmer{
			{Path: "/api/services", Markers: [][]string{{`"data"`}, {`"total"`, `"errors"`}},
				Primary: true, UnauthLeak: true, LeakName: "instrumented service list"},
		},
	},
	{
		ID: "zipkin", Name: "Zipkin", Category: CatObservability,
		Tags:        []string{"zipkin", "tracing", "observability", "dashboard"},
		Ref:         "https://zipkin.io",
		BodyMarkers: [][]string{{"<title>zipkin"}},
		Mounts:      []string{"/zipkin"},
		Confirmers: []Confirmer{
			{Path: "/config.json", Markers: [][]string{{"querylimit"}, {"defaultlookback", "instrumented"}},
				Primary: true, UnauthLeak: true, LeakName: "UI configuration"},
		},
	},
	{
		ID: "influxdb", Name: "InfluxDB", Category: CatObservability,
		Tags:          []string{"influxdb", "tsdb", "observability", "dashboard"},
		Ref:           "https://www.influxdata.com",
		Headers:       []HeaderSig{{Name: "X-Influxdb-Version"}, {Name: "X-Influxdb-Build"}},
		VersionHeader: "X-Influxdb-Version",
		BodyMarkers:   [][]string{{"<title>influxdb"}},
		Confirmers: []Confirmer{
			{Path: "/ping", OKStatus: []int{200, 204}, HeaderName: "X-Influxdb-Version",
				Primary: true, UnauthLeak: true, LeakName: "version (X-Influxdb-Version header)"},
			{Path: "/health", Markers: [][]string{{"influxdb"}, {`"status"`, `"version"`}},
				UnauthLeak: true, LeakName: "version + status",
				VersionRe: `"version"\s*:\s*"([^"]+)"`},
		},
	},
	{
		ID: "netdata", Name: "Netdata", Category: CatObservability,
		Tags:        []string{"netdata", "observability", "metrics", "dashboard"},
		Ref:         "https://www.netdata.cloud",
		Headers:     []HeaderSig{{Name: "Server", Contains: "netdata"}},
		BodyMarkers: [][]string{{"<title>netdata"}},
		Confirmers: []Confirmer{
			{Path: "/api/v1/info", Markers: [][]string{{`"version"`}, {"os_name", "mirrored_hosts", "hostname"}},
				Primary: true, UnauthLeak: true, LeakName: "host info (version, OS, hostname, mirrored hosts)",
				VersionRe: `"version"\s*:\s*"([^"]+)"`},
		},
	},
	{
		ID: "cadvisor", Name: "cAdvisor", Category: CatObservability,
		Tags:        []string{"cadvisor", "containers", "observability", "dashboard"},
		Ref:         "https://github.com/google/cadvisor",
		BodyMarkers: [][]string{{"<title>cadvisor"}},
		Confirmers: []Confirmer{
			{Path: "/api/v1.3/machine", Markers: [][]string{{"num_cores"}, {"memory_capacity", "machine_id"}},
				Primary: true, UnauthLeak: true, LeakName: "machine spec + container topology"},
		},
	},
	{
		ID: "loki", Name: "Grafana Loki", Category: CatObservability,
		Tags: []string{"loki", "grafana", "logs", "observability", "dashboard"},
		Ref:  "https://grafana.com/oss/loki/",
		Confirmers: []Confirmer{
			{Path: "/loki/api/v1/labels", Markers: [][]string{{`"status":"success"`, `"status": "success"`}, {`"data"`}},
				Primary: true, UnauthLeak: true, LeakName: "log label list"},
		},
	},
	{
		ID: "uptime-kuma", Name: "Uptime Kuma", Category: CatObservability,
		Tags:        []string{"uptime-kuma", "monitoring", "observability", "dashboard"},
		Ref:         "https://github.com/louislam/uptime-kuma",
		BodyMarkers: [][]string{{"uptime kuma", "<title>uptime kuma"}},
		// Passive-only: recognised from its UI markers in crawled traffic; no
		// unauthenticated API endpoint worth an active probe.
	},

	// ─────────────────────────── CI/CD & dev platforms ───────────────────────────
	{
		ID: "gitlab", Name: "GitLab", Category: CatCICD,
		Tags: []string{"gitlab", "ci-cd", "scm", "dashboard"},
		Ref:  "https://gitlab.com",
		// "gitlab" mentioned AND a GitLab-route-specific structural marker. The
		// old group-2 included og:site_name (a generic OpenGraph tag on every
		// blog) and gon. (a substring of words like "dragon."), which combined
		// with a prose "gitlab" mention false-positived on engineering blogs.
		BodyMarkers: [][]string{{"gitlab"}, {"/-/manifest.json", "data-page=\"sessions"}},
		Confirmers: []Confirmer{
			// Presence (sign-in page, UI markers) is handled passively; the active
			// probe targets only the anonymous version-leak API.
			{Path: "/api/v4/version", Markers: [][]string{{`"version"`}, {`"revision"`}},
				Primary: true, UnauthLeak: true, LeakName: "version (anonymous API)",
				VersionRe: `"version"\s*:\s*"([^"]+)"`},
		},
		Login: &LoginProbe{
			Paths:       []string{"/oauth/token"},
			ContentType: "application/json",
			Body:        `{"grant_type":"password","username":"{{user}}","password":"{{pass}}"}`,
			Creds: [][2]string{
				{"root", "5iveL!fe"}, {"root", "123456789"},
				{"admin", "5iveL!fe"}, {"admin@local.host", "5iveL!fe"},
			},
			Success: LoginSuccess{
				Status:       []int{200},
				Headers:      []HeaderSig{{Name: "Content-Type", Contains: "application/json"}},
				BodyContains: []string{`"access_token"`, `"token_type"`, `"refresh_token"`},
			},
		},
		PresenceSev: severity.Low,
	},
	{
		ID: "jenkins", Name: "Jenkins", Category: CatCICD,
		Tags:          []string{"jenkins", "ci-cd", "dashboard"},
		Ref:           "https://www.jenkins.io",
		Headers:       []HeaderSig{{Name: "X-Jenkins"}, {Name: "X-Jenkins-Session"}},
		VersionHeader: "X-Jenkins",
		BodyMarkers:   [][]string{{"jenkins"}, {"dashboard [jenkins]", "j_username", "/static/", "login?from"}},
		Confirmers: []Confirmer{
			// Presence (login page, X-Jenkins header, UI markers) is handled
			// passively; the active probe targets only the anonymous-read API.
			{Path: "/api/json", Markers: [][]string{{`"jobs"`, `"views"`}, {"nodedescription", "assignedlabels", `"_class"`}},
				Primary: true, UnauthLeak: true, LeakName: "jobs/nodes (anonymous read)"},
		},
		PresenceSev: severity.Low,
	},
	{
		ID: "argocd", Name: "Argo CD", Category: CatCICD,
		Tags:        []string{"argocd", "ci-cd", "kubernetes", "dashboard"},
		Ref:         "https://argo-cd.readthedocs.io",
		BodyMarkers: [][]string{{"argocd", "argo cd", "<title>argo cd"}},
		Confirmers: []Confirmer{
			{Path: "/api/version", Markers: [][]string{{`"version"`}},
				Primary: true, UnauthLeak: true, LeakName: "version + build info",
				VersionRe: `"[Vv]ersion"\s*:\s*"([^"]+)"`},
		},
	},
	{
		ID: "sonarqube", Name: "SonarQube", Category: CatCICD,
		Tags:        []string{"sonarqube", "ci-cd", "code-quality", "dashboard"},
		Ref:         "https://www.sonarqube.org",
		BodyMarkers: [][]string{{"<title>sonarqube", "sonarqube"}},
		Confirmers: []Confirmer{
			{Path: "/api/server/version", BodyRe: `^\s*\d+\.\d+(\.\d+)+`,
				Primary: true, UnauthLeak: true, LeakName: "server version",
				VersionRe: `(\d+\.\d+(?:\.\d+)+)`},
			{Path: "/api/system/status", Markers: [][]string{{`"status"`}, {`"version"`, `"id"`}},
				UnauthLeak: true, LeakName: "system status + version"},
		},
		Login: &LoginProbe{
			Paths:       []string{"/api/authentication/login"},
			ContentType: "application/x-www-form-urlencoded",
			Body:        "login={{user}}&password={{pass}}",
			Creds:       [][2]string{{"admin", "admin"}, {"sonar", "sonar"}},
			Success: LoginSuccess{
				Status:    []int{200},
				EmptyBody: true,
				Headers:   []HeaderSig{{Name: "Set-Cookie", Contains: "jwt-session="}},
			},
		},
	},
	{
		ID: "nexus", Name: "Sonatype Nexus Repository", Category: CatCICD,
		Tags:        []string{"nexus", "ci-cd", "artifact-registry", "dashboard"},
		Ref:         "https://www.sonatype.com/products/nexus-repository",
		BodyMarkers: [][]string{{"nexus repository", "<title>nexus"}},
		// Passive-only: recognised from its UI markers in crawled traffic.
	},
	{
		ID: "artifactory", Name: "JFrog Artifactory", Category: CatCICD,
		Tags:    []string{"artifactory", "jfrog", "ci-cd", "artifact-registry", "dashboard"},
		Ref:     "https://jfrog.com/artifactory",
		Headers: []HeaderSig{{Name: "X-Artifactory-Id"}, {Name: "X-Artifactory-Node-Id"}},
		Confirmers: []Confirmer{
			{Path: "/artifactory/api/system/ping", BodyRe: `(?i)^\s*ok`, Primary: true, LeakName: "system ping"},
			{Path: "/artifactory/api/system/version", Markers: [][]string{{`"version"`}},
				UnauthLeak: true, LeakName: "version + license",
				VersionRe: `"version"\s*:\s*"([^"]+)"`},
		},
	},

	// ─────────────────────────── Infra / orchestration ───────────────────────────
	{
		ID: "vault", Name: "HashiCorp Vault", Category: CatInfra,
		Tags: []string{"vault", "hashicorp", "secrets", "dashboard"},
		Ref:  "https://www.vaultproject.io",
		Confirmers: []Confirmer{
			{Path: "/v1/sys/health", Markers: [][]string{{`"sealed"`}, {`"version"`}},
				Primary: true, UnauthLeak: true, LeakName: "seal status + version",
				VersionRe: `"version"\s*:\s*"([^"]+)"`},
			{Path: "/v1/sys/seal-status", Markers: [][]string{{`"sealed"`}, {`"type"`, `"t"`}},
				UnauthLeak: true, LeakName: "seal status"},
		},
	},
	{
		ID: "consul", Name: "HashiCorp Consul", Category: CatInfra,
		Tags: []string{"consul", "hashicorp", "service-mesh", "dashboard"},
		Ref:  "https://www.consul.io",
		// Anchored to the Consul web UI shell, not the bare word "consul" (a
		// common English/infra term that matches any blog mentioning it).
		BodyMarkers: [][]string{{"<title>consul by hashicorp", "consul-ui/"}},
		Confirmers: []Confirmer{
			{Path: "/v1/status/leader", BodyRe: `^\s*"?\d{1,3}(\.\d{1,3}){3}:\d+"?`,
				Primary: true, UnauthLeak: true, LeakName: "raft leader address"},
			{Path: "/v1/agent/self", Markers: [][]string{{`"config"`}, {"datacenter", `"member"`}},
				UnauthLeak: true, LeakName: "full agent configuration"},
		},
	},
	{
		ID: "traefik", Name: "Traefik", Category: CatInfra,
		Tags:        []string{"traefik", "proxy", "ingress", "dashboard"},
		Ref:         "https://traefik.io",
		BodyMarkers: [][]string{{"<title>traefik"}},
		Mounts:      []string{"/dashboard"},
		Confirmers: []Confirmer{
			{Path: "/api/version", Markers: [][]string{{`"version"`}},
				Primary: true, UnauthLeak: true, LeakName: "version",
				VersionRe: `"[Vv]ersion"\s*:\s*"([^"]+)"`},
			{Path: "/api/rawdata", Markers: [][]string{{`"routers"`}, {`"services"`}},
				UnauthLeak: true, LeakName: "full routing configuration"},
		},
	},
	{
		ID: "portainer", Name: "Portainer", Category: CatInfra,
		Tags:        []string{"portainer", "docker", "kubernetes", "dashboard"},
		Ref:         "https://www.portainer.io",
		BodyMarkers: [][]string{{"<title>portainer", "portainer"}},
		Confirmers: []Confirmer{
			{Path: "/api/status", Markers: [][]string{{`"version"`}},
				Primary: true, UnauthLeak: true, LeakName: "version + instance ID",
				VersionRe: `"Version"\s*:\s*"([^"]+)"`},
			{Path: "/api/system/status", Markers: [][]string{{`"version"`}},
				UnauthLeak: true, LeakName: "version"},
		},
	},
	{
		ID: "rabbitmq", Name: "RabbitMQ Management", Category: CatInfra,
		Tags:        []string{"rabbitmq", "messaging", "dashboard"},
		Ref:         "https://www.rabbitmq.com/management.html",
		BodyMarkers: [][]string{{"rabbitmq management", "<title>rabbitmq"}},
		Confirmers: []Confirmer{
			// Presence handled passively; active probe targets the overview API.
			{Path: "/api/overview", Markers: [][]string{{"rabbitmq_version", "management_version"}},
				Primary: true, UnauthLeak: true, LeakName: "cluster overview (weak/default credentials?)"},
		},
		Login: &LoginProbe{
			Paths:     []string{"/api/whoami"},
			Method:    "GET",
			BasicAuth: true,
			Creds:     [][2]string{{"guest", "guest"}},
			Success: LoginSuccess{
				Status:       []int{200},
				Headers:      []HeaderSig{{Name: "Content-Type", Contains: "application/json"}},
				BodyContains: []string{`"name":"guest"`},
			},
		},
	},
	{
		ID: "keycloak", Name: "Keycloak", Category: CatInfra,
		Tags:   []string{"keycloak", "iam", "sso", "dashboard"},
		Ref:    "https://www.keycloak.org",
		Mounts: []string{"/auth"},
		Confirmers: []Confirmer{
			// /realms/master is public by design — report as inventory (INFO), not a leak.
			{Path: "/realms/master", Markers: [][]string{{`"realm"`}, {"token-service", "public_key", "account-service"}},
				Primary: true, LeakName: "realm metadata"},
		},
	},

	// ─────────────────────────── Data / DB consoles ───────────────────────────
	{
		ID: "phpmyadmin", Name: "phpMyAdmin", Category: CatData,
		Tags:        []string{"phpmyadmin", "database", "console", "dashboard"},
		Ref:         "https://www.phpmyadmin.net",
		Cookies:     []string{"phpmyadmin", "pmasid", "pma_lang"},
		BodyMarkers: [][]string{{"phpmyadmin"}, {"pma_username", "pma_password", "input_username", "pmahomme"}},
		// Passive-only: file/path discovery surfaces /phpmyadmin/ and passive
		// fingerprints it (markers + pma_* cookies); no data endpoint to probe.
	},
	{
		ID: "adminer", Name: "Adminer", Category: CatData,
		Tags:        []string{"adminer", "database", "console", "dashboard"},
		Ref:         "https://www.adminer.org",
		BodyMarkers: [][]string{{"adminer"}, {"login - adminer", "class=\"version\"", "db driver"}},
		VersionRe:   `(?i)adminer\s+([\d.]+)`,
		// Passive-only: file/path discovery surfaces /adminer.php and passive
		// fingerprints it (markers + version).
	},
	{
		ID: "minio", Name: "MinIO", Category: CatData,
		Tags:        []string{"minio", "object-storage", "s3", "dashboard"},
		Ref:         "https://min.io",
		Headers:     []HeaderSig{{Name: "Server", Contains: "minio"}},
		BodyMarkers: [][]string{{"minio console", "<title>minio"}},
		Confirmers: []Confirmer{
			{Path: "/minio/health/live", OKStatus: []int{200}, HeaderName: "Server", HeaderContains: "minio",
				Primary: true, LeakName: "object-storage endpoint"},
			{Path: "/minio/health/cluster", OKStatus: []int{200}, HeaderName: "Server", HeaderContains: "minio",
				LeakName: "cluster health endpoint"},
		},
		Login: &LoginProbe{
			Paths:       []string{"/minio/webrpc"},
			ContentType: "application/json",
			Body:        `{"id":1,"jsonrpc":"2.0","params":{"username":"{{user}}","password":"{{pass}}"},"method":"Web.Login"}`,
			Creds:       [][2]string{{"minioadmin", "minioadmin"}},
			Success: LoginSuccess{
				Status:       []int{200},
				Headers:      []HeaderSig{{Name: "Content-Type", Contains: "application/json"}},
				BodyContains: []string{`"token"`, `"uiversion"`},
			},
		},
	},

	// ─────────────────────────── AI / LLM ───────────────────────────
	{
		ID: "ollama", Name: "Ollama", Category: CatAI,
		Tags:        []string{"ollama", "ai", "llm", "dashboard"},
		Ref:         "https://ollama.com",
		BodyMarkers: [][]string{{"ollama is running"}},
		Confirmers: []Confirmer{
			{Path: "/api/tags", Markers: [][]string{{`"models"`}, {`"name"`, `"model"`, `"modified_at"`}},
				Primary: true, UnauthLeak: true, LeakName: "installed model list"},
			{Path: "/api/version", Markers: [][]string{{`"version"`}},
				UnauthLeak: true, LeakName: "version", VersionRe: `"version"\s*:\s*"([^"]+)"`},
			// The "Ollama is running" root banner is handled passively (BodyMarkers).
		},
	},
	{
		ID: "llm-openai-api", Name: "LLM Inference API (OpenAI-compatible)", Category: CatAI,
		Tags: []string{"llm", "ai", "openai-compatible", "dashboard"},
		Ref:  "https://platform.openai.com/docs/api-reference/models",
		Confirmers: []Confirmer{
			{Path: "/v1/models", Markers: [][]string{{`"object":"list"`, `"object": "list"`}, {`"owned_by"`, `"id"`}},
				Primary: true, UnauthLeak: true, LeakName: "served model list (no API key)", LeakSev: severity.High},
		},
	},
	{
		ID: "vllm", Name: "vLLM", Category: CatAI,
		Tags: []string{"vllm", "ai", "llm", "dashboard"},
		Ref:  "https://github.com/vllm-project/vllm",
		Confirmers: []Confirmer{
			{Path: "/version", Markers: [][]string{{`"version"`}},
				Primary: true, UnauthLeak: true, LeakName: "version", VersionRe: `"version"\s*:\s*"([^"]+)"`},
		},
	},
	{
		ID: "litellm", Name: "LiteLLM Proxy", Category: CatAI,
		Tags:        []string{"litellm", "ai", "llm-proxy", "dashboard"},
		Ref:         "https://docs.litellm.ai",
		BodyMarkers: [][]string{{"litellm"}},
		Confirmers: []Confirmer{
			{Path: "/health/liveliness", BodyRe: `(?i)alive`, Primary: true, LeakName: "liveness endpoint"},
			{Path: "/model/info", Markers: [][]string{{`"data"`}, {"model_name", "litellm_params"}},
				UnauthLeak: true, LeakName: "model + provider configuration"},
		},
	},
	{
		ID: "tgi", Name: "Text Generation Inference", Category: CatAI,
		Tags: []string{"tgi", "huggingface", "ai", "llm", "dashboard"},
		Ref:  "https://github.com/huggingface/text-generation-inference",
		Confirmers: []Confirmer{
			{Path: "/info", Markers: [][]string{{`"model_id"`}, {"model_dtype", "max_concurrent_requests", "model_device_type"}},
				Primary: true, UnauthLeak: true, LeakName: "model + runtime info",
				VersionRe: `"version"\s*:\s*"([^"]+)"`},
		},
	},
	{
		ID: "gradio", Name: "Gradio", Category: CatAI,
		Tags:        []string{"gradio", "ai", "ml-demo", "dashboard"},
		Ref:         "https://www.gradio.app",
		BodyMarkers: [][]string{{"gradio"}, {"gradio-app", "gradio_config", "window.gradio"}},
		Confirmers: []Confirmer{
			{Path: "/config", Markers: [][]string{{`"components"`}, {`"mode"`, `"version"`, "gradio"}},
				Primary: true, UnauthLeak: true, LeakName: "app configuration (component graph)",
				VersionRe: `"version"\s*:\s*"([^"]+)"`},
			{Path: "/info", Markers: [][]string{{"named_endpoints", `"api"`}},
				UnauthLeak: true, LeakName: "API schema"},
		},
	},
	{
		ID: "streamlit", Name: "Streamlit", Category: CatAI,
		Tags:        []string{"streamlit", "ai", "ml-demo", "dashboard"},
		Ref:         "https://streamlit.io",
		BodyMarkers: [][]string{{"streamlit"}, {"stapp", "data-testid=\"stapp", "static/js/index"}},
		Confirmers: []Confirmer{
			{Path: "/_stcore/health", BodyRe: `(?i)^\s*ok`, Primary: true, LeakName: "health endpoint"},
			{Path: "/healthz", BodyRe: `(?i)^\s*ok`, LeakName: "health endpoint"},
			{Path: "/_stcore/host-config", Markers: [][]string{{"allowedorigins"}, {"enablecustomparentmessages", "usewidgetstateforcomponents", "useexternalauthtoken"}},
				UnauthLeak: true, LeakName: "host configuration", LeakSev: severity.Medium},
		},
	},
	{
		ID: "open-webui", Name: "Open WebUI", Category: CatAI,
		Tags:        []string{"open-webui", "ai", "llm", "dashboard"},
		Ref:         "https://github.com/open-webui/open-webui",
		BodyMarkers: [][]string{{"open webui", "<title>open webui"}},
		Confirmers: []Confirmer{
			{Path: "/api/config", Markers: [][]string{{`"name"`}, {`"version"`, `"features"`, "default_models"}},
				Primary: true, UnauthLeak: true, LeakName: "instance configuration",
				VersionRe: `"version"\s*:\s*"([^"]+)"`},
		},
		Login: &LoginProbe{
			Paths:       []string{"/api/v1/auths/signin"},
			ContentType: "application/json",
			Body:        `{"email":"{{user}}","password":"{{pass}}"}`,
			Creds:       [][2]string{{"admin@localhost", "admin"}, {"admin@example.com", "admin"}},
			Success: LoginSuccess{
				Status:       []int{200},
				Headers:      []HeaderSig{{Name: "Content-Type", Contains: "application/json"}},
				BodyContains: []string{`"token"`, `"role"`, `"token_type"`},
			},
		},
	},
	{
		ID: "ray", Name: "Ray Dashboard", Category: CatAI,
		Tags:        []string{"ray", "ai", "compute", "dashboard"},
		Ref:         "https://docs.ray.io",
		BodyMarkers: [][]string{{"<title>ray", "ray dashboard"}},
		Confirmers: []Confirmer{
			{Path: "/api/version", Markers: [][]string{{`"ray_version"`}},
				Primary: true, UnauthLeak: true, LeakName: "version",
				VersionRe: `"ray_version"\s*:\s*"([^"]+)"`},
			{Path: "/api/cluster_status", Markers: [][]string{{"clusterstatus", "autoscalingstatus"}},
				UnauthLeak: true, LeakName: "cluster status (RCE-capable if job submission is open)", LeakSev: severity.High},
		},
	},
	{
		ID: "comfyui", Name: "ComfyUI", Category: CatAI,
		Tags:        []string{"comfyui", "ai", "ml-demo", "dashboard"},
		Ref:         "https://github.com/comfyanonymous/ComfyUI",
		BodyMarkers: [][]string{{"comfyui", "<title>comfyui"}},
		Confirmers: []Confirmer{
			{Path: "/system_stats", Markers: [][]string{{`"system"`}, {"comfyui_version", `"devices"`}},
				Primary: true, UnauthLeak: true, LeakName: "system stats + version",
				VersionRe: `"comfyui_version"\s*:\s*"([^"]+)"`},
		},
	},

	{
		ID: "qdrant", Name: "Qdrant", Category: CatAI,
		Tags:        []string{"qdrant", "ai", "vector-db", "dashboard"},
		Ref:         "https://qdrant.tech",
		BodyMarkers: [][]string{{"qdrant - vector search"}}, // also recognised passively if the JSON root is crawled
		Mounts:      []string{"/dashboard"},
		Confirmers: []Confirmer{
			{Path: "/", Markers: [][]string{{"qdrant"}, {`"version"`}},
				Primary: true, UnauthLeak: true, LeakName: "version",
				VersionRe: `"version"\s*:\s*"([^"]+)"`},
			{Path: "/collections", Markers: [][]string{{`"result"`}, {"collections"}},
				UnauthLeak: true, LeakName: "vector collection list"},
		},
	},
	{
		ID: "weaviate", Name: "Weaviate", Category: CatAI,
		Tags: []string{"weaviate", "ai", "vector-db", "dashboard"},
		Ref:  "https://weaviate.io",
		Confirmers: []Confirmer{
			{Path: "/v1/meta", Markers: [][]string{{"hostname"}, {`"version"`, "modules"}},
				Primary: true, UnauthLeak: true, LeakName: "meta (version + enabled modules)",
				VersionRe: `"version"\s*:\s*"([^"]+)"`},
		},
	},
	{
		ID: "chroma", Name: "Chroma", Category: CatAI,
		Tags: []string{"chroma", "ai", "vector-db", "dashboard"},
		Ref:  "https://www.trychroma.com",
		Confirmers: []Confirmer{
			{Path: "/api/v1/heartbeat", Markers: [][]string{{"nanosecond heartbeat"}},
				Primary: true, LeakName: "heartbeat (unauthenticated API)"},
			{Path: "/api/v1/version", BodyRe: `^\s*"?\d+\.\d+`,
				UnauthLeak: true, LeakName: "version", VersionRe: `(\d+\.\d+(?:\.\d+)*)`},
		},
	},
	{
		ID: "mlflow", Name: "MLflow", Category: CatAI,
		Tags: []string{"mlflow", "ai", "ml-platform", "dashboard"},
		Ref:  "https://mlflow.org",
		// Anchored to the MLflow UI shell, not the bare word "mlflow" that any
		// blog about it contains.
		BodyMarkers: [][]string{{"<title>mlflow", "static-files/static"}},
		Confirmers: []Confirmer{
			{Path: "/ajax-api/2.0/mlflow/experiments/search?max_results=1", Markers: [][]string{{"experiments", "next_page_token"}},
				Primary: true, UnauthLeak: true, LeakName: "experiment list (unauthenticated tracking server)"},
		},
	},
	{
		ID: "flowise", Name: "Flowise", Category: CatAI,
		Tags:        []string{"flowise", "ai", "llm", "dashboard"},
		Ref:         "https://flowiseai.com",
		BodyMarkers: [][]string{{"flowise", "<title>flowise"}},
		Confirmers: []Confirmer{
			{Path: "/api/v1/ping", BodyRe: `(?i)pong`, Primary: true, LeakName: "API ping"},
			{Path: "/api/v1/chatflows", Markers: [][]string{{"flowdata", "deployed", "ispublic"}},
				UnauthLeak: true, LeakName: "chatflow list (LLM pipelines)"},
		},
	},

	// ─────────────────────────── Analytics / BI ───────────────────────────
	{
		ID: "metabase", Name: "Metabase", Category: CatAnalytics,
		Tags:        []string{"metabase", "analytics", "bi", "dashboard"},
		Ref:         "https://www.metabase.com",
		BodyMarkers: [][]string{{"metabase"}, {"<title>metabase", "metabasebootstrap"}},
		Confirmers: []Confirmer{
			{Path: "/api/session/properties", Markers: [][]string{{`"version"`}, {"site-name", "setup-token", "engines"}},
				Primary: true, UnauthLeak: true, LeakName: "version + settings (watch for setup-token)",
				VersionRe: `"tag"\s*:\s*"([^"]+)"`},
		},
	},
	{
		ID: "superset", Name: "Apache Superset", Category: CatAnalytics,
		Tags:        []string{"superset", "analytics", "bi", "dashboard"},
		Ref:         "https://superset.apache.org",
		BodyMarkers: [][]string{{"superset"}, {"<title>superset", "superset_app", "appbuilder"}},
		Confirmers: []Confirmer{
			// Presence (login page, UI markers) handled passively; active probe is
			// the health endpoint only.
			{Path: "/health", BodyRe: `(?i)^\s*ok`, Primary: true, LeakName: "health endpoint"},
		},
		Login: &LoginProbe{
			Paths:       []string{"/api/v1/security/login"},
			ContentType: "application/json",
			Body:        `{"username":"{{user}}","password":"{{pass}}","provider":"db","refresh":true}`,
			Creds:       [][2]string{{"admin", "admin"}},
			Success: LoginSuccess{
				Status:       []int{200},
				Headers:      []HeaderSig{{Name: "Content-Type", Contains: "application/json"}},
				BodyContains: []string{`"access_token"`, `"refresh_token"`},
			},
		},
	},
	{
		ID: "redash", Name: "Redash", Category: CatAnalytics,
		Tags:        []string{"redash", "analytics", "bi", "dashboard"},
		Ref:         "https://redash.io",
		BodyMarkers: [][]string{{"redash"}, {"<title>redash", "redash-app"}},
		Confirmers: []Confirmer{
			{Path: "/ping", BodyRe: `(?i)^\s*pong`, Primary: true, LeakName: "health endpoint"},
			{Path: "/api/session", Markers: [][]string{{"client_config"}, {`"version"`, `"org_slug"`}},
				UnauthLeak: true, LeakName: "client config + version"},
		},
	},
	{
		ID: "matomo", Name: "Matomo", Category: CatAnalytics,
		Tags:        []string{"matomo", "piwik", "analytics", "dashboard"},
		Ref:         "https://matomo.org",
		Cookies:     []string{"matomo_sessid", "piwik_auth"},
		BodyMarkers: [][]string{{"matomo"}, {"piwik", "matomo.js", "var _paq"}},
		// Passive-only: recognised from its UI markers / cookies in crawled traffic.
	},
	{
		ID: "clickhouse", Name: "ClickHouse", Category: CatAnalytics,
		Tags:    []string{"clickhouse", "analytics", "datastore", "dashboard"},
		Ref:     "https://clickhouse.com",
		Headers: []HeaderSig{{Name: "X-ClickHouse-Server-Display-Name"}, {Name: "X-ClickHouse-Query-Id"}},
		Confirmers: []Confirmer{
			{Path: "/?query=SELECT+1", HeaderName: "X-ClickHouse-Query-Id", BodyRe: `^\s*1`,
				Primary: true, UnauthLeak: true, LeakName: "open HTTP SQL interface (no auth)", LeakSev: severity.High},
		},
	},

	// ─────────────────────────── Orchestration / Kubernetes ───────────────────────────
	{
		ID: "kubernetes-api", Name: "Kubernetes API Server", Category: CatOrchestration,
		Tags: []string{"kubernetes", "k8s", "orchestration", "dashboard"},
		Ref:  "https://kubernetes.io",
		Confirmers: []Confirmer{
			{Path: "/version", Markers: [][]string{{"gitversion"}, {"major", "builddate", "gitcommit"}},
				Primary: true, UnauthLeak: true, LeakName: "Kubernetes version (anonymous API)",
				VersionRe: `"gitVersion"\s*:\s*"([^"]+)"`},
			{Path: "/api", Markers: [][]string{{"apiversions"}, {"serveraddressbyclientcidrs", "versions"}},
				UnauthLeak: true, LeakName: "anonymous API access", LeakSev: severity.High},
		},
	},
	{
		ID: "kubernetes-dashboard", Name: "Kubernetes Dashboard", Category: CatOrchestration,
		Tags:        []string{"kubernetes", "k8s", "orchestration", "dashboard"},
		Ref:         "https://github.com/kubernetes/dashboard",
		BodyMarkers: [][]string{{"kubernetes dashboard", "<title>kubernetes dashboard"}},
		// Passive-only: recognised from its UI markers in crawled traffic.
	},
	{
		ID: "rancher", Name: "Rancher", Category: CatOrchestration,
		Tags:        []string{"rancher", "kubernetes", "orchestration", "dashboard"},
		Ref:         "https://www.rancher.com",
		BodyMarkers: [][]string{{"rancher"}, {"<title>rancher", "__rancher", "cattle"}},
		// Passive-only: recognised from its UI markers in crawled traffic.
	},

	// ─────────────────────────── Collaboration / productivity ───────────────────────────
	{
		ID: "jira", Name: "Atlassian Jira", Category: CatCollab,
		Tags:        []string{"jira", "atlassian", "collaboration", "dashboard"},
		Ref:         "https://www.atlassian.com/software/jira",
		BodyMarkers: [][]string{{"jira"}, {"atlassian", "ajs-", "jira.app", "data-name=\"jira"}},
		Mounts:      []string{"/jira"},
		Confirmers: []Confirmer{
			{Path: "/rest/api/2/serverInfo", Markers: [][]string{{"versionnumbers"}, {"deploymenttype", "buildnumber"}},
				Primary: true, UnauthLeak: true, LeakName: "version + build (anonymous serverInfo)",
				VersionRe: `"version"\s*:\s*"([^"]+)"`},
		},
	},
	{
		ID: "confluence", Name: "Atlassian Confluence", Category: CatCollab,
		Tags:        []string{"confluence", "atlassian", "collaboration", "dashboard"},
		Ref:         "https://www.atlassian.com/software/confluence",
		BodyMarkers: [][]string{{"confluence"}, {"ajs-", "confluence-base-url", "com.atlassian.confluence"}},
		Mounts:      []string{"/confluence", "/wiki"},
		Confirmers: []Confirmer{
			{Path: "/login.action", Markers: [][]string{{"confluence"}, {"ajs-version-number", "login.action", "os_username"}},
				Primary: true, UnauthLeak: true, LeakName: "version (login page meta)",
				VersionRe: `ajs-version-number"\s+content="([^"]+)"`},
		},
	},
	{
		ID: "nextcloud", Name: "Nextcloud", Category: CatCollab,
		Tags:        []string{"nextcloud", "collaboration", "storage", "dashboard"},
		Ref:         "https://nextcloud.com",
		Cookies:     []string{"nc_session_id", "oc_sessionpassphrase"},
		BodyMarkers: [][]string{{"nextcloud"}, {"data-requesttoken", "oc-", "<title>nextcloud"}},
		Confirmers: []Confirmer{
			{Path: "/status.php", Markers: [][]string{{"installed"}, {"versionstring", "productname"}},
				Primary: true, UnauthLeak: true, LeakName: "version (status.php)",
				VersionRe: `"versionstring"\s*:\s*"([^"]+)"`},
		},
	},
	{
		ID: "gitea", Name: "Gitea / Forgejo", Category: CatCollab,
		Tags:        []string{"gitea", "forgejo", "scm", "collaboration", "dashboard"},
		Ref:         "https://about.gitea.com",
		BodyMarkers: [][]string{{"powered by gitea", "gitea version", ">forgejo<", "forgejo version"}},
		// Passive-only: recognised from its footer/UI markers in crawled traffic.
	},

	// ─────────────────────────── Automation / workflow ───────────────────────────
	{
		ID: "node-red", Name: "Node-RED", Category: CatAutomation,
		Tags:        []string{"node-red", "automation", "low-code", "dashboard"},
		Ref:         "https://nodered.org",
		BodyMarkers: [][]string{{"node-red"}, {"<title>node-red", "red.settings", "/red/"}},
		Mounts:      []string{"/red"},
		Confirmers: []Confirmer{
			{Path: "/settings", Markers: [][]string{{"httpnoderoot", "editortheme"}, {`"version"`}},
				Primary: true, UnauthLeak: true, LeakName: "settings + version (unauthenticated editor enables code execution)",
				LeakSev: severity.High, VersionRe: `"version"\s*:\s*"([^"]+)"`},
		},
		Login: &LoginProbe{
			Paths:       []string{"/auth/token"},
			ContentType: "application/x-www-form-urlencoded;charset=UTF-8",
			Body:        "client_id=node-red-editor&grant_type=password&scope=&username={{user}}&password={{pass}}",
			Creds:       [][2]string{{"admin", "password"}},
			Success: LoginSuccess{
				Status:       []int{200},
				Headers:      []HeaderSig{{Name: "Content-Type", Contains: "application/json"}},
				BodyContains: []string{`"access_token"`, `"expires_in"`, `"token_type"`},
			},
		},
	},
	{
		ID: "n8n", Name: "n8n", Category: CatAutomation,
		Tags:        []string{"n8n", "automation", "low-code", "dashboard"},
		Ref:         "https://n8n.io",
		BodyMarkers: [][]string{{"n8n"}, {"<title>n8n", "window.n8nexternalhooks", "data-n8n"}},
		Confirmers: []Confirmer{
			{Path: "/rest/settings", Markers: [][]string{{"versioncli"}, {"endpointwebhook", "n8nmetadata", "instanceid"}},
				Primary: true, UnauthLeak: true, LeakName: "settings + version",
				VersionRe: `"versionCli"\s*:\s*"([^"]+)"`},
		},
	},
	{
		ID: "prefect", Name: "Prefect", Category: CatAutomation,
		Tags:        []string{"prefect", "automation", "workflow", "dashboard"},
		Ref:         "https://www.prefect.io",
		BodyMarkers: [][]string{{"<title>prefect", "prefect"}},
		Confirmers: []Confirmer{
			{Path: "/api/admin/version", BodyRe: `^\s*"?\d+\.\d+`, Primary: true, UnauthLeak: true,
				LeakName: "version (unauthenticated API)", VersionRe: `(\d+\.\d+(?:\.\d+)*)`},
		},
	},

	// ─────────────────────────── Messaging / streaming ───────────────────────────
	{
		ID: "nats", Name: "NATS Monitoring", Category: CatMessaging,
		Tags: []string{"nats", "messaging", "dashboard"},
		Ref:  "https://docs.nats.io/running-a-nats-service/configuration/monitoring",
		Confirmers: []Confirmer{
			{Path: "/varz", Markers: [][]string{{"server_id"}, {`"version"`, "max_payload", "go"}},
				Primary: true, UnauthLeak: true, LeakName: "server config + version (varz)",
				VersionRe: `"version"\s*:\s*"([^"]+)"`},
			{Path: "/connz", Markers: [][]string{{"num_connections"}, {"connections", "total"}},
				UnauthLeak: true, LeakName: "active connection list"},
		},
	},
	{
		ID: "kafka-ui", Name: "Kafka Web UI", Category: CatMessaging,
		Tags: []string{"kafka", "messaging", "dashboard"},
		Ref:  "https://github.com/provectus/kafka-ui",
		// Product slugs / titles, not "<title>kafka" — which matched any article
		// titled "Kafka …" (e.g. "Kafka on Kubernetes").
		BodyMarkers: [][]string{{"kafka-ui", "kafdrop", "akhq", "ui for apache kafka"}},
		Confirmers: []Confirmer{
			{Path: "/api/clusters", Markers: [][]string{{"brokercount", "\"name\""}, {"status", "topiccount"}},
				Primary: true, UnauthLeak: true, LeakName: "Kafka cluster + broker list"},
		},
	},
}
