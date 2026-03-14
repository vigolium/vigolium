package modules

import (
	"github.com/vigolium/vigolium/pkg/modules/active/backslash_transformation"
	"github.com/vigolium/vigolium/pkg/modules/active/client_prototype_pollution"
	"github.com/vigolium/vigolium/pkg/modules/active/csti_detection"
	"github.com/vigolium/vigolium/pkg/modules/active/forbidden_bypass"
	"github.com/vigolium/vigolium/pkg/modules/active/code_exec"
	"github.com/vigolium/vigolium/pkg/modules/active/default_credentials"
	"github.com/vigolium/vigolium/pkg/modules/active/file_upload_scan"
	"github.com/vigolium/vigolium/pkg/modules/active/graphql_scan"
	"github.com/vigolium/vigolium/pkg/modules/active/cors_misconfiguration"
	"github.com/vigolium/vigolium/pkg/modules/active/crlf_injection"
	"github.com/vigolium/vigolium/pkg/modules/active/host_header_injection"
	"github.com/vigolium/vigolium/pkg/modules/active/http_method_tampering"
	"github.com/vigolium/vigolium/pkg/modules/active/iis_shortname_discovery"
	"github.com/vigolium/vigolium/pkg/modules/active/http_request_smuggling"
	"github.com/vigolium/vigolium/pkg/modules/active/insecure_deserialization"
	"github.com/vigolium/vigolium/pkg/modules/active/jwt_vulnerability"
	"github.com/vigolium/vigolium/pkg/modules/active/csrf_verify"
	"github.com/vigolium/vigolium/pkg/modules/active/authz_compare"
	"github.com/vigolium/vigolium/pkg/modules/active/idor_detection"
	"github.com/vigolium/vigolium/pkg/modules/active/jsonp_callback"
	"github.com/vigolium/vigolium/pkg/modules/active/lfi_generic"
	"github.com/vigolium/vigolium/pkg/modules/active/lfi_path_traversal"
	"github.com/vigolium/vigolium/pkg/modules/active/mass_assignment"
	"github.com/vigolium/vigolium/pkg/modules/active/nosqli_operator_injection"
	"github.com/vigolium/vigolium/pkg/modules/active/oast_probe"
	"github.com/vigolium/vigolium/pkg/modules/active/proxy_pingback"
	"github.com/vigolium/vigolium/pkg/modules/active/nginx_off_by_slash"
	"github.com/vigolium/vigolium/pkg/modules/active/nginx_path_escape"
	"github.com/vigolium/vigolium/pkg/modules/active/nosqli_error_based"
	"github.com/vigolium/vigolium/pkg/modules/active/backup_file_discovery"
	"github.com/vigolium/vigolium/pkg/modules/active/sensitive_file_discovery"
	"github.com/vigolium/vigolium/pkg/modules/active/path_normalization"
	"github.com/vigolium/vigolium/pkg/modules/active/prototype_pollution"

	"github.com/vigolium/vigolium/pkg/modules/active/race_interference"
	"github.com/vigolium/vigolium/pkg/modules/active/reflected_ssti"
	"github.com/vigolium/vigolium/pkg/modules/active/input_behavior_probe"
	smart_behavior_detection "github.com/vigolium/vigolium/pkg/modules/active/smart_behavior_detection"
	"github.com/vigolium/vigolium/pkg/modules/active/spring_actuator_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/angular_template_injection"
	"github.com/vigolium/vigolium/pkg/modules/active/sqli_boolean_blind"
	"github.com/vigolium/vigolium/pkg/modules/active/sqli_error_based"
	"github.com/vigolium/vigolium/pkg/modules/active/sqli_time_blind"
	"github.com/vigolium/vigolium/pkg/modules/active/ssrf_blind"
	"github.com/vigolium/vigolium/pkg/modules/active/ssrf_detection"
	"github.com/vigolium/vigolium/pkg/modules/active/ssti_blind"
	ssti_detection "github.com/vigolium/vigolium/pkg/modules/active/ssti_detection"
	"github.com/vigolium/vigolium/pkg/modules/active/suspect_transform"
	"github.com/vigolium/vigolium/pkg/modules/active/web_cache_poisoning"
	"github.com/vigolium/vigolium/pkg/modules/active/xml_saml_security"
	xsslightscanner "github.com/vigolium/vigolium/pkg/modules/active/xss_light_scanner"
	"github.com/vigolium/vigolium/pkg/modules/active/websocket_security"
	"github.com/vigolium/vigolium/pkg/modules/active/ws_cswsh"
	"github.com/vigolium/vigolium/pkg/modules/active/ws_injection"
	"github.com/vigolium/vigolium/pkg/modules/active/api_rate_limit_bypass"
	"github.com/vigolium/vigolium/pkg/modules/active/xxe_generic"
	// JS Framework Security - Active
	"github.com/vigolium/vigolium/pkg/modules/active/js_devserver_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/nextjs_data_leakage"
	"github.com/vigolium/vigolium/pkg/modules/active/nextjs_draft_mode_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/nextjs_image_ssrf"
	"github.com/vigolium/vigolium/pkg/modules/active/nextjs_middleware_bypass"
	"github.com/vigolium/vigolium/pkg/modules/active/nextjs_version_audit"
	// WordPress Security - Active
	"github.com/vigolium/vigolium/pkg/modules/active/wp_ajax_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/wp_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/wp_user_enum"
	"github.com/vigolium/vigolium/pkg/modules/active/wp_xmlrpc"
	// Drupal Security - Active
	"github.com/vigolium/vigolium/pkg/modules/active/drupal_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/drupal_user_enum"
	// Joomla Security - Active
	"github.com/vigolium/vigolium/pkg/modules/active/joomla_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/joomla_user_enum"
	// Cross-CMS Security - Active
	"github.com/vigolium/vigolium/pkg/modules/active/cms_installer_exposure"
	// PHP Security - Active
	"github.com/vigolium/vigolium/pkg/modules/active/php_debug_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/php_source_disclosure"
	"github.com/vigolium/vigolium/pkg/modules/active/php_composer_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/php_framework_debug"
	"github.com/vigolium/vigolium/pkg/modules/active/php_path_info_misconfig"
	// PHP Framework Security - Active
	"github.com/vigolium/vigolium/pkg/modules/active/laravel_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/laravel_ignition_rce"
	"github.com/vigolium/vigolium/pkg/modules/active/laravel_devtool_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/laravel_sensitive_files"
	"github.com/vigolium/vigolium/pkg/modules/active/laravel_admin_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/symfony_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/magento_misconfig"
	// Firebase Security - Active
	"github.com/vigolium/vigolium/pkg/modules/active/firebase_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/firebase_rtdb_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/firebase_storage_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/firebase_auth_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/firebase_functions_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/open_redirect"
	// Cloud Storage Security - Active
	"github.com/vigolium/vigolium/pkg/modules/active/cloud_storage_listing"
	"github.com/vigolium/vigolium/pkg/modules/active/cloud_bucket_takeover"
	"github.com/vigolium/vigolium/pkg/modules/active/cloud_origin_bypass"
	"github.com/vigolium/vigolium/pkg/modules/active/cloud_public_read"
	// ASP.NET Security - Active
	"github.com/vigolium/vigolium/pkg/modules/active/aspnet_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/aspnet_sensitive_files"
	"github.com/vigolium/vigolium/pkg/modules/active/aspnet_viewstate_scan"
	"github.com/vigolium/vigolium/pkg/modules/active/aspnet_service_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/aspnet_blazor_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/aspnet_health_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/aspnet_identity_probe"
	// Java/Spring Security - Active
	"github.com/vigolium/vigolium/pkg/modules/active/java_appserver_console"
	"github.com/vigolium/vigolium/pkg/modules/active/java_sensitive_files"
	"github.com/vigolium/vigolium/pkg/modules/active/struts_ognl_injection"
	"github.com/vigolium/vigolium/pkg/modules/active/log4shell_probe"
	// LDAP Injection - Active
	"github.com/vigolium/vigolium/pkg/modules/active/ldap_injection"
	// IDOR GUID - Active
	"github.com/vigolium/vigolium/pkg/modules/active/idor_guid"
	// Cache Deception - Active
	"github.com/vigolium/vigolium/pkg/modules/active/cache_deception"
	// Subdomain Takeover - Active
	"github.com/vigolium/vigolium/pkg/modules/active/subdomain_takeover"
	// PDF Generation Injection - Active
	"github.com/vigolium/vigolium/pkg/modules/active/pdf_generation_injection"
	"github.com/vigolium/vigolium/pkg/modules/active/spring_boot_admin_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/spring_cloud_config_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/spring_data_rest_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/spring_debug_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/spring_gateway_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/spring_h2_console_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/spring_jolokia_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/tomcat_manager_exposure"
	// Express/NestJS Security - Active
	"github.com/vigolium/vigolium/pkg/modules/active/express_debug_probe"
	"github.com/vigolium/vigolium/pkg/modules/active/express_directory_listing"
	"github.com/vigolium/vigolium/pkg/modules/active/express_trust_proxy_misconfig"
	// Fastify/Hono Security - Active
	"github.com/vigolium/vigolium/pkg/modules/active/fastify_hono_probe"
	// Meta-Framework Security - Active
	"github.com/vigolium/vigolium/pkg/modules/active/metaframework_probe"
	// API Security - Active
	"github.com/vigolium/vigolium/pkg/modules/active/api_key_url_exposure"
	// Common Directory Listing - Active
	"github.com/vigolium/vigolium/pkg/modules/active/common_directory_listing"
	// Rails Security - Active
	"github.com/vigolium/vigolium/pkg/modules/active/rails_info_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/rails_sensitive_files"
	"github.com/vigolium/vigolium/pkg/modules/active/rails_admin_dashboard"
	"github.com/vigolium/vigolium/pkg/modules/active/rails_active_storage_probe"
	"github.com/vigolium/vigolium/pkg/modules/active/rails_action_mailbox_probe"
	// API Spec Discovery & Ingestion - Active
	"github.com/vigolium/vigolium/pkg/modules/active/api_spec_ingest"
	// Python/Django/Flask/FastAPI Security - Active
	"github.com/vigolium/vigolium/pkg/modules/active/fastapi_docs_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/fastapi_auth_inconsistency"
	"github.com/vigolium/vigolium/pkg/modules/active/django_debug_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/django_admin_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/django_debug_toolbar_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/django_browsable_api_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/flask_werkzeug_debugger"
	"github.com/vigolium/vigolium/pkg/modules/active/proxy_header_trust"
	// Auth/API Security - Active
	"github.com/vigolium/vigolium/pkg/modules/active/bfla_detection"
	"github.com/vigolium/vigolium/pkg/modules/active/oauth_misconfiguration"
	"github.com/vigolium/vigolium/pkg/modules/passive/anomaly_ranking"
	"github.com/vigolium/vigolium/pkg/modules/passive/auth_headers_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/base64_data_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/content_type_mismatch"
	"github.com/vigolium/vigolium/pkg/modules/passive/csrf_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/idor_params_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/cookie_security_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/crypto_weakness_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/cors_headers_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/dom_xss_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/error_message_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/directory_listing_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/info_disclosure_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/graphql_introspection_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/jwt_claims_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/jwt_weak_secret"
	"github.com/vigolium/vigolium/pkg/modules/passive/mixed_content_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/oauth_facebook_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/openredirect_params"
	"github.com/vigolium/vigolium/pkg/modules/passive/secret_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/security_headers_missing"
	"github.com/vigolium/vigolium/pkg/modules/passive/sensitive_url_params"
	"github.com/vigolium/vigolium/pkg/modules/passive/serialized_object_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/sourcemap_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/cacheable_https_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/input_reflection_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/password_autocomplete_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/sql_syntax_detect"
	// JS Framework Security - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/cache_auth_misconfiguration"
	"github.com/vigolium/vigolium/pkg/modules/passive/cache_data_leak"
	"github.com/vigolium/vigolium/pkg/modules/passive/client_auth_guard"
	"github.com/vigolium/vigolium/pkg/modules/passive/javascript_uri_sink"
	"github.com/vigolium/vigolium/pkg/modules/passive/js_framework_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/nextauth_config_audit"
	"github.com/vigolium/vigolium/pkg/modules/passive/nextjs_config_audit"
	"github.com/vigolium/vigolium/pkg/modules/passive/nuxt_config_audit"
	"github.com/vigolium/vigolium/pkg/modules/passive/remix_loader_exposure"
	"github.com/vigolium/vigolium/pkg/modules/passive/server_action_auth"
	"github.com/vigolium/vigolium/pkg/modules/passive/server_action_bind_audit"
	"github.com/vigolium/vigolium/pkg/modules/passive/server_action_input_audit"
	"github.com/vigolium/vigolium/pkg/modules/passive/server_only_boundary_audit"
	"github.com/vigolium/vigolium/pkg/modules/passive/nextjs_dynamic_param_audit"
	"github.com/vigolium/vigolium/pkg/modules/passive/ssr_data_exposure"
	"github.com/vigolium/vigolium/pkg/modules/passive/ssr_hydration_xss"
	// Endpoint classification - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/endpoint_classifier"
	// WordPress Security - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/wp_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/wp_rest_api_detect"
	// Drupal Security - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/drupal_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/drupal_api_detect"
	// Joomla Security - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/joomla_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/joomla_api_detect"
	// Firebase Security - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/firebase_fingerprint"
	// Cloud Storage Security - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/cloud_storage_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/cloud_signed_url_leak"
	"github.com/vigolium/vigolium/pkg/modules/passive/cloud_storage_error_info"
	// Laravel Security - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/laravel_fingerprint"
	// ASP.NET Security - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/aspnet_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/aspnet_viewstate_detect"
	// Spring/Java Security - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/jackson_deserialize_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/spring_fingerprint"
	// Express/NestJS Security - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/cors_vary_origin_missing"
	"github.com/vigolium/vigolium/pkg/modules/passive/express_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/express_session_audit"
	// Rails Security - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/rails_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/rails_debug_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/rails_active_storage_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/rails_action_cable_detect"
	// Python Security - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/fastapi_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/django_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/flask_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/python_debug_detect"
	// API Spec Detection - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/api_spec_detect"
	// API Security - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/sensitive_api_fields_detect"
	// Protocol & Technology Detection - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/api_version_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/grpc_web_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/wasm_module_detect"
	// JS Framework Source Analysis - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/build_misconfig_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/env_secret_exposure"
	"github.com/vigolium/vigolium/pkg/modules/passive/insecure_token_storage"
	"github.com/vigolium/vigolium/pkg/modules/passive/unsafe_html_sink"
	// Security Headers Audit - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/csp_weakness_audit"
	"github.com/vigolium/vigolium/pkg/modules/passive/hsts_preload_audit"
	"github.com/vigolium/vigolium/pkg/modules/passive/permissions_policy_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/referrer_policy_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/subresource_integrity_detect"
	// API Pagination & Error Analysis - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/api_pagination_leak"
	"github.com/vigolium/vigolium/pkg/modules/passive/verbose_error_stacktrace"
	// GraphQL Error Analysis - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/graphql_error_leak"
	// Meta-Framework Fingerprinting - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/metaframework_fingerprint"
	// Software Version Detection - Passive
	"github.com/vigolium/vigolium/pkg/modules/passive/software_version_header"
)

// DefaultRegistry is the default registry with all built-in modules.
var DefaultRegistry = NewRegistry().
	// Active modules - XSS Light (3 specialized scanners)
	RegisterActive(xsslightscanner.NewURLParamsScanner()).
	RegisterActive(xsslightscanner.NewPathScanner()).
	RegisterActive(xsslightscanner.NewParamDiscoveryScanner()).
	// Active modules - XSS
	// RegisterActive(xss_scanner.New()).
	// Active modules - Injection
	RegisterActive(reflected_ssti.New()).
	RegisterActive(ssti_detection.New()).
	RegisterActive(csti_detection.New()).
	RegisterActive(angular_template_injection.New()).
	RegisterActive(lfi_generic.New()).
	RegisterActive(lfi_path_traversal.New()).
	RegisterActive(sqli_error_based.New()).
	RegisterActive(sqli_boolean_blind.New()).
	RegisterActive(sqli_time_blind.New()).
	RegisterActive(nosqli_error_based.New()).
	RegisterActive(nosqli_operator_injection.New()).
	RegisterActive(crlf_injection.New()).
	RegisterActive(code_exec.New()).
	RegisterActive(input_behavior_probe.New()).
	RegisterActive(xxe_generic.New()).
	RegisterActive(insecure_deserialization.New()).
	// Active modules - SSRF
	RegisterActive(ssrf_detection.New()).
	RegisterActive(ssrf_blind.New()).
	// Active modules - SSTI (Blind)
	RegisterActive(ssti_blind.New()).
	// Active modules - OAST (Out-of-Band)
	RegisterActive(oast_probe.New()).
	RegisterActive(proxy_pingback.New()).
	// Active modules - Misconfig
	RegisterActive(cors_misconfiguration.New()).
	RegisterActive(spring_actuator_misconfig.New()).
	RegisterActive(host_header_injection.New()).
	RegisterActive(web_cache_poisoning.New()).
	RegisterActive(prototype_pollution.New()).
	RegisterActive(client_prototype_pollution.New()).
	// Active modules - Diff-based
	RegisterActive(path_normalization.New()).
	RegisterActive(nginx_off_by_slash.New()).
	RegisterActive(nginx_path_escape.New()).
	RegisterActive(smart_behavior_detection.New()).
	RegisterActive(suspect_transform.New()).
	RegisterActive(backslash_transformation.New()).
	// Active modules - Race Conditions
	RegisterActive(race_interference.New()).
	// Active modules - XML Security
	RegisterActive(xml_saml_security.New()).
	// Active modules - JWT
	RegisterActive(jwt_vulnerability.New()).
	// Active modules - HTTP Smuggling
	RegisterActive(http_request_smuggling.New()).
	// Active modules - GraphQL
	RegisterActive(graphql_scan.New()).
	// Active modules - File Upload
	RegisterActive(file_upload_scan.New()).
	// Active modules - Default Credentials
	RegisterActive(default_credentials.New()).
	// Active modules - Access Control
	RegisterActive(forbidden_bypass.New()).
	RegisterActive(http_method_tampering.New()).
	RegisterActive(csrf_verify.New()).
	RegisterActive(idor_detection.New()).
	RegisterActive(authz_compare.New()).
	RegisterActive(mass_assignment.New()).
	// Active modules - Discovery
	RegisterActive(sensitive_file_discovery.New()).
	RegisterActive(backup_file_discovery.New()).
	RegisterActive(iis_shortname_discovery.New()).
	// Active modules - JSONP
	RegisterActive(jsonp_callback.New()).
	// Active modules - Open Redirect
	RegisterActive(open_redirect.New()).
	// Active modules - WebSocket
	RegisterActive(websocket_security.New()).
	RegisterActive(ws_injection.New()).
	RegisterActive(ws_cswsh.New()).
	// Active modules - Rate Limiting
	RegisterActive(api_rate_limit_bypass.New()).
	// Active modules - JS Framework Security
	RegisterActive(nextjs_data_leakage.New()).
	RegisterActive(nextjs_middleware_bypass.New()).
	RegisterActive(nextjs_image_ssrf.New()).
	RegisterActive(nextjs_draft_mode_exposure.New()).
	RegisterActive(nextjs_version_audit.New()).
	RegisterActive(js_devserver_exposure.New()).
	// Active modules - WordPress Security
	RegisterActive(wp_misconfig.New()).
	RegisterActive(wp_xmlrpc.New()).
	RegisterActive(wp_user_enum.New()).
	RegisterActive(wp_ajax_exposure.New()).
	// Active modules - Drupal Security
	RegisterActive(drupal_misconfig.New()).
	RegisterActive(drupal_user_enum.New()).
	// Active modules - Joomla Security
	RegisterActive(joomla_misconfig.New()).
	RegisterActive(joomla_user_enum.New()).
	// Active modules - Cross-CMS Security
	RegisterActive(cms_installer_exposure.New()).
	// Active modules - Firebase Security
	RegisterActive(firebase_misconfig.New()).
	RegisterActive(firebase_rtdb_exposure.New()).
	RegisterActive(firebase_storage_exposure.New()).
	RegisterActive(firebase_auth_misconfig.New()).
	RegisterActive(firebase_functions_exposure.New()).
	// Active modules - PHP Security
	RegisterActive(php_debug_exposure.New()).
	RegisterActive(php_source_disclosure.New()).
	RegisterActive(php_composer_exposure.New()).
	RegisterActive(php_framework_debug.New()).
	RegisterActive(php_path_info_misconfig.New()).
	// Active modules - PHP Framework Security
	RegisterActive(laravel_misconfig.New()).
	RegisterActive(laravel_ignition_rce.New()).
	RegisterActive(laravel_devtool_exposure.New()).
	RegisterActive(laravel_sensitive_files.New()).
	RegisterActive(laravel_admin_exposure.New()).
	RegisterActive(symfony_misconfig.New()).
	RegisterActive(magento_misconfig.New()).
	// Active modules - Cloud Storage Security
	RegisterActive(cloud_storage_listing.New()).
	RegisterActive(cloud_bucket_takeover.New()).
	RegisterActive(cloud_origin_bypass.New()).
	RegisterActive(cloud_public_read.New()).
	// Active modules - ASP.NET Security
	RegisterActive(aspnet_misconfig.New()).
	RegisterActive(aspnet_sensitive_files.New()).
	RegisterActive(aspnet_viewstate_scan.New()).
	RegisterActive(aspnet_service_exposure.New()).
	RegisterActive(aspnet_blazor_exposure.New()).
	RegisterActive(aspnet_health_exposure.New()).
	RegisterActive(aspnet_identity_probe.New()).
	// Active modules - Java/Spring Security
	RegisterActive(spring_h2_console_exposure.New()).
	RegisterActive(spring_jolokia_exposure.New()).
	RegisterActive(spring_debug_exposure.New()).
	RegisterActive(spring_cloud_config_exposure.New()).
	RegisterActive(spring_gateway_exposure.New()).
	RegisterActive(spring_data_rest_exposure.New()).
	RegisterActive(spring_boot_admin_exposure.New()).
	RegisterActive(java_sensitive_files.New()).
	RegisterActive(java_appserver_console.New()).
	RegisterActive(tomcat_manager_exposure.New()).
	RegisterActive(struts_ognl_injection.New()).
	RegisterActive(log4shell_probe.New()).
	// Active modules - LDAP Injection
	RegisterActive(ldap_injection.New()).
	// Active modules - IDOR GUID
	RegisterActive(idor_guid.New()).
	// Active modules - Cache Deception
	RegisterActive(cache_deception.New()).
	// Active modules - Subdomain Takeover
	RegisterActive(subdomain_takeover.New()).
	// Active modules - PDF Generation Injection
	RegisterActive(pdf_generation_injection.New()).
	// Active modules - Express/NestJS Security
	RegisterActive(express_debug_probe.New()).
	RegisterActive(express_trust_proxy_misconfig.New()).
	RegisterActive(express_directory_listing.New()).
	// Active modules - Common Directory Listing
	RegisterActive(common_directory_listing.New()).
	// Active modules - Rails Security
	RegisterActive(rails_info_exposure.New()).
	RegisterActive(rails_sensitive_files.New()).
	RegisterActive(rails_admin_dashboard.New()).
	RegisterActive(rails_active_storage_probe.New()).
	RegisterActive(rails_action_mailbox_probe.New()).
	// Active modules - API Spec Discovery & Ingestion
	RegisterActive(api_spec_ingest.New()).
	// Active modules - Python/Django/Flask/FastAPI Security
	RegisterActive(fastapi_docs_exposure.New()).
	RegisterActive(fastapi_auth_inconsistency.New()).
	RegisterActive(django_debug_exposure.New()).
	RegisterActive(django_admin_exposure.New()).
	RegisterActive(django_debug_toolbar_exposure.New()).
	RegisterActive(django_browsable_api_exposure.New()).
	RegisterActive(flask_werkzeug_debugger.New()).
	RegisterActive(proxy_header_trust.New()).
	// Active modules - Auth/API Security
	RegisterActive(bfla_detection.New()).
	RegisterActive(oauth_misconfiguration.New()).
	RegisterActive(api_key_url_exposure.New()).
	// Active modules - Fastify/Hono Security
	RegisterActive(fastify_hono_probe.New()).
	// Active modules - Meta-Framework Security
	RegisterActive(metaframework_probe.New()).
	// Passive modules
	RegisterPassive(dom_xss_detect.New()).
	RegisterPassive(auth_headers_detect.New()).
	RegisterPassive(openredirect_params.New()).
	RegisterPassive(oauth_facebook_detect.New()).
	RegisterPassive(anomaly_ranking.New()).
	RegisterPassive(secret_detect.New()).
	RegisterPassive(sourcemap_detect.New()).
	RegisterPassive(security_headers_missing.New()).
	RegisterPassive(info_disclosure_detect.New()).
	RegisterPassive(directory_listing_detect.New()).
	RegisterPassive(cookie_security_detect.New()).
	RegisterPassive(mixed_content_detect.New()).
	RegisterPassive(sensitive_url_params.New()).
	RegisterPassive(cors_headers_detect.New()).
	RegisterPassive(jwt_weak_secret.New()).
	RegisterPassive(jwt_claims_detect.New()).
	RegisterPassive(serialized_object_detect.New()).
	RegisterPassive(sql_syntax_detect.New()).
	RegisterPassive(content_type_mismatch.New()).
	RegisterPassive(csrf_detect.New()).
	RegisterPassive(idor_params_detect.New()).
	RegisterPassive(crypto_weakness_detect.New()).
	RegisterPassive(error_message_detect.New()).
	RegisterPassive(base64_data_detect.New()).
	RegisterPassive(password_autocomplete_detect.New()).
	RegisterPassive(cacheable_https_detect.New()).
	RegisterPassive(input_reflection_detect.New()).
	RegisterPassive(graphql_introspection_detect.New()).
	// Passive modules - JS Framework Security
	RegisterPassive(js_framework_fingerprint.New()).
	RegisterPassive(ssr_data_exposure.New()).
	RegisterPassive(cache_auth_misconfiguration.New()).
	RegisterPassive(server_action_auth.New()).
	RegisterPassive(nextauth_config_audit.New()).
	RegisterPassive(nextjs_config_audit.New()).
	RegisterPassive(nuxt_config_audit.New()).
	RegisterPassive(javascript_uri_sink.New()).
	RegisterPassive(ssr_hydration_xss.New()).
	RegisterPassive(remix_loader_exposure.New()).
	RegisterPassive(client_auth_guard.New()).
	RegisterPassive(cache_data_leak.New()).
	RegisterPassive(server_action_input_audit.New()).
	RegisterPassive(server_action_bind_audit.New()).
	RegisterPassive(server_only_boundary_audit.New()).
	RegisterPassive(nextjs_dynamic_param_audit.New()).
	// Passive modules - JS Framework Source Analysis
	RegisterPassive(unsafe_html_sink.New()).
	RegisterPassive(insecure_token_storage.New()).
	RegisterPassive(env_secret_exposure.New()).
	RegisterPassive(build_misconfig_detect.New()).
	// Security Headers Audit
	RegisterPassive(csp_weakness_audit.New()).
	RegisterPassive(hsts_preload_audit.New()).
	RegisterPassive(referrer_policy_detect.New()).
	RegisterPassive(permissions_policy_detect.New()).
	RegisterPassive(subresource_integrity_detect.New()).
	// Protocol & Technology Detection
	RegisterPassive(api_version_detect.New()).
	RegisterPassive(grpc_web_detect.New()).
	RegisterPassive(wasm_module_detect.New()).
	// Endpoint classification
	RegisterPassive(endpoint_classifier.New()).
	// WordPress Security - Passive
	RegisterPassive(wp_fingerprint.New()).
	RegisterPassive(wp_rest_api_detect.New()).
	// Drupal Security - Passive
	RegisterPassive(drupal_fingerprint.New()).
	RegisterPassive(drupal_api_detect.New()).
	// Joomla Security - Passive
	RegisterPassive(joomla_fingerprint.New()).
	RegisterPassive(joomla_api_detect.New()).
	// Firebase Security - Passive
	RegisterPassive(firebase_fingerprint.New()).
	// Cloud Storage Security - Passive
	RegisterPassive(cloud_storage_fingerprint.New()).
	RegisterPassive(cloud_signed_url_leak.New()).
	RegisterPassive(cloud_storage_error_info.New()).
	// Laravel Security - Passive
	RegisterPassive(laravel_fingerprint.New()).
	// ASP.NET Security - Passive
	RegisterPassive(aspnet_fingerprint.New()).
	RegisterPassive(aspnet_viewstate_detect.New()).
	// Spring/Java Security - Passive
	RegisterPassive(spring_fingerprint.New()).
	RegisterPassive(jackson_deserialize_detect.New()).
	// Express/NestJS Security - Passive
	RegisterPassive(express_fingerprint.New()).
	RegisterPassive(express_session_audit.New()).
	RegisterPassive(cors_vary_origin_missing.New()).
	// Rails Security - Passive
	RegisterPassive(rails_fingerprint.New()).
	RegisterPassive(rails_debug_detect.New()).
	RegisterPassive(rails_active_storage_detect.New()).
	RegisterPassive(rails_action_cable_detect.New()).
	// Python Security - Passive
	RegisterPassive(fastapi_fingerprint.New()).
	RegisterPassive(django_fingerprint.New()).
	RegisterPassive(flask_fingerprint.New()).
	RegisterPassive(python_debug_detect.New()).
	// API Spec Detection - Passive
	RegisterPassive(api_spec_detect.New()).
	// API Security - Passive
	RegisterPassive(sensitive_api_fields_detect.New()).
	// API Pagination & Error Analysis - Passive
	RegisterPassive(api_pagination_leak.New()).
	RegisterPassive(verbose_error_stacktrace.New()).
	// GraphQL Error Analysis - Passive
	RegisterPassive(graphql_error_leak.New()).
	// Meta-Framework Fingerprinting - Passive
	RegisterPassive(metaframework_fingerprint.New()).
	// Software Version Detection - Passive
	RegisterPassive(software_version_header.New())

// Convenience functions - delegate to DefaultRegistry

// GetActiveModules returns all registered active modules.
func GetActiveModules() []ActiveModule {
	return DefaultRegistry.GetActiveModules()
}

// GetActiveModulesID returns IDs of all registered active modules.
func GetActiveModulesID() []string {
	return DefaultRegistry.GetActiveModulesID()
}

// GetActiveModulesByIDs returns active modules matching the given IDs.
func GetActiveModulesByIDs(ids []string) []ActiveModule {
	return DefaultRegistry.GetActiveModulesByIDs(ids)
}

// GetPassiveModules returns all registered passive modules.
func GetPassiveModules() []PassiveModule {
	return DefaultRegistry.GetPassiveModules()
}

// GetPassiveModulesID returns IDs of all registered passive modules.
func GetPassiveModulesID() []string {
	return DefaultRegistry.GetPassiveModulesID()
}

// GetPassiveModulesByIDs returns passive modules matching the given IDs.
func GetPassiveModulesByIDs(ids []string) []PassiveModule {
	return DefaultRegistry.GetPassiveModulesByIDs(ids)
}

// ResolveModulePatterns resolves user-provided patterns into exact module IDs
// using fuzzy matching against module IDs and names.
func ResolveModulePatterns(patterns []string) []string {
	return DefaultRegistry.ResolveModulePatterns(patterns)
}

// ResolveModuleTags returns module IDs for all modules matching any of the given tags.
func ResolveModuleTags(tags []string) []string {
	return DefaultRegistry.ResolveModuleTags(tags)
}
