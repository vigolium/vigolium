package modules

import (
	"github.com/vigolium/vigolium/pkg/modules/passive/anomaly_ranking"
	"github.com/vigolium/vigolium/pkg/modules/passive/api_pagination_leak"
	"github.com/vigolium/vigolium/pkg/modules/passive/api_spec_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/api_version_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/aspnet_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/aspnet_viewstate_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/auth_headers_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/base64_data_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/build_misconfig_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/cache_auth_misconfiguration"
	"github.com/vigolium/vigolium/pkg/modules/passive/cache_data_leak"
	"github.com/vigolium/vigolium/pkg/modules/passive/client_auth_guard"
	"github.com/vigolium/vigolium/pkg/modules/passive/cloud_signed_url_leak"
	"github.com/vigolium/vigolium/pkg/modules/passive/cloud_storage_error_info"
	"github.com/vigolium/vigolium/pkg/modules/passive/cloud_storage_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/content_type_mismatch"
	"github.com/vigolium/vigolium/pkg/modules/passive/cookie_security_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/cors_headers_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/cors_vary_origin_missing"
	"github.com/vigolium/vigolium/pkg/modules/passive/crypto_weakness_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/csp_weakness_audit"
	"github.com/vigolium/vigolium/pkg/modules/passive/csrf_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/directory_listing_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/django_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/dom_xss_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/dom_xss_taint"
	"github.com/vigolium/vigolium/pkg/modules/passive/drupal_api_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/drupal_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/endpoint_classifier"
	"github.com/vigolium/vigolium/pkg/modules/passive/env_secret_exposure"
	"github.com/vigolium/vigolium/pkg/modules/passive/error_message_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/express_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/express_session_audit"
	"github.com/vigolium/vigolium/pkg/modules/passive/fastapi_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/firebase_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/flask_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/graphql_error_leak"
	"github.com/vigolium/vigolium/pkg/modules/passive/graphql_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/graphql_introspection_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/grpc_web_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/hsts_preload_audit"
	"github.com/vigolium/vigolium/pkg/modules/passive/idor_params_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/info_disclosure_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/input_reflection_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/insecure_token_storage"
	"github.com/vigolium/vigolium/pkg/modules/passive/jackson_deserialize_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/java_server_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/javascript_uri_sink"
	"github.com/vigolium/vigolium/pkg/modules/passive/joomla_api_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/joomla_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/js_framework_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/jwt_claims_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/jwt_weak_secret"
	"github.com/vigolium/vigolium/pkg/modules/passive/laravel_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/mcp_description_injection"
	"github.com/vigolium/vigolium/pkg/modules/passive/mcp_endpoint_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/metaframework_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/mixed_content_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/nextauth_config_audit"
	"github.com/vigolium/vigolium/pkg/modules/passive/nextjs_config_audit"
	"github.com/vigolium/vigolium/pkg/modules/passive/nextjs_dynamic_param_audit"
	"github.com/vigolium/vigolium/pkg/modules/passive/nuxt_config_audit"
	"github.com/vigolium/vigolium/pkg/modules/passive/oauth_facebook_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/openredirect_params"
	"github.com/vigolium/vigolium/pkg/modules/passive/password_autocomplete_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/permissions_policy_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/php_generic_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/python_debug_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/rails_action_cable_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/rails_active_storage_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/rails_debug_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/rails_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/remix_loader_exposure"
	"github.com/vigolium/vigolium/pkg/modules/passive/secret_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/security_headers_missing"
	"github.com/vigolium/vigolium/pkg/modules/passive/sensitive_api_fields_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/sensitive_header_leak"
	"github.com/vigolium/vigolium/pkg/modules/passive/sensitive_url_params"
	"github.com/vigolium/vigolium/pkg/modules/passive/serialized_object_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/server_action_auth"
	"github.com/vigolium/vigolium/pkg/modules/passive/server_action_bind_audit"
	"github.com/vigolium/vigolium/pkg/modules/passive/server_action_input_audit"
	"github.com/vigolium/vigolium/pkg/modules/passive/server_only_boundary_audit"
	"github.com/vigolium/vigolium/pkg/modules/passive/software_version_header"
	"github.com/vigolium/vigolium/pkg/modules/passive/sourcemap_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/spring_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/sql_syntax_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/ssr_data_exposure"
	"github.com/vigolium/vigolium/pkg/modules/passive/ssr_hydration_xss"
	"github.com/vigolium/vigolium/pkg/modules/passive/subresource_integrity_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/symfony_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/unsafe_html_sink"
	"github.com/vigolium/vigolium/pkg/modules/passive/verbose_error_stacktrace"
	"github.com/vigolium/vigolium/pkg/modules/passive/wasm_module_detect"
	"github.com/vigolium/vigolium/pkg/modules/passive/wp_fingerprint"
	"github.com/vigolium/vigolium/pkg/modules/passive/wp_rest_api_detect"
)

// registerPassiveModules registers every built-in passive scanner module.
// Split out of default_registry.go; order is preserved from the original chain.
func registerPassiveModules(r *Registry) {
	// Passive modules
	r.RegisterPassive(dom_xss_detect.New())
	r.RegisterPassive(dom_xss_taint.New())
	r.RegisterPassive(auth_headers_detect.New())
	r.RegisterPassive(openredirect_params.New())
	r.RegisterPassive(oauth_facebook_detect.New())
	r.RegisterPassive(anomaly_ranking.New())
	r.RegisterPassive(secret_detect.New())
	r.RegisterPassive(sourcemap_detect.New())
	r.RegisterPassive(security_headers_missing.New())
	r.RegisterPassive(info_disclosure_detect.New())
	r.RegisterPassive(directory_listing_detect.New())
	r.RegisterPassive(cookie_security_detect.New())
	r.RegisterPassive(mixed_content_detect.New())
	r.RegisterPassive(sensitive_url_params.New())
	r.RegisterPassive(cors_headers_detect.New())
	r.RegisterPassive(jwt_weak_secret.New())
	r.RegisterPassive(jwt_claims_detect.New())
	r.RegisterPassive(serialized_object_detect.New())
	r.RegisterPassive(sql_syntax_detect.New())
	r.RegisterPassive(content_type_mismatch.New())
	r.RegisterPassive(csrf_detect.New())
	r.RegisterPassive(idor_params_detect.New())
	r.RegisterPassive(crypto_weakness_detect.New())
	r.RegisterPassive(error_message_detect.New())
	r.RegisterPassive(base64_data_detect.New())
	r.RegisterPassive(password_autocomplete_detect.New())
	r.RegisterPassive(input_reflection_detect.New())
	r.RegisterPassive(graphql_introspection_detect.New())
	// Passive modules - JS Framework Security
	r.RegisterPassive(js_framework_fingerprint.New())
	r.RegisterPassive(ssr_data_exposure.New())
	r.RegisterPassive(cache_auth_misconfiguration.New())
	r.RegisterPassive(server_action_auth.New())
	r.RegisterPassive(nextauth_config_audit.New())
	r.RegisterPassive(nextjs_config_audit.New())
	r.RegisterPassive(nuxt_config_audit.New())
	r.RegisterPassive(javascript_uri_sink.New())
	r.RegisterPassive(ssr_hydration_xss.New())
	r.RegisterPassive(remix_loader_exposure.New())
	r.RegisterPassive(client_auth_guard.New())
	r.RegisterPassive(cache_data_leak.New())
	r.RegisterPassive(server_action_input_audit.New())
	r.RegisterPassive(server_action_bind_audit.New())
	r.RegisterPassive(server_only_boundary_audit.New())
	r.RegisterPassive(nextjs_dynamic_param_audit.New())
	// Passive modules - JS Framework Source Analysis
	r.RegisterPassive(unsafe_html_sink.New())
	r.RegisterPassive(insecure_token_storage.New())
	r.RegisterPassive(env_secret_exposure.New())
	r.RegisterPassive(build_misconfig_detect.New())
	// Security Headers Audit
	r.RegisterPassive(csp_weakness_audit.New())
	r.RegisterPassive(hsts_preload_audit.New())
	r.RegisterPassive(permissions_policy_detect.New())
	r.RegisterPassive(subresource_integrity_detect.New())
	// Protocol & Technology Detection
	r.RegisterPassive(api_version_detect.New())
	r.RegisterPassive(grpc_web_detect.New())
	r.RegisterPassive(wasm_module_detect.New())
	// Endpoint classification
	r.RegisterPassive(endpoint_classifier.New())
	// WordPress Security - Passive
	r.RegisterPassive(wp_fingerprint.New())
	r.RegisterPassive(wp_rest_api_detect.New())
	// Drupal Security - Passive
	r.RegisterPassive(drupal_fingerprint.New())
	r.RegisterPassive(drupal_api_detect.New())
	// Joomla Security - Passive
	r.RegisterPassive(joomla_fingerprint.New())
	r.RegisterPassive(joomla_api_detect.New())
	// Firebase Security - Passive
	r.RegisterPassive(firebase_fingerprint.New())
	// Cloud Storage Security - Passive
	r.RegisterPassive(cloud_storage_fingerprint.New())
	r.RegisterPassive(cloud_signed_url_leak.New())
	r.RegisterPassive(cloud_storage_error_info.New())
	// Laravel Security - Passive
	r.RegisterPassive(laravel_fingerprint.New())
	// Symfony - Passive
	r.RegisterPassive(symfony_fingerprint.New())
	// PHP (generic) - Passive
	r.RegisterPassive(php_generic_fingerprint.New())
	// ASP.NET Security - Passive
	r.RegisterPassive(aspnet_fingerprint.New())
	r.RegisterPassive(aspnet_viewstate_detect.New())
	// Spring/Java Security - Passive
	r.RegisterPassive(spring_fingerprint.New())
	r.RegisterPassive(java_server_fingerprint.New())
	r.RegisterPassive(jackson_deserialize_detect.New())
	// Express/NestJS Security - Passive
	r.RegisterPassive(express_fingerprint.New())
	r.RegisterPassive(express_session_audit.New())
	r.RegisterPassive(cors_vary_origin_missing.New())
	// Rails Security - Passive
	r.RegisterPassive(rails_fingerprint.New())
	r.RegisterPassive(rails_debug_detect.New())
	r.RegisterPassive(rails_active_storage_detect.New())
	r.RegisterPassive(rails_action_cable_detect.New())
	// Python Security - Passive
	r.RegisterPassive(fastapi_fingerprint.New())
	r.RegisterPassive(django_fingerprint.New())
	r.RegisterPassive(flask_fingerprint.New())
	r.RegisterPassive(python_debug_detect.New())
	// API Spec Detection - Passive
	r.RegisterPassive(api_spec_detect.New())
	r.RegisterPassive(graphql_fingerprint.New())
	// API Security - Passive
	r.RegisterPassive(sensitive_api_fields_detect.New())
	// API Pagination & Error Analysis - Passive
	r.RegisterPassive(api_pagination_leak.New())
	r.RegisterPassive(verbose_error_stacktrace.New())
	// GraphQL Error Analysis - Passive
	r.RegisterPassive(graphql_error_leak.New())
	// Meta-Framework Fingerprinting - Passive
	r.RegisterPassive(metaframework_fingerprint.New())
	// Software Version Detection - Passive
	r.RegisterPassive(software_version_header.New())
	// MCP Security - Passive
	r.RegisterPassive(mcp_endpoint_detect.New())
	r.RegisterPassive(mcp_description_injection.New())
	// Sensitive Data in Headers - Passive
	r.RegisterPassive(sensitive_header_leak.New())
}
