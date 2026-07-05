package modules

import (
	xsslightscanner "github.com/vigolium/vigolium/pkg/modules/active/xss_light_scanner"

	"github.com/vigolium/vigolium/pkg/modules/active/aem_cloudsettings_injection"
	"github.com/vigolium/vigolium/pkg/modules/active/aem_console_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/aem_content_discovery"
	"github.com/vigolium/vigolium/pkg/modules/active/aem_default_credentials"
	"github.com/vigolium/vigolium/pkg/modules/active/aem_dispatcher_bypass"
	"github.com/vigolium/vigolium/pkg/modules/active/aem_oob_injection"
	"github.com/vigolium/vigolium/pkg/modules/active/aem_rce"
	"github.com/vigolium/vigolium/pkg/modules/active/aem_sensitive_servlet"
	"github.com/vigolium/vigolium/pkg/modules/active/aem_ssrf"
	"github.com/vigolium/vigolium/pkg/modules/active/aem_xss"
	"github.com/vigolium/vigolium/pkg/modules/active/aem_xxe"
	"github.com/vigolium/vigolium/pkg/modules/active/angular_template_injection"
	"github.com/vigolium/vigolium/pkg/modules/active/api_key_url_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/api_rate_limit_bypass"
	"github.com/vigolium/vigolium/pkg/modules/active/api_spec_ingest"
	"github.com/vigolium/vigolium/pkg/modules/active/aspnet_blazor_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/aspnet_health_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/aspnet_identity_probe"
	"github.com/vigolium/vigolium/pkg/modules/active/aspnet_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/aspnet_sensitive_files"
	"github.com/vigolium/vigolium/pkg/modules/active/aspnet_service_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/aspnet_viewstate_scan"
	"github.com/vigolium/vigolium/pkg/modules/active/authz_compare"
	"github.com/vigolium/vigolium/pkg/modules/active/backslash_transformation"
	"github.com/vigolium/vigolium/pkg/modules/active/backup_file_discovery"
	"github.com/vigolium/vigolium/pkg/modules/active/bfla_detection"
	"github.com/vigolium/vigolium/pkg/modules/active/cache_deception"
	"github.com/vigolium/vigolium/pkg/modules/active/cdn_object_traversal_listing"
	"github.com/vigolium/vigolium/pkg/modules/active/client_prototype_pollution"
	"github.com/vigolium/vigolium/pkg/modules/active/cloud_bucket_takeover"
	"github.com/vigolium/vigolium/pkg/modules/active/cloud_origin_bypass"
	"github.com/vigolium/vigolium/pkg/modules/active/cloud_public_read"
	"github.com/vigolium/vigolium/pkg/modules/active/cloud_storage_listing"
	"github.com/vigolium/vigolium/pkg/modules/active/cms_installer_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/code_exec"
	"github.com/vigolium/vigolium/pkg/modules/active/command_injection_echo"
	"github.com/vigolium/vigolium/pkg/modules/active/command_injection_oast"
	"github.com/vigolium/vigolium/pkg/modules/active/command_injection_timing"
	"github.com/vigolium/vigolium/pkg/modules/active/common_directory_listing"
	"github.com/vigolium/vigolium/pkg/modules/active/cors_misconfiguration"
	"github.com/vigolium/vigolium/pkg/modules/active/cpdos"
	"github.com/vigolium/vigolium/pkg/modules/active/crlf_injection"
	"github.com/vigolium/vigolium/pkg/modules/active/csrf_verify"
	"github.com/vigolium/vigolium/pkg/modules/active/csti_detection"
	"github.com/vigolium/vigolium/pkg/modules/active/dashboard_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/default_credentials"
	"github.com/vigolium/vigolium/pkg/modules/active/django_admin_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/django_browsable_api_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/django_debug_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/django_debug_toolbar_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/drupal_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/drupal_user_enum"
	"github.com/vigolium/vigolium/pkg/modules/active/express_debug_probe"
	"github.com/vigolium/vigolium/pkg/modules/active/express_directory_listing"
	"github.com/vigolium/vigolium/pkg/modules/active/express_trust_proxy_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/fastapi_auth_inconsistency"
	"github.com/vigolium/vigolium/pkg/modules/active/fastapi_docs_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/fastify_hono_probe"
	"github.com/vigolium/vigolium/pkg/modules/active/file_upload_scan"
	"github.com/vigolium/vigolium/pkg/modules/active/firebase_auth_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/firebase_functions_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/firebase_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/firebase_rtdb_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/firebase_storage_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/flask_werkzeug_debugger"
	"github.com/vigolium/vigolium/pkg/modules/active/forbidden_bypass"
	"github.com/vigolium/vigolium/pkg/modules/active/go_debug_endpoint_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/graphql_scan"
	"github.com/vigolium/vigolium/pkg/modules/active/host_header_injection"
	"github.com/vigolium/vigolium/pkg/modules/active/http_method_tampering"
	"github.com/vigolium/vigolium/pkg/modules/active/http_request_smuggling"
	"github.com/vigolium/vigolium/pkg/modules/active/idor_detection"
	"github.com/vigolium/vigolium/pkg/modules/active/idor_guid"
	"github.com/vigolium/vigolium/pkg/modules/active/iis_cookieless_source_disclosure"
	"github.com/vigolium/vigolium/pkg/modules/active/iis_extension_confusion_bypass"
	"github.com/vigolium/vigolium/pkg/modules/active/iis_shortname_discovery"
	"github.com/vigolium/vigolium/pkg/modules/active/input_behavior_probe"
	"github.com/vigolium/vigolium/pkg/modules/active/insecure_deserialization"
	"github.com/vigolium/vigolium/pkg/modules/active/internal_header_probe"
	"github.com/vigolium/vigolium/pkg/modules/active/java_appserver_console"
	"github.com/vigolium/vigolium/pkg/modules/active/java_sensitive_files"
	"github.com/vigolium/vigolium/pkg/modules/active/joomla_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/joomla_user_enum"
	"github.com/vigolium/vigolium/pkg/modules/active/js_devserver_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/jsonp_callback"
	"github.com/vigolium/vigolium/pkg/modules/active/jwt_vulnerability"
	"github.com/vigolium/vigolium/pkg/modules/active/laravel_admin_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/laravel_devtool_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/laravel_ignition_rce"
	"github.com/vigolium/vigolium/pkg/modules/active/laravel_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/laravel_sensitive_files"
	"github.com/vigolium/vigolium/pkg/modules/active/ldap_injection"
	"github.com/vigolium/vigolium/pkg/modules/active/lfi_generic"
	"github.com/vigolium/vigolium/pkg/modules/active/lfi_path_traversal"
	"github.com/vigolium/vigolium/pkg/modules/active/log4shell_probe"
	"github.com/vigolium/vigolium/pkg/modules/active/magento_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/mass_assignment"
	"github.com/vigolium/vigolium/pkg/modules/active/mcp_batch_abuse"
	"github.com/vigolium/vigolium/pkg/modules/active/mcp_completion_enum"
	"github.com/vigolium/vigolium/pkg/modules/active/mcp_dos_amplification"
	"github.com/vigolium/vigolium/pkg/modules/active/mcp_method_enum"
	"github.com/vigolium/vigolium/pkg/modules/active/mcp_origin_rebinding"
	"github.com/vigolium/vigolium/pkg/modules/active/mcp_prompt_fuzz"
	"github.com/vigolium/vigolium/pkg/modules/active/mcp_resource_fuzz"
	"github.com/vigolium/vigolium/pkg/modules/active/mcp_server_probe"
	"github.com/vigolium/vigolium/pkg/modules/active/mcp_session_checks"
	"github.com/vigolium/vigolium/pkg/modules/active/mcp_tool_definition_drift"
	"github.com/vigolium/vigolium/pkg/modules/active/mcp_tool_fuzz"
	"github.com/vigolium/vigolium/pkg/modules/active/metaframework_probe"
	"github.com/vigolium/vigolium/pkg/modules/active/nextjs_chunk_audit"
	"github.com/vigolium/vigolium/pkg/modules/active/nextjs_data_leakage"
	"github.com/vigolium/vigolium/pkg/modules/active/nextjs_draft_mode_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/nextjs_image_ssrf"
	"github.com/vigolium/vigolium/pkg/modules/active/nextjs_middleware_bypass"
	"github.com/vigolium/vigolium/pkg/modules/active/nextjs_version_audit"
	"github.com/vigolium/vigolium/pkg/modules/active/nginx_off_by_slash"
	"github.com/vigolium/vigolium/pkg/modules/active/nginx_path_escape"
	"github.com/vigolium/vigolium/pkg/modules/active/nosqli_error_based"
	"github.com/vigolium/vigolium/pkg/modules/active/nosqli_operator_injection"
	"github.com/vigolium/vigolium/pkg/modules/active/oast_probe"
	"github.com/vigolium/vigolium/pkg/modules/active/oauth_misconfiguration"
	"github.com/vigolium/vigolium/pkg/modules/active/open_redirect"
	"github.com/vigolium/vigolium/pkg/modules/active/open_redirect_confusion"
	"github.com/vigolium/vigolium/pkg/modules/active/path_normalization"
	"github.com/vigolium/vigolium/pkg/modules/active/pdf_generation_injection"
	"github.com/vigolium/vigolium/pkg/modules/active/php_composer_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/php_debug_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/php_framework_debug"
	"github.com/vigolium/vigolium/pkg/modules/active/php_path_info_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/php_source_disclosure"
	"github.com/vigolium/vigolium/pkg/modules/active/powerpages_dataverse_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/prototype_pollution"
	"github.com/vigolium/vigolium/pkg/modules/active/proxy_header_trust"
	"github.com/vigolium/vigolium/pkg/modules/active/proxy_pingback"
	"github.com/vigolium/vigolium/pkg/modules/active/race_interference"
	"github.com/vigolium/vigolium/pkg/modules/active/rails_action_mailbox_probe"
	"github.com/vigolium/vigolium/pkg/modules/active/rails_active_storage_probe"
	"github.com/vigolium/vigolium/pkg/modules/active/rails_admin_dashboard"
	"github.com/vigolium/vigolium/pkg/modules/active/rails_info_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/rails_sensitive_files"
	"github.com/vigolium/vigolium/pkg/modules/active/reflected_ssti"
	"github.com/vigolium/vigolium/pkg/modules/active/response_header_injection"
	"github.com/vigolium/vigolium/pkg/modules/active/reverse_proxy_path_confusion"
	"github.com/vigolium/vigolium/pkg/modules/active/routing_ssrf"
	"github.com/vigolium/vigolium/pkg/modules/active/salesforce_aura_apex_execution"
	"github.com/vigolium/vigolium/pkg/modules/active/salesforce_aura_object_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/salesforce_aura_record_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/salesforce_lightning_debug_mode"
	"github.com/vigolium/vigolium/pkg/modules/active/sensitive_file_discovery"
	"github.com/vigolium/vigolium/pkg/modules/active/servicenow_kb_widget_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/servicenow_widget_data_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/session_fixation"
	"github.com/vigolium/vigolium/pkg/modules/active/smart_behavior_detection"
	"github.com/vigolium/vigolium/pkg/modules/active/spring_actuator_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/spring_boot_admin_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/spring_cloud_config_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/spring_data_rest_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/spring_debug_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/spring_gateway_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/spring_h2_console_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/spring_jolokia_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/sqli_boolean_blind"
	"github.com/vigolium/vigolium/pkg/modules/active/sqli_error_based"
	"github.com/vigolium/vigolium/pkg/modules/active/sqli_out_of_band"
	"github.com/vigolium/vigolium/pkg/modules/active/sqli_time_blind"
	"github.com/vigolium/vigolium/pkg/modules/active/ssrf_blind"
	"github.com/vigolium/vigolium/pkg/modules/active/ssrf_detection"
	"github.com/vigolium/vigolium/pkg/modules/active/ssrf_filter_bypass"
	"github.com/vigolium/vigolium/pkg/modules/active/ssrf_protocol_smuggling"
	"github.com/vigolium/vigolium/pkg/modules/active/ssti_blind"
	"github.com/vigolium/vigolium/pkg/modules/active/ssti_detection"
	"github.com/vigolium/vigolium/pkg/modules/active/struts_ognl_injection"
	"github.com/vigolium/vigolium/pkg/modules/active/subdomain_takeover"
	"github.com/vigolium/vigolium/pkg/modules/active/suspect_transform"
	"github.com/vigolium/vigolium/pkg/modules/active/swagger_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/symfony_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/tls_cert_recon"
	"github.com/vigolium/vigolium/pkg/modules/active/tls_protocol_cipher_audit"
	"github.com/vigolium/vigolium/pkg/modules/active/tomcat_manager_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/unauth_service_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/upgrade_routing_ssrf"
	"github.com/vigolium/vigolium/pkg/modules/active/web_cache_poisoning"
	"github.com/vigolium/vigolium/pkg/modules/active/websocket_security"
	"github.com/vigolium/vigolium/pkg/modules/active/wp_ajax_exposure"
	"github.com/vigolium/vigolium/pkg/modules/active/wp_misconfig"
	"github.com/vigolium/vigolium/pkg/modules/active/wp_user_enum"
	"github.com/vigolium/vigolium/pkg/modules/active/wp_xmlrpc"
	"github.com/vigolium/vigolium/pkg/modules/active/ws_cswsh"
	"github.com/vigolium/vigolium/pkg/modules/active/ws_injection"
	"github.com/vigolium/vigolium/pkg/modules/active/xml_saml_security"
	"github.com/vigolium/vigolium/pkg/modules/active/xpath_injection"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_dom_confirm"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_stored"
	"github.com/vigolium/vigolium/pkg/modules/active/xxe_generic"
)

// registerActiveModules registers every built-in active scanner module.
// Split out of default_registry.go; order is preserved from the original chain.
func registerActiveModules(r *Registry) {
	// Active modules - XSS Light (4 specialized scanners)
	r.RegisterActive(xsslightscanner.NewURLParamsScanner())
	r.RegisterActive(xsslightscanner.NewPathScanner())
	r.RegisterActive(xsslightscanner.NewParamDiscoveryScanner())
	r.RegisterActive(xsslightscanner.NewEncodedScanner())
	// Active modules - XSS DOM Confirm (browser-confirmed reflected + DOM)
	r.RegisterActive(xss_dom_confirm.New())
	// Active modules - Stored XSS (browser-confirmed persistent)
	r.RegisterActive(xss_stored.New())
	// Active modules - Injection
	r.RegisterActive(reflected_ssti.New())
	r.RegisterActive(ssti_detection.New())
	r.RegisterActive(csti_detection.New())
	r.RegisterActive(angular_template_injection.New())
	r.RegisterActive(lfi_generic.New())
	r.RegisterActive(lfi_path_traversal.New())
	r.RegisterActive(sqli_error_based.New())
	r.RegisterActive(sqli_boolean_blind.New())
	r.RegisterActive(sqli_time_blind.New())
	r.RegisterActive(sqli_out_of_band.New())
	r.RegisterActive(nosqli_error_based.New())
	r.RegisterActive(nosqli_operator_injection.New())
	r.RegisterActive(crlf_injection.New())
	r.RegisterActive(response_header_injection.New())
	r.RegisterActive(code_exec.New())
	r.RegisterActive(command_injection_echo.New())
	r.RegisterActive(command_injection_oast.New())
	r.RegisterActive(command_injection_timing.New())
	r.RegisterActive(input_behavior_probe.New())
	r.RegisterActive(xxe_generic.New())
	r.RegisterActive(insecure_deserialization.New())
	// Active modules - SSRF
	r.RegisterActive(ssrf_detection.New())
	r.RegisterActive(ssrf_blind.New())
	r.RegisterActive(ssrf_filter_bypass.New())
	r.RegisterActive(ssrf_protocol_smuggling.New())
	// Active modules - Routing-based SSRF (request-line; "Cracking the lens")
	r.RegisterActive(routing_ssrf.New())
	r.RegisterActive(unauth_service_exposure.New())
	r.RegisterActive(upgrade_routing_ssrf.New())
	// Active modules - SSTI (Blind)
	r.RegisterActive(ssti_blind.New())
	// Active modules - OAST (Out-of-Band)
	r.RegisterActive(oast_probe.New())
	r.RegisterActive(proxy_pingback.New())
	// Active modules - Misconfig
	r.RegisterActive(cors_misconfiguration.New())
	r.RegisterActive(internal_header_probe.New())
	r.RegisterActive(spring_actuator_misconfig.New())
	r.RegisterActive(go_debug_endpoint_exposure.New())
	r.RegisterActive(host_header_injection.New())
	r.RegisterActive(web_cache_poisoning.New())
	r.RegisterActive(prototype_pollution.New())
	r.RegisterActive(client_prototype_pollution.New())
	// Active modules - Diff-based
	r.RegisterActive(path_normalization.New())
	r.RegisterActive(nginx_off_by_slash.New())
	r.RegisterActive(nginx_path_escape.New())
	r.RegisterActive(reverse_proxy_path_confusion.New())
	r.RegisterActive(session_fixation.New())
	r.RegisterActive(smart_behavior_detection.New())
	r.RegisterActive(suspect_transform.New())
	r.RegisterActive(backslash_transformation.New())
	// Active modules - Race Conditions
	r.RegisterActive(race_interference.New())
	// Active modules - XML Security
	r.RegisterActive(xml_saml_security.New())
	r.RegisterActive(xpath_injection.New())
	// Active modules - JWT
	r.RegisterActive(jwt_vulnerability.New())
	// Active modules - HTTP Smuggling
	r.RegisterActive(http_request_smuggling.New())
	// Active modules - GraphQL
	r.RegisterActive(graphql_scan.New())
	// Active modules - File Upload
	r.RegisterActive(file_upload_scan.New())
	// Active modules - Default Credentials
	r.RegisterActive(default_credentials.New())
	// Active modules - Access Control
	r.RegisterActive(forbidden_bypass.New())
	r.RegisterActive(http_method_tampering.New())
	r.RegisterActive(csrf_verify.New())
	r.RegisterActive(idor_detection.New())
	r.RegisterActive(authz_compare.New())
	r.RegisterActive(mass_assignment.New())
	// Active modules - Discovery
	r.RegisterActive(sensitive_file_discovery.New())
	r.RegisterActive(backup_file_discovery.New())
	r.RegisterActive(iis_shortname_discovery.New())
	r.RegisterActive(iis_cookieless_source_disclosure.New())
	r.RegisterActive(iis_extension_confusion_bypass.New())
	// Active modules - JSONP
	r.RegisterActive(jsonp_callback.New())
	// Active modules - Open Redirect
	r.RegisterActive(open_redirect.New())
	r.RegisterActive(open_redirect_confusion.New())
	// Active modules - WebSocket
	r.RegisterActive(websocket_security.New())
	r.RegisterActive(ws_injection.New())
	r.RegisterActive(ws_cswsh.New())
	// Active modules - Rate Limiting
	r.RegisterActive(api_rate_limit_bypass.New())
	// Active modules - JS Framework Security
	r.RegisterActive(nextjs_data_leakage.New())
	r.RegisterActive(nextjs_middleware_bypass.New())
	r.RegisterActive(nextjs_image_ssrf.New())
	r.RegisterActive(nextjs_draft_mode_exposure.New())
	r.RegisterActive(nextjs_version_audit.New())
	r.RegisterActive(nextjs_chunk_audit.New())
	r.RegisterActive(js_devserver_exposure.New())
	// Active modules - WordPress Security
	r.RegisterActive(wp_misconfig.New())
	r.RegisterActive(wp_xmlrpc.New())
	r.RegisterActive(wp_user_enum.New())
	r.RegisterActive(wp_ajax_exposure.New())
	// Active modules - Drupal Security
	r.RegisterActive(drupal_misconfig.New())
	r.RegisterActive(drupal_user_enum.New())
	// Active modules - Joomla Security
	r.RegisterActive(joomla_misconfig.New())
	r.RegisterActive(joomla_user_enum.New())
	// Active modules - Adobe Experience Manager Security
	r.RegisterActive(aem_console_exposure.New())
	r.RegisterActive(aem_content_discovery.New())
	r.RegisterActive(aem_cloudsettings_injection.New())
	r.RegisterActive(aem_sensitive_servlet.New())
	r.RegisterActive(aem_dispatcher_bypass.New())
	r.RegisterActive(aem_default_credentials.New())
	r.RegisterActive(aem_xss.New())
	r.RegisterActive(aem_ssrf.New())
	r.RegisterActive(aem_oob_injection.New())
	r.RegisterActive(aem_xxe.New())
	r.RegisterActive(aem_rce.New())
	// Active modules - Cross-CMS Security
	r.RegisterActive(cms_installer_exposure.New())
	// Active modules - Firebase Security
	r.RegisterActive(firebase_misconfig.New())
	r.RegisterActive(firebase_rtdb_exposure.New())
	r.RegisterActive(firebase_storage_exposure.New())
	r.RegisterActive(firebase_auth_misconfig.New())
	r.RegisterActive(firebase_functions_exposure.New())
	// Active modules - PHP Security
	r.RegisterActive(php_debug_exposure.New())
	r.RegisterActive(php_source_disclosure.New())
	r.RegisterActive(php_composer_exposure.New())
	r.RegisterActive(php_framework_debug.New())
	r.RegisterActive(php_path_info_misconfig.New())
	// Active modules - PHP Framework Security
	r.RegisterActive(laravel_misconfig.New())
	r.RegisterActive(laravel_ignition_rce.New())
	r.RegisterActive(laravel_devtool_exposure.New())
	r.RegisterActive(laravel_sensitive_files.New())
	r.RegisterActive(laravel_admin_exposure.New())
	r.RegisterActive(symfony_misconfig.New())
	r.RegisterActive(magento_misconfig.New())
	// Active modules - Cloud Storage Security
	r.RegisterActive(cloud_storage_listing.New())
	r.RegisterActive(cdn_object_traversal_listing.New())
	r.RegisterActive(cloud_bucket_takeover.New())
	r.RegisterActive(cloud_origin_bypass.New())
	r.RegisterActive(cloud_public_read.New())
	// Active modules - ASP.NET Security
	r.RegisterActive(aspnet_misconfig.New())
	r.RegisterActive(aspnet_sensitive_files.New())
	r.RegisterActive(aspnet_viewstate_scan.New())
	r.RegisterActive(aspnet_service_exposure.New())
	r.RegisterActive(aspnet_blazor_exposure.New())
	r.RegisterActive(aspnet_health_exposure.New())
	r.RegisterActive(aspnet_identity_probe.New())
	// Active modules - Java/Spring Security
	r.RegisterActive(spring_h2_console_exposure.New())
	r.RegisterActive(spring_jolokia_exposure.New())
	r.RegisterActive(spring_debug_exposure.New())
	r.RegisterActive(spring_cloud_config_exposure.New())
	r.RegisterActive(spring_gateway_exposure.New())
	r.RegisterActive(spring_data_rest_exposure.New())
	r.RegisterActive(spring_boot_admin_exposure.New())
	r.RegisterActive(java_sensitive_files.New())
	r.RegisterActive(java_appserver_console.New())
	r.RegisterActive(tomcat_manager_exposure.New())
	r.RegisterActive(struts_ognl_injection.New())
	r.RegisterActive(log4shell_probe.New())
	// Active modules - LDAP Injection
	r.RegisterActive(ldap_injection.New())
	// Active modules - IDOR GUID
	r.RegisterActive(idor_guid.New())
	// Active modules - Cache Deception
	r.RegisterActive(cache_deception.New())
	// Active modules - Cache-Poisoned DoS (CPDoS)
	r.RegisterActive(cpdos.New())
	// Active modules - Subdomain Takeover
	r.RegisterActive(subdomain_takeover.New())
	// Active modules - PDF Generation Injection
	r.RegisterActive(pdf_generation_injection.New())
	// Active modules - Express/NestJS Security
	r.RegisterActive(express_debug_probe.New())
	r.RegisterActive(express_trust_proxy_misconfig.New())
	r.RegisterActive(express_directory_listing.New())
	// Active modules - Common Directory Listing
	r.RegisterActive(common_directory_listing.New())
	// Active modules - Rails Security
	r.RegisterActive(rails_info_exposure.New())
	r.RegisterActive(rails_sensitive_files.New())
	r.RegisterActive(rails_admin_dashboard.New())
	r.RegisterActive(rails_active_storage_probe.New())
	r.RegisterActive(rails_action_mailbox_probe.New())
	// Active modules - API Spec Discovery & Ingestion
	r.RegisterActive(api_spec_ingest.New())
	r.RegisterActive(swagger_exposure.New())
	// Active modules - Third-party dashboards / consoles / self-hosted apps
	r.RegisterActive(dashboard_exposure.New())
	// Active modules - Python/Django/Flask/FastAPI Security
	r.RegisterActive(fastapi_docs_exposure.New())
	r.RegisterActive(fastapi_auth_inconsistency.New())
	r.RegisterActive(django_debug_exposure.New())
	r.RegisterActive(django_admin_exposure.New())
	r.RegisterActive(django_debug_toolbar_exposure.New())
	r.RegisterActive(django_browsable_api_exposure.New())
	r.RegisterActive(flask_werkzeug_debugger.New())
	r.RegisterActive(proxy_header_trust.New())
	// Active modules - Auth/API Security
	r.RegisterActive(bfla_detection.New())
	r.RegisterActive(oauth_misconfiguration.New())
	r.RegisterActive(api_key_url_exposure.New())
	// Active modules - TLS / Certificate Recon
	r.RegisterActive(tls_cert_recon.New())
	r.RegisterActive(tls_protocol_cipher_audit.New())
	// Active modules - Fastify/Hono Security
	r.RegisterActive(fastify_hono_probe.New())
	// Active modules - Meta-Framework Security
	r.RegisterActive(metaframework_probe.New())
	// Active modules - MCP Security
	r.RegisterActive(mcp_server_probe.New())
	r.RegisterActive(mcp_tool_fuzz.New())
	r.RegisterActive(mcp_resource_fuzz.New())
	r.RegisterActive(mcp_prompt_fuzz.New())
	r.RegisterActive(mcp_completion_enum.New())
	r.RegisterActive(mcp_method_enum.New())
	r.RegisterActive(mcp_session_checks.New())
	r.RegisterActive(mcp_batch_abuse.New())
	r.RegisterActive(mcp_origin_rebinding.New())
	r.RegisterActive(mcp_tool_definition_drift.New())
	r.RegisterActive(mcp_dos_amplification.New())
	// Active modules - SaaS Data Exposure (Salesforce / ServiceNow / Power Pages)
	r.RegisterActive(salesforce_aura_object_exposure.New())
	r.RegisterActive(salesforce_aura_record_exposure.New())
	r.RegisterActive(salesforce_aura_apex_execution.New())
	r.RegisterActive(salesforce_lightning_debug_mode.New())
	r.RegisterActive(servicenow_widget_data_exposure.New())
	r.RegisterActive(servicenow_kb_widget_exposure.New())
	r.RegisterActive(powerpages_dataverse_exposure.New())
}
