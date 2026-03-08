package wp_ajax_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

type ajaxAction struct {
	name   string
	plugin string
	desc   string
	sev    severity.Severity
}

// vulnerableActions lists known wp_ajax_nopriv_* actions from popular plugins
// that have had public vulnerabilities. We only test for handler existence,
// not exploitation.
var vulnerableActions = []ajaxAction{
	// Revolution Slider - arbitrary file download
	{
		name:   "revslider_show_image",
		plugin: "Starter Templates (RevSlider)",
		desc:   "Known arbitrary file download vulnerability",
		sev:    severity.Critical,
	},
	// Duplicator - backup download
	{
		name:   "duplicator_download",
		plugin: "Duplicator",
		desc:   "Known backup file download vulnerability allowing full site takeover",
		sev:    severity.Critical,
	},
	// WP File Manager - arbitrary file operations
	{
		name:   "connector",
		plugin: "WP File Manager",
		desc:   "Known RCE vulnerability via elFinder connector",
		sev:    severity.Critical,
	},
	// UpdraftPlus - backup download
	{
		name:   "updraft_download_backup",
		plugin: "UpdraftPlus",
		desc:   "Known backup download vulnerability",
		sev:    severity.High,
	},
	// Formidable Forms
	{
		name:   "frm_forms_preview",
		plugin: "Formidable Forms",
		desc:   "Unauthenticated form preview access",
		sev:    severity.Medium,
	},
	// WooCommerce
	{
		name:   "woocommerce_apply_coupon",
		plugin: "WooCommerce",
		desc:   "Unauthenticated coupon application may indicate exposed commerce actions",
		sev:    severity.Low,
	},
	// All-in-One WP Migration
	{
		name:   "ai1wm_export",
		plugin: "All-in-One WP Migration",
		desc:   "Known unauthenticated export vulnerability allowing full site backup download",
		sev:    severity.Critical,
	},
	// Essential Addons for Elementor
	{
		name:   "eael_select_2_get_posts",
		plugin: "Essential Addons for Elementor",
		desc:   "Known privilege escalation and data exposure vulnerability",
		sev:    severity.High,
	},
	// Ultimate Member
	{
		name:   "um_get_members",
		plugin: "Ultimate Member",
		desc:   "User data exposure via unauthenticated member listing",
		sev:    severity.Medium,
	},
	// InfiniteWP Client
	{
		name:   "iwp_mmb_set_noiframe",
		plugin: "InfiniteWP Client",
		desc:   "Known authentication bypass vulnerability",
		sev:    severity.Critical,
	},
	// ThemeGrill Demo Importer
	{
		name:   "reset_flavor",
		plugin: "ThemeGrill Demo Importer",
		desc:   "Known database reset vulnerability",
		sev:    severity.Critical,
	},
	// WP GDPR Compliance
	{
		name:   "wpgdprc_process_action",
		plugin: "WP GDPR Compliance",
		desc:   "Known privilege escalation via option update",
		sev:    severity.Critical,
	},
	// ProfilePress (WP User Avatar)
	{
		name:   "pp_ajax_signup",
		plugin: "ProfilePress",
		desc:   "Unauthenticated user registration with potential privilege escalation",
		sev:    severity.High,
	},
	// Contact Form 7 Data Manager
	{
		name:   "cfdb7_before_send_mail",
		plugin: "Contact Form 7 DB",
		desc:   "Unauthenticated access to form submission data",
		sev:    severity.Medium,
	},
	// Jetstash
	{
		name:   "jetstash_clear_cache",
		plugin: "JetStash",
		desc:   "Unauthenticated cache manipulation",
		sev:    severity.Medium,
	},
}
