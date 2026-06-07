package wp_ajax_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

type ajaxAction struct {
	name   string
	plugin string
	desc   string
	sev    severity.Severity
	// markers are AND-of-OR groups of plugin/action-specific substrings (all
	// lowercase) that confirm the response actually came from this plugin's
	// registered handler. A genuinely wired-up wp_ajax_nopriv_* handler echoes
	// these even in its error / permission / missing-parameter responses;
	// a generic CDN / WAF / SPA error page (e.g. the help.grab.com
	// "load-failed … Refresh" page that produced a false positive) contains
	// none of them. The body is matched case-insensitively via
	// modkit.MatchAllGroups — every group must have at least one hit, so a
	// finding fires only on the co-occurrence the real endpoint emits.
	//
	// Without markers the module would fire on ANY 200 response that merely
	// differs from the unregistered-action control probe, which is exactly the
	// behaviour that mislabelled an unrelated error page as a critical export
	// vulnerability.
	markers [][]string
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
		markers: [][]string{{
			"revslider", "rev_slider", "revolution slider", "slider revolution",
			"revslider_show_image", "img_id", "show_image",
		}},
	},
	// Duplicator - backup download
	{
		name:   "duplicator_download",
		plugin: "Duplicator",
		desc:   "Known backup file download vulnerability allowing full site takeover",
		sev:    severity.Critical,
		markers: [][]string{{
			"duplicator", "dup-installer", "dup_archive", "duplicator_download",
			"installer.php", "duparchive",
		}},
	},
	// WP File Manager - arbitrary file operations
	{
		name:   "connector",
		plugin: "WP File Manager",
		desc:   "Known RCE vulnerability via elFinder connector",
		sev:    severity.Critical,
		// elFinder's connector replies with a JSON error naming the missing
		// command, e.g. {"error":["errCmdReq"]} / {"error":["errUnknownCmd"]}.
		markers: [][]string{{
			"errcmdreq", "errunknowncmd", "errcmdparams", "errcmd", "errrequest",
			"elfinder", "wp file manager", "file_manager", "wp-file-manager",
		}},
	},
	// UpdraftPlus - backup download
	{
		name:   "updraft_download_backup",
		plugin: "UpdraftPlus",
		desc:   "Known backup download vulnerability",
		sev:    severity.High,
		markers: [][]string{{
			"updraftplus", "updraft", "updraft_download", "nonce check failed",
		}},
	},
	// Formidable Forms
	{
		name:   "frm_forms_preview",
		plugin: "Formidable Forms",
		desc:   "Unauthenticated form preview access",
		sev:    severity.Medium,
		markers: [][]string{{
			"formidable", "frm_forms", "frm-", "frm_", "frm_forms_preview",
			"with_frm_style",
		}},
	},
	// WooCommerce
	{
		name:   "woocommerce_apply_coupon",
		plugin: "WooCommerce",
		desc:   "Unauthenticated coupon application may indicate exposed commerce actions",
		sev:    severity.Low,
		markers: [][]string{{
			"woocommerce", "wc-ajax", "wc_ajax", "apply_coupon", "coupon_applied",
			"cart_totals", "woocommerce-error", "woocommerce-message",
		}},
	},
	// All-in-One WP Migration
	{
		name:   "ai1wm_export",
		plugin: "All-in-One WP Migration",
		desc:   "Known unauthenticated export vulnerability allowing full site backup download",
		sev:    severity.Critical,
		markers: [][]string{{
			"ai1wm", "all-in-one-wp-migration", "all-in-one wp migration",
			"servmask", "secret_key", "ai1wm_export",
		}},
	},
	// Essential Addons for Elementor
	{
		name:   "eael_select_2_get_posts",
		plugin: "Essential Addons for Elementor",
		desc:   "Known privilege escalation and data exposure vulnerability",
		sev:    severity.High,
		markers: [][]string{{
			"eael", "essential addons", "eael_select", "essential-addons",
		}},
	},
	// Ultimate Member
	{
		name:   "um_get_members",
		plugin: "Ultimate Member",
		desc:   "User data exposure via unauthenticated member listing",
		sev:    severity.Medium,
		markers: [][]string{{
			"ultimate member", "ultimatemember", "um_get_members", "um_members",
			"um-member", "um_search",
		}},
	},
	// InfiniteWP Client
	{
		name:   "iwp_mmb_set_noiframe",
		plugin: "InfiniteWP Client",
		desc:   "Known authentication bypass vulnerability",
		sev:    severity.Critical,
		markers: [][]string{{
			"infinitewp", "iwp_mmb", "iwp_", "mmb_", "noiframe",
		}},
	},
	// ThemeGrill Demo Importer
	{
		name:   "reset_flavor",
		plugin: "ThemeGrill Demo Importer",
		desc:   "Known database reset vulnerability",
		sev:    severity.Critical,
		markers: [][]string{{
			"themegrill", "demo importer", "reset_flavor", "tg_demo_importer",
			"tg-demo",
		}},
	},
	// WP GDPR Compliance
	{
		name:   "wpgdprc_process_action",
		plugin: "WP GDPR Compliance",
		desc:   "Known privilege escalation via option update",
		sev:    severity.Critical,
		markers: [][]string{{
			"wpgdprc", "wp gdpr compliance", "wp-gdpr-compliance", "gdpr",
		}},
	},
	// ProfilePress (WP User Avatar)
	{
		name:   "pp_ajax_signup",
		plugin: "ProfilePress",
		desc:   "Unauthenticated user registration with potential privilege escalation",
		sev:    severity.High,
		markers: [][]string{{
			"profilepress", "pp_ajax_signup", "wp_user_avatar", "wpua", "presselite",
		}},
	},
	// Contact Form 7 Data Manager
	{
		name:   "cfdb7_before_send_mail",
		plugin: "Contact Form 7 DB",
		desc:   "Unauthenticated access to form submission data",
		sev:    severity.Medium,
		markers: [][]string{{
			"cfdb7", "cf7-database", "contact form 7", "cfdb", "cfdb7_before_send_mail",
		}},
	},
	// Jetstash
	{
		name:   "jetstash_clear_cache",
		plugin: "JetStash",
		desc:   "Unauthenticated cache manipulation",
		sev:    severity.Medium,
		markers: [][]string{{
			"jetstash", "jetstash_clear_cache", "jetstash-cache",
		}},
	},
}
