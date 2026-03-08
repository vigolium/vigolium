package rails_admin_dashboard

import "github.com/vigolium/vigolium/pkg/types/severity"

type probe struct {
	path        string
	name        string
	markers     []string
	antiMarkers []string
	sev         severity.Severity
	desc        string
}

var probes = []probe{
	{
		path:    "/sidekiq",
		name:    "Sidekiq Web UI",
		markers: []string{"Sidekiq"},
		sev:     severity.High,
		desc:    "Sidekiq Web UI is exposed, revealing background job queues, retry data, and potentially sensitive job arguments",
	},
	{
		path:    "/admin/sidekiq",
		name:    "Sidekiq Web UI (admin path)",
		markers: []string{"Sidekiq"},
		sev:     severity.High,
		desc:    "Sidekiq Web UI is exposed at admin path",
	},
	{
		path:    "/good_job",
		name:    "GoodJob Dashboard",
		markers: []string{"GoodJob"},
		sev:     severity.High,
		desc:    "GoodJob dashboard is exposed, revealing job payloads and schedules",
	},
	{
		path:    "/resque",
		name:    "Resque Dashboard",
		markers: []string{"Resque"},
		sev:     severity.High,
		desc:    "Resque dashboard is exposed, revealing background job data and worker status",
	},
	{
		path:    "/delayed_job",
		name:    "Delayed Job Dashboard",
		markers: []string{"Delayed::Job", "Delayed Job"},
		sev:     severity.High,
		desc:    "Delayed Job dashboard is exposed",
	},
	{
		path:    "/mini-profiler-resources/includes.js",
		name:    "rack-mini-profiler",
		markers: []string{"MiniProfiler"},
		sev:     severity.Medium,
		desc:    "rack-mini-profiler is enabled, potentially exposing performance traces, SQL queries, and internal timing data",
	},
	{
		path:    "/admin",
		name:    "ActiveAdmin Panel",
		markers: []string{"Active Admin", "activeadmin", "active_admin"},
		antiMarkers: []string{"WordPress", "wp-login", "Joomla", "Drupal"},
		sev:     severity.High,
		desc:    "ActiveAdmin panel is accessible, potentially allowing administrative operations",
	},
	{
		path:    "/rails_admin",
		name:    "RailsAdmin Panel",
		markers: []string{"RailsAdmin", "rails_admin"},
		sev:     severity.High,
		desc:    "RailsAdmin panel is accessible, potentially allowing full administrative control",
	},
	{
		path:    "/active_admin",
		name:    "ActiveAdmin Panel (alternate path)",
		markers: []string{"Active Admin", "activeadmin", "active_admin"},
		sev:     severity.High,
		desc:    "ActiveAdmin panel is accessible at alternate path",
	},
}
