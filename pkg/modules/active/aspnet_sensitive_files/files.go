package aspnet_sensitive_files

import "github.com/vigolium/vigolium/pkg/types/severity"

type sensitiveFile struct {
	path        string
	name        string
	markers     []string
	antiMarkers []string
	sev         severity.Severity
	desc        string
}

var defaultAntiMarkers = []string{"<html", "<!DOCTYPE", "404", "Not Found"}

var sensitiveFiles = []sensitiveFile{
	{
		path:        "/web.config",
		name:        "ASP.NET Web.config",
		markers:     []string{"<configuration>", "<system.web>"},
		antiMarkers: defaultAntiMarkers,
		sev:         severity.Critical,
		desc:        "ASP.NET web.config file exposed, potentially revealing connection strings, authentication settings, and application secrets",
	},
	{
		path:        "/web.config.bak",
		name:        "ASP.NET Web.config Backup",
		markers:     []string{"<configuration>", "<system.web>"},
		antiMarkers: defaultAntiMarkers,
		sev:         severity.Critical,
		desc:        "ASP.NET web.config backup file exposed with potential credentials and configuration details",
	},
	{
		path:        "/web.config.old",
		name:        "ASP.NET Web.config Old",
		markers:     []string{"<configuration>", "<system.web>"},
		antiMarkers: defaultAntiMarkers,
		sev:         severity.Critical,
		desc:        "Old ASP.NET web.config file exposed with potential credentials and configuration details",
	},
	{
		path:        "/Web.Debug.config",
		name:        "ASP.NET Debug Config Transform",
		markers:     []string{"<configuration>", "xdt:Transform"},
		antiMarkers: defaultAntiMarkers,
		sev:         severity.High,
		desc:        "ASP.NET debug configuration transform file exposed, potentially revealing debug-specific settings",
	},
	{
		path:        "/Web.Release.config",
		name:        "ASP.NET Release Config Transform",
		markers:     []string{"<configuration>", "xdt:Transform"},
		antiMarkers: defaultAntiMarkers,
		sev:         severity.High,
		desc:        "ASP.NET release configuration transform file exposed, potentially revealing production settings",
	},
	{
		path:        "/appsettings.json",
		name:        "ASP.NET Core appsettings.json",
		markers:     []string{"ConnectionStrings", "Logging"},
		antiMarkers: defaultAntiMarkers,
		sev:         severity.Critical,
		desc:        "ASP.NET Core appsettings.json exposed, potentially containing connection strings and API keys",
	},
	{
		path:        "/appsettings.Development.json",
		name:        "ASP.NET Core Development Settings",
		markers:     []string{"ConnectionStrings", "Logging"},
		antiMarkers: defaultAntiMarkers,
		sev:         severity.Critical,
		desc:        "ASP.NET Core development settings file exposed with potential debug credentials",
	},
	{
		path:        "/connectionStrings.config",
		name:        "Connection Strings Config",
		markers:     []string{"<connectionStrings>"},
		antiMarkers: defaultAntiMarkers,
		sev:         severity.Critical,
		desc:        "ASP.NET connection strings configuration file exposed with database credentials",
	},
	{
		path:        "/Global.asax",
		name:        "Global.asax",
		markers:     []string{"Application_Start", "<%@"},
		antiMarkers: defaultAntiMarkers,
		sev:         severity.Medium,
		desc:        "ASP.NET Global.asax file exposed, revealing application lifecycle event handlers",
	},
	{
		path:        "/App_Data/",
		name:        "App_Data Directory",
		markers:     []string{"<pre>", "Parent Directory", "Index of", "<DIR>"},
		antiMarkers: []string{"404", "Not Found", "403", "Forbidden"},
		sev:         severity.High,
		desc:        "ASP.NET App_Data directory listing exposed, potentially revealing database files and application data",
	},
	{
		path:        "/bin/",
		name:        "Bin Directory",
		markers:     []string{"<pre>", "Parent Directory", "Index of", "<DIR>", ".dll"},
		antiMarkers: []string{"404", "Not Found", "403", "Forbidden"},
		sev:         severity.High,
		desc:        "ASP.NET bin directory listing exposed, potentially allowing download of compiled assemblies",
	},
	{
		path:        "/aspnet_client/",
		name:        "ASP.NET Client Directory",
		markers:     []string{"<pre>", "Parent Directory", "Index of", "<DIR>"},
		antiMarkers: []string{"404", "Not Found", "403", "Forbidden"},
		sev:         severity.Low,
		desc:        "ASP.NET client-side files directory exposed, confirming ASP.NET deployment",
	},
	{
		path:        "/App_Offline.htm",
		name:        "App_Offline.htm",
		markers:     []string{"offline", "maintenance", "unavailable"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Low,
		desc:        "ASP.NET App_Offline.htm file found, may indicate deployment state information",
	},
	{
		path:        "/packages.config",
		name:        "NuGet Packages Config",
		markers:     []string{"<packages>", "<package id="},
		antiMarkers: defaultAntiMarkers,
		sev:         severity.Medium,
		desc:        "NuGet packages.config exposed, revealing installed package dependencies and versions",
	},
	{
		path:        "/nuget.config",
		name:        "NuGet Config",
		markers:     []string{"<configuration>", "packageSources"},
		antiMarkers: defaultAntiMarkers,
		sev:         severity.Medium,
		desc:        "NuGet configuration file exposed, potentially revealing private package feed URLs and credentials",
	},
	{
		path:        "/clientaccesspolicy.xml",
		name:        "Silverlight Client Access Policy",
		markers:     []string{"<access-policy>", "<cross-domain-access>"},
		antiMarkers: defaultAntiMarkers,
		sev:         severity.Medium,
		desc:        "Silverlight client access policy file found with potentially overly permissive cross-domain settings",
	},
	{
		path:        "/crossdomain.xml",
		name:        "Flash Cross-Domain Policy",
		markers:     []string{"<cross-domain-policy>", "<allow-access-from"},
		antiMarkers: defaultAntiMarkers,
		sev:         severity.Medium,
		desc:        "Flash cross-domain policy file found with potentially overly permissive settings",
	},
	{
		path:        "/Global.asa",
		name:        "Classic ASP Global.asa",
		markers:     []string{"Application_OnStart", "Session_OnStart"},
		antiMarkers: defaultAntiMarkers,
		sev:         severity.High,
		desc:        "Classic ASP Global.asa file exposed, revealing application lifecycle configuration",
	},
	{
		path:        "/includes/config.inc",
		name:        "Classic ASP Config Include",
		markers:     []string{"ADODB", "Connection", "password"},
		antiMarkers: defaultAntiMarkers,
		sev:         severity.Critical,
		desc:        "Classic ASP configuration include file exposed with potential database credentials",
	},
	{
		path:        "/includes/db.inc",
		name:        "Classic ASP DB Include",
		markers:     []string{"ADODB", "Connection", "password"},
		antiMarkers: defaultAntiMarkers,
		sev:         severity.Critical,
		desc:        "Classic ASP database include file exposed with potential connection credentials",
	},
	{
		path:        "/includes/conn.inc",
		name:        "Classic ASP Connection Include",
		markers:     []string{"ADODB", "Connection", "password"},
		antiMarkers: defaultAntiMarkers,
		sev:         severity.Critical,
		desc:        "Classic ASP database connection include file exposed with potential credentials",
	},
}
