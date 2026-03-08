package aspnet_service_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

type probe struct {
	path        string
	name        string
	markers     []string
	antiMarkers []string
	sev         severity.Severity
	desc        string
}

var commonProbes = []probe{
	{
		path:        "/odata/$metadata",
		name:        "OData Metadata",
		markers:     []string{"<edmx:Edmx", "EntityType"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "OData service metadata endpoint exposed, revealing entity data model and available operations",
	},
	{
		path:        "/api/odata/$metadata",
		name:        "API OData Metadata",
		markers:     []string{"<edmx:Edmx", "EntityType"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "OData service metadata endpoint exposed under /api path, revealing entity data model",
	},
	{
		path:        "/_vti_bin/",
		name:        "SharePoint VTI Bin",
		markers:     []string{"<pre>", "Parent Directory", "Index of", ".asmx"},
		antiMarkers: []string{"404", "Not Found", "403", "Forbidden"},
		sev:         severity.Medium,
		desc:        "SharePoint _vti_bin directory exposed, revealing available web service endpoints",
	},
	{
		path:        "/Services/",
		name:        "Services Directory",
		markers:     []string{"<pre>", "Parent Directory", "Index of", ".svc", ".asmx"},
		antiMarkers: []string{"404", "Not Found", "403", "Forbidden"},
		sev:         severity.Low,
		desc:        "ASP.NET Services directory listing exposed, revealing available web service files",
	},
}

// WSDL markers for .asmx and .svc endpoints
var wsdlMarkers = []string{"<wsdl:definitions", "<definitions", "wsdl:types", "wsdl:portType"}
var discoMarkers = []string{"<discovery", "<contractRef", "<discoveryRef"}
var wcfFaultMarkers = []string{"<ExceptionDetail>", "<StackTrace>", "includeExceptionDetailInFaults"}
