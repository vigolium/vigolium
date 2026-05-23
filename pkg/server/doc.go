// Package server implements the REST API server (built on Fiber): traffic
// ingestion endpoints, scan and findings APIs, the agent run API, project
// scoping via the X-Project-UUID header, and the bundled Swagger UI. Handlers
// are composed from focused sub-structs and delegate scanning to pkg/core and
// agent runs to pkg/agent. See docs/server-mode/.
package server
