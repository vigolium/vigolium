//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/server"
)

// accessTestEnv wraps projectTestEnv with email-aware request helpers.
type accessTestEnv struct {
	*projectTestEnv
}

func newAccessTestEnv(t *testing.T) *accessTestEnv {
	t.Helper()
	return &accessTestEnv{newProjectTestEnv(t)}
}

// createProjectWithAccess creates a project with allowed_domains and allowed_emails.
func (env *accessTestEnv) createProjectWithAccess(t *testing.T, name string, domains, emails []string) string {
	t.Helper()
	body := fmt.Sprintf(`{"name":%q`, name)
	if domains != nil {
		b, _ := json.Marshal(domains)
		body += fmt.Sprintf(`,"allowed_domains":%s`, b)
	}
	if emails != nil {
		b, _ := json.Marshal(emails)
		body += fmt.Sprintf(`,"allowed_emails":%s`, b)
	}
	body += "}"

	resp := env.post(t, "/api/projects", body)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var project database.Project
	readJSON(t, resp, &project)
	require.NotEmpty(t, project.UUID)
	return project.UUID
}

// getWithEmail sends a GET with both X-Project-UUID and X-User-Email headers.
func (env *accessTestEnv) getWithEmail(t *testing.T, path, projectUUID, userEmail string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, env.url+path, nil)
	require.NoError(t, err)
	if projectUUID != "" {
		req.Header.Set("X-Project-UUID", projectUUID)
	}
	if userEmail != "" {
		req.Header.Set("X-User-Email", userEmail)
	}
	if env.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+env.apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// postWithEmail sends a POST with X-Project-UUID and X-User-Email headers.
func (env *accessTestEnv) postWithEmail(t *testing.T, path, body, projectUUID, userEmail string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, env.url+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if projectUUID != "" {
		req.Header.Set("X-Project-UUID", projectUUID)
	}
	if userEmail != "" {
		req.Header.Set("X-User-Email", userEmail)
	}
	if env.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+env.apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// ============================================================
// Project Access Control — E2E Tests
// ============================================================

func TestProjectAccess_OpenProject_AllowsAnyone(t *testing.T) {
	env := newAccessTestEnv(t)

	proj := env.createProjectWithAccess(t, "Open Project", nil, nil)

	// Any email → allowed
	resp := env.getWithEmail(t, "/api/http-records", proj, "random@example.com")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// No email → allowed
	resp = env.getWithEmail(t, "/api/http-records", proj, "")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestProjectAccess_AllowedEmails_ExactMatch(t *testing.T) {
	env := newAccessTestEnv(t)

	proj := env.createProjectWithAccess(t, "Email Restricted",
		nil, []string{"alice@acme.com", "bob@partner.io"})

	// Listed email → allowed
	resp := env.getWithEmail(t, "/api/http-records", proj, "alice@acme.com")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Other listed email → allowed
	resp = env.getWithEmail(t, "/api/http-records", proj, "bob@partner.io")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Unlisted email → denied
	resp = env.getWithEmail(t, "/api/http-records", proj, "eve@evil.com")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	resp.Body.Close()
}

func TestProjectAccess_AllowedEmails_CaseInsensitive(t *testing.T) {
	env := newAccessTestEnv(t)

	proj := env.createProjectWithAccess(t, "Case Test",
		nil, []string{"alice@acme.com"})

	resp := env.getWithEmail(t, "/api/http-records", proj, "Alice@ACME.COM")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestProjectAccess_AllowedDomains_DomainMatch(t *testing.T) {
	env := newAccessTestEnv(t)

	proj := env.createProjectWithAccess(t, "Domain Restricted",
		[]string{"@acme.com", "@partner.io"}, nil)

	// Matching domain → allowed
	resp := env.getWithEmail(t, "/api/http-records", proj, "anyone@acme.com")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	resp = env.getWithEmail(t, "/api/http-records", proj, "user@partner.io")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Non-matching domain → denied
	resp = env.getWithEmail(t, "/api/http-records", proj, "user@evil.com")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	resp.Body.Close()
}

func TestProjectAccess_AllowedDomains_CaseInsensitive(t *testing.T) {
	env := newAccessTestEnv(t)

	proj := env.createProjectWithAccess(t, "Domain Case Test",
		[]string{"@acme.com"}, nil)

	resp := env.getWithEmail(t, "/api/http-records", proj, "user@ACME.COM")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestProjectAccess_EmailsTakePriorityOverDomains(t *testing.T) {
	env := newAccessTestEnv(t)

	// Both set — emails list is non-empty so domains should be ignored
	proj := env.createProjectWithAccess(t, "Priority Test",
		[]string{"@acme.com"}, []string{"alice@acme.com"})

	// Listed email → allowed
	resp := env.getWithEmail(t, "/api/http-records", proj, "alice@acme.com")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Same domain but not in email list → denied
	resp = env.getWithEmail(t, "/api/http-records", proj, "bob@acme.com")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	resp.Body.Close()
}

func TestProjectAccess_NoEmailHeader_SkipsCheck(t *testing.T) {
	env := newAccessTestEnv(t)

	// Restricted project
	proj := env.createProjectWithAccess(t, "Skip Check",
		[]string{"@acme.com"}, []string{"alice@acme.com"})

	// No X-User-Email header → access check is skipped
	resp := env.getWithEmail(t, "/api/http-records", proj, "")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestProjectAccess_BlocksWriteEndpoints(t *testing.T) {
	env := newAccessTestEnv(t)

	proj := env.createProjectWithAccess(t, "Write Block",
		nil, []string{"alice@acme.com"})

	// Unauthorized user trying to ingest → denied
	resp := env.postWithEmail(t, "/api/ingest-http",
		`{"input_mode":"url","content":"http://evil.example.com/x"}`,
		proj, "eve@evil.com")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	resp.Body.Close()

	// Authorized user → allowed
	resp = env.postWithEmail(t, "/api/ingest-http",
		`{"input_mode":"url","content":"http://good.example.com/x"}`,
		proj, "alice@acme.com")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestProjectAccess_DomainMap_Endpoint(t *testing.T) {
	env := newAccessTestEnv(t)

	env.createProjectWithAccess(t, "Map A",
		[]string{"@acme.com"}, []string{"alice@external.com"})
	env.createProjectWithAccess(t, "Map B",
		[]string{"@acme.com", "@partner.io"}, nil)

	resp := env.get(t, "/api/projects/domain-map")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var domainMap struct {
		Domains map[string][]string `json:"domains"`
		Emails  map[string][]string `json:"emails"`
	}
	readJSON(t, resp, &domainMap)

	// @acme.com should appear in at least 2 projects
	assert.GreaterOrEqual(t, len(domainMap.Domains["@acme.com"]), 2,
		"@acme.com should map to at least 2 projects")

	// @partner.io should appear in at least 1 project
	assert.GreaterOrEqual(t, len(domainMap.Domains["@partner.io"]), 1)

	// alice@external.com should appear in at least 1 project
	assert.GreaterOrEqual(t, len(domainMap.Emails["alice@external.com"]), 1)
}

func TestProjectAccess_UpdateDomains_ChangesAccess(t *testing.T) {
	env := newAccessTestEnv(t)

	// Create project with @acme.com domain
	proj := env.createProjectWithAccess(t, "Update Access",
		[]string{"@acme.com"}, nil)

	// User from acme.com → allowed
	resp := env.getWithEmail(t, "/api/http-records", proj, "user@acme.com")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// User from partner.io → denied
	resp = env.getWithEmail(t, "/api/http-records", proj, "user@partner.io")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	resp.Body.Close()

	// Update project to add @partner.io
	resp = env.put(t, "/api/projects/"+proj, `{"allowed_domains":["@acme.com","@partner.io"]}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// User from partner.io → now allowed
	resp = env.getWithEmail(t, "/api/http-records", proj, "user@partner.io")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestProjectAccess_ClearDomainsOpensProject(t *testing.T) {
	env := newAccessTestEnv(t)

	// Create restricted project
	proj := env.createProjectWithAccess(t, "Clear Access",
		[]string{"@acme.com"}, nil)

	// Random user → denied
	resp := env.getWithEmail(t, "/api/http-records", proj, "user@evil.com")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	resp.Body.Close()

	// Clear domains → project becomes open
	resp = env.put(t, "/api/projects/"+proj, `{"allowed_domains":[]}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Random user → now allowed
	resp = env.getWithEmail(t, "/api/http-records", proj, "user@evil.com")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestProjectAccess_CreateProject_ReturnsAccessFields(t *testing.T) {
	env := newAccessTestEnv(t)

	resp := env.post(t, "/api/projects",
		`{"name":"Fields Test","allowed_domains":["@acme.com"],"allowed_emails":["bob@ext.com"]}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var project database.Project
	readJSON(t, resp, &project)
	assert.Equal(t, []string{"@acme.com"}, project.AllowedDomains)
	assert.Equal(t, []string{"bob@ext.com"}, project.AllowedEmails)
}

func TestProjectAccess_GetProject_ReturnsAccessFields(t *testing.T) {
	env := newAccessTestEnv(t)

	proj := env.createProjectWithAccess(t, "Get Fields",
		[]string{"@acme.com"}, []string{"alice@ext.com"})

	resp := env.get(t, "/api/projects/"+proj)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ProjectWithStats
	readJSON(t, resp, &body)
	assert.Equal(t, []string{"@acme.com"}, body.Project.AllowedDomains)
	assert.Equal(t, []string{"alice@ext.com"}, body.Project.AllowedEmails)
}

func TestProjectAccess_InvalidEmail_Rejected(t *testing.T) {
	env := newAccessTestEnv(t)

	proj := env.createProjectWithAccess(t, "Invalid Email",
		[]string{"@acme.com"}, nil)

	// Email with no @ sign → invalid format → 403
	resp := env.getWithEmail(t, "/api/http-records", proj, "not-an-email")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	resp.Body.Close()
}
