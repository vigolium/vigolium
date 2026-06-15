package joomla_misconfig

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsConfigBackup drives the real scan method against a
// host that exposes a Joomla configuration.php backup leaking the JConfig class
// and DB credentials. The module fingerprints a 404, then probes the backup
// paths; the config markers must surface a critical finding.
func TestScanPerRequest_DetectsConfigBackup(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/configuration.php.bak" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<?php class JConfig {\n" +
				"\tpublic $host = 'localhost';\n" +
				"\tpublic $user = 'joomla';\n" +
				"\tpublic $password = 's3cret';\n" +
				"\tpublic $db = 'joomla_db';\n" +
				"\tpublic $secret = 'abc123';\n}"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("x"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a misconfig finding when a config backup leaks JConfig credentials")
	assert.Contains(t, strings.ToLower(res[0].Info.Name), "joomla misconfiguration")
}

// TestScanPerRequest_NoFP_GenericJSONShell reproduces the generic-JSON-catch-all
// FP class: a host that 200s every path with a JSON body carrying generic keys
// ("name","version","data") but no Joomla/Composer-specific anchor. The old
// single-OR matcher fired the composer.json / installed.json / com_ajax probes on
// a bare "name"/"version"/"data" key; the anchor-group requirement must suppress
// all of them.
func TestScanPerRequest_NoFP_GenericJSONShell(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "vigolium") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"my-app","version":"2.1.0","description":"a service","data":[]}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a generic JSON body with only name/version/data must not yield a Joomla finding")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every probe path
// yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host that 404s every probe must not yield a Joomla misconfig finding")
}
