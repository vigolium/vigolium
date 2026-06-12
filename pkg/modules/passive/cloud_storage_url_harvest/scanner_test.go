package cloud_storage_url_harvest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

type fakeFeeder struct{ fed []string }

func (f *fakeFeeder) Feed(rr *httpmsg.HttpRequestResponse) bool {
	if u, err := rr.URL(); err == nil {
		f.fed = append(f.fed, u.String())
	}
	return true
}

func TestHarvestsAndFeeds(t *testing.T) {
	t.Parallel()
	body := `<html><body>
	<img src="https://lf-creative-factory.cdn.acme.com/obj/eden-sg/fyvajhm_lcpahlyj">
	<a href="https://storage.googleapis.com/my-bucket/path/file.json">x</a>
	</body></html>`
	rr := modtest.Response(modtest.Request(t, "https://app.example.com/page"), "text/html", body)

	feeder := &fakeFeeder{}
	res, err := New().ScanPerRequest(rr, &modkit.ScanContext{RequestFeeder: feeder})
	require.NoError(t, err)
	require.NotEmpty(t, res)
	assert.GreaterOrEqual(t, len(res[0].ExtractedResults), 2, "should harvest both storage URLs")
	assert.GreaterOrEqual(t, len(feeder.fed), 2, "should feed both candidates back into the pipeline")
}

func TestSkipsStaticAssetBodies(t *testing.T) {
	t.Parallel()
	// A binary/image response body must not be mined even if it contains a URL.
	body := `https://storage.googleapis.com/my-bucket/path/file.json`
	rr := modtest.Response(modtest.Request(t, "https://cdn.example.com/obj/b/o.png"), "image/png", body)

	feeder := &fakeFeeder{}
	res, err := New().ScanPerRequest(rr, &modkit.ScanContext{RequestFeeder: feeder})
	require.NoError(t, err)
	assert.Empty(t, res, "static asset bodies must be skipped")
	assert.Empty(t, feeder.fed)
}

func TestNoStorageURLsNoFinding(t *testing.T) {
	t.Parallel()
	rr := modtest.Response(modtest.Request(t, "https://app.example.com/page"), "text/html", "<html>nothing here</html>")
	res, err := New().ScanPerRequest(rr, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
}
