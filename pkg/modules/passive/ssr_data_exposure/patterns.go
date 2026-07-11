package ssr_data_exposure

// ssrStateBlob defines where to find SSR state data in the HTML.
type ssrStateBlob struct {
	name    string
	start   string // start delimiter in HTML
	end     string // end delimiter
	jsonKey bool   // if true, extract JSON between { and }
}

// stateBlobs defines the SSR state injection points to scan.
var stateBlobs = []ssrStateBlob{
	{
		name:  "__NEXT_DATA__",
		start: `<script id="__NEXT_DATA__" type="application/json">`,
		end:   `</script>`,
	},
	{
		name:    "__NUXT__",
		start:   `window.__NUXT__=`,
		end:     `;</script>`,
		jsonKey: true,
	},
	{
		name:    "__INITIAL_STATE__",
		start:   `window.__INITIAL_STATE__=`,
		end:     `;</script>`,
		jsonKey: true,
	},
	{
		name:    "__APOLLO_STATE__",
		start:   `window.__APOLLO_STATE__=`,
		end:     `;</script>`,
		jsonKey: true,
	},
}
