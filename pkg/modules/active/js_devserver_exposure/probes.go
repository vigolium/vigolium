package js_devserver_exposure

// devProbe defines a development server endpoint to check.
type devProbe struct {
	path           string
	name           string
	expectedCT     string   // expected Content-Type (partial match)
	expectedStatus int      // expected status code (0 = any 2xx)
	markers        []string // body markers (at least one must match)
	desc           string
}

// devProbes is the list of development server endpoints to test.
var devProbes = []devProbe{
	{
		path:       "/_next/webpack-hmr",
		name:       "Next.js Webpack HMR",
		expectedCT: "text/event-stream",
		desc:       "Next.js webpack hot module replacement endpoint exposed, indicating a development server is running in production",
	},
	{
		path:           "__vite_ping",
		name:           "Vite Dev Server",
		expectedStatus: 204,
		desc:           "Vite development server ping endpoint exposed, indicating a dev server is accessible in production",
	},
	{
		path:    "/__webpack_dev_server__/sockjs-node/info",
		name:    "Webpack Dev Server SockJS",
		markers: []string{`"websocket"`, `"entropy"`},
		desc:    "Webpack dev server SockJS endpoint exposed, enabling HMR connections and potential code injection",
	},
	{
		path:    "/sockjs-node/info",
		name:    "SockJS Node Info",
		markers: []string{`"websocket"`, `"origins"`},
		desc:    "SockJS node info endpoint exposed, indicating webpack dev server is accessible",
	},
	{
		path:    "/__open-in-editor",
		name:    "Vue CLI Open-in-Editor",
		markers: []string{},
		desc:    "Vue CLI open-in-editor debug endpoint exposed, potentially allowing arbitrary file reads",
	},
	{
		path:       "/_nuxt/hmr/",
		name:       "Nuxt.js HMR",
		expectedCT: "text/event-stream",
		desc:       "Nuxt.js hot module replacement endpoint exposed, indicating a development server in production",
	},
	{
		path:    "/__remix_dev/",
		name:    "Remix Dev Server",
		markers: []string{},
		desc:    "Remix development server endpoint exposed, indicating dev mode is accessible in production",
	},
	{
		path: "/__esbuild__/",
		name: "esbuild Dev Server",
		desc: "esbuild development server endpoint exposed",
	},
	{
		path: "/__parcel_hmr/",
		name: "Parcel HMR",
		desc: "Parcel hot module replacement endpoint exposed",
	},
	{
		path:       "/_next/turbopack-hmr",
		name:       "Turbopack HMR",
		expectedCT: "text/event-stream",
		desc:       "Turbopack (Next.js) HMR endpoint exposed",
	},
}
