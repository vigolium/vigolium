# Architecture Entry Points Inventory — Shopify CLI

Generated: 2026-05-01  
Target: `/Users/bytedance/Desktop/oss-to-run/shopify-cli`  
Purpose: reusable Stage 03 inventory for later SAST/manual phases.

## 1. Executable / package entry points

| Entrypoint | Type | Public surface | Key files | Attacker-controlled inputs | High-value sinks |
|---|---|---|---|---|---|
| `shopify` binary (`@shopify/cli`) | CLI | Published npm bin; oclif command router; lazy command loading. | `packages/cli/package.json`, `packages/cli/bin/run.js`, `packages/cli/src/bootstrap.ts`, `packages/cli/src/index.ts`, `packages/cli/src/command-registry.ts` | argv/flags, `SHOPIFY_FLAG_*`, global env/proxy vars, cwd, oclif plugin metadata. | All command sinks: auth/session, HTTP, filesystem, process exec, local servers. |
| `create-app` binary (`@shopify/create-app`) | CLI | Published npm bin that runs `app:init`. | `packages/create-app/package.json`, `packages/create-app/src/index.ts` | template/name/directory/package-manager flags, env, GitHub template URL. | Git clone/download, Liquid rendering, package-manager install, filesystem writes. |
| `@shopify/cli-kit` exports | Library | Published utility package consumed by CLI/packages and potentially downstream code. | `packages/cli-kit/package.json`, `packages/cli-kit/src/public/node/**`, `packages/cli-kit/src/private/node/**` | API callers pass paths, commands, URLs, tokens, parsed config. | `exec`/`execCommand`/`treeKill`, `fetch`/`shopifyFetch`, `LocalStorage`, Liquid/fs helpers. |
| `@shopify/plugin-cloudflare` hook | Plugin | oclif tunnel provider/start hooks; executes `cloudflared`. | `packages/plugin-cloudflare/src/provider.ts`, `packages/plugin-cloudflare/src/tunnel.ts`, `packages/plugin-cloudflare/src/install-cloudflared.ts` | tunnel port, `SHOPIFY_CLI_CLOUDFLARED_PATH`, `SHOPIFY_CLI_CLOUDFLARED_DOMAIN`, downloaded release bytes. | Public tunnel URL, binary download/execution, local server exposure. |
| GitHub workflows | CI/CD | Repo automation and release/test workflows. | `.github/workflows/*.yml`, root `package.json` scripts, `bin/**` | GitHub event metadata, PR contents, workflow inputs, repository secrets. | NPM/release publishing, GitHub token, Shopify automation tokens, build artifacts. |

## 2. CLI command inventory

### `@shopify/app` commands

Source: `packages/app/src/cli/index.ts`, `packages/app/src/cli/commands/**`.

| Command group | Commands / entry files | Main attacker-controlled sources | Principal sinks / security notes |
|---|---|---|---|
| App lifecycle | `app:init`, `app:dev`, `app:build`, `app:deploy`, `app:release`, `app:info`, `app:versions:list` | `--path`, `--config`, `--client-id`, app TOML, environment, project files, selected org/store/app, prompts. | Auth/token exchange, dev servers/tunnels, build subprocesses, deploy/release GraphQL mutations. |
| App config/env | `app:config:link`, `app:config:use`, `app:config:pull`, `app:config:validate`, `app:env:pull`, `app:env:show` | TOML files, remote app config, API secrets, output `.env`, selected config names. | Writes config/env files; prints API secret values; remote app mutation/pull. |
| App execute/bulk | `app:execute`, `app:bulk:execute`, `app:bulk:cancel`, `app:bulk:status` | GraphQL query string/file, variables JSON/file, API version, store selection. | Admin/App GraphQL requests with app/store token; output files; mutation restrictions rely on store type. |
| Extension generation/import | `app:generate:extension`, `app:generate:schema`, `app:import-extensions`, `app:import-custom-data-definitions` | template selection/specs, local extension TOML/files, remote template specs. | Filesystem generation, TOML/JSON schema parsing, package dependencies. |
| Function tooling | `app:function:build`, `app:function:run`, `app:function:replay`, `app:function:schema`, `app:function:typegen`, `app:function:info` | function TOML (`build.path`, `typegen_command`, targets/exports), input/query/schema files, stdin, env. | Downloads/runs function-runner/Javy/wasm-opt/trampoline; `exec`; WebAssembly parse/compile; file reads/writes. |
| Webhooks/logs | `app:webhook:trigger`, deprecated `webhook:trigger`, `app:logs`, `app:logs:sources` | topic/API version/address/delivery method/client secret, logs options, remote events. | HTTP POST to local address, Partner API sample request, secret/HMAC headers, log rendering. |
| Dev cleanup/watch | `app:dev:clean`, `demo:watcher`, dev event watchers | app/store config, filesystem events. | Dev session deletion, file watching, GraphQL mutations. |

### `@shopify/theme` commands

Source: `packages/theme/src/index.ts`, `packages/theme/src/cli/commands/theme/**`.

| Command group | Commands / entry files | Main attacker-controlled sources | Principal sinks / security notes |
|---|---|---|---|
| Theme dev/serve | `theme:dev`, `theme:serve` | `--host`, `--port`, `--store`, theme directory, `--only/--ignore`, `--notify`, store password, remote theme/editor state. | Local H3 server on `127.0.0.1:9292` by default; CORS; SSE; local files; token-bearing storefront proxy. |
| Theme file operations | `theme:push`, `theme:pull`, `theme:package`, `theme:check`, `theme:metafields:pull` | local theme files, ignore patterns, JSON/YAML/Liquid, output path. | Upload/download/delete remote theme files, ZIP/archive creation, local writes. |
| Theme mutations | `theme:delete`, `theme:duplicate`, `theme:publish`, `theme:rename`, `theme:share`, `theme:open`, `theme:list`, `theme:preview`, `theme:info` | theme IDs/names, store selection, confirmation flags. | Admin API/theme mutations; preview/share URLs; local storage of dev theme. |
| Theme utilities | `theme:console`, `theme:language-server`, `theme:init`, `theme:profile` | shell/editor/browser inputs, paths. | Browser/open operations, local files, language server. |

### `@shopify/store` commands

Source: `packages/store/src/index.ts`, `packages/store/src/cli/commands/store/**`.

| Command | Entry files | Main attacker-controlled sources | Principal sinks / security notes |
|---|---|---|---|
| `store:auth` | `packages/store/src/cli/commands/store/auth.ts`, `services/store/auth/**` | `--store`, `--scopes`, browser OAuth callback query (`shop`, `state`, `code`, `error`), fixed callback port. | PKCE auth URL, loopback callback `127.0.0.1:13387`, token exchange/storage. |
| `store:execute` | `packages/store/src/cli/commands/store/execute.ts`, `services/store/execute/**` | query string/file, variables JSON/file, API version, output file, `--allow-mutations`. | Admin GraphQL request with stored app access token; output file/stdout; mutation gate disabled by default. |

### Root / platform commands

Source: `packages/cli/src/index.ts`, `packages/cli/src/cli/commands/**`, external packages.

| Command group | Commands | Main sources | Sinks / notes |
|---|---|---|---|
| Auth/session | `auth:login`, `auth:logout` | device auth responses, env tokens, local conf store. | OAuth device flow, session store removal/write, browser open. |
| CLI maintenance | `upgrade`, `version`, `search`, `help`, `commands`, `plugins:*`, `cache:clear`, `config:autoupgrade:*` | argv/env, package manager context, installed plugin state. | Package-manager/system commands, cache/local storage, plugin loading. |
| Docs/notifications/debug | `docs:generate`, `notifications:list`, `notifications:generate`, `debug:command-flags`, `doctor-release:*`, `kitchen-sink:*` | local repo files, env, API responses. | File generation/output, UI rendering, network calls. |
| External Hydrogen commands | `hydrogen:*` imported from `@shopify/cli-hydrogen` | external package surfaces not fully in repo. | Out-of-scope third-party command logic but shares cli-kit env/auth/process context. |

## 3. Local HTTP / WebSocket / SSE routes

| Surface | Default bind/URL | Routes or route patterns | Key files | Attacker-controlled request data | Sensitive data/sinks |
|---|---|---|---|---|---|
| App GraphiQL dev server | `http://localhost:3457` (or `SHOPIFY_FLAG_GRAPHIQL_PORT`) | `GET /graphiql`, `POST /graphiql/graphql.json`, `GET /graphiql/status`, `/graphiql/ping`, `/graphiql/simple.css`, `/graphiql/favicon.ico`; URL printed with `?key=` | `packages/app/src/cli/services/dev/graphiql/server.ts`, `templates/graphiql.tsx`, `utilities.ts` | query params `key`, `query`, `variables`, `api_version`; POST body; request headers; Host/X-Forwarded-Proto. | Admin OAuth access token fetched from store; Admin GraphQL proxy; app/store URLs; wildcard CORS; inline HTML/JS. |
| UI extension HTTP dev server | `http://localhost:<themeExtensionPort/app dev chosen>` | `/extensions`, `/extensions/`, `/extensions/dev-console`, `/extensions/dev-console/assets/**:assetPath`, `/extensions/:extensionId`, `/extensions/:extensionId/:extensionPointTarget`, `/extensions/:extensionId/assets/**:assetPath`, `/extensions/assets/:assetKey/**:filePath`, `/` redirect | `packages/app/src/cli/services/dev/extension/server.ts`, `server/middlewares.ts`, `payload/**`, `templates.ts` | route params `extensionId`, `assetPath`, `filePath`, `assetKey`, Accept header, Origin. | Extension payloads, app API key, store FQDN, local build/assets file reads, dev console UI, CORS `*`. |
| UI extension WebSocket | Same HTTP server | WS upgrade only when `request.url === '/extensions'` | `packages/app/src/cli/services/dev/extension/websocket.ts`, `websocket/handlers.ts` | WS Origin, messages with `{event,data}`, JSON body, logs from extension runtime. | Payload store updates, dispatch broadcast, terminal logs, connected payload, extension metadata. |
| Theme dev server | `http://127.0.0.1:9292` by default; `--host`/`--port` can change | Catch-all H3 stack: hot reload/SSE, local assets, proxy, HTML renderer; common paths `/assets/*`, `/cdn/*`, `/ext/cdn/*`, `/cart/*`, `/checkouts/*`, `/account*`, `/?hr-log=...`, `/@shopify/theme-hot-reload` | `packages/theme/src/cli/services/dev.ts`, `utilities/theme-environment/theme-environment.ts`, `local-assets.ts`, `proxy.ts`, `html.ts`, `hot-reload/server.ts` | path/query/headers, Origin, Accept, cookies, `hr-log` JSON, theme files, ignore/only patterns. | Local theme/extension files, storefront-renderer/Admin tokens/cookies, SSE events, proxied response headers/cookies, HTML/JS injection. |
| Theme extension dev server | `http://127.0.0.1:<themeExtensionPort|9293>` | Same theme-environment handlers as theme dev for extension files | `packages/theme/src/cli/utilities/theme-ext-environment/theme-ext-server.ts` | HTTP path/query/headers, local theme extension files. | Theme extension assets/templates, storefront renderer proxy, SSE. |
| Store OAuth callback | `http://127.0.0.1:13387/auth/callback` | `GET /auth/callback?shop=&state=&code=&error=`; non-matching path returns 404 | `packages/store/src/cli/services/store/auth/callback.ts`, `pkce.ts`, `token-client.ts` | callback query params from browser/Identity/local attacker, fixed port availability. | PKCE auth code, token exchange, stored store app session; HTML success/error page. |
| App reverse proxy | Dynamic app dev local port(s), often behind tunnel/localhost | Prefix-based rules plus `default`/`websocket`; proxies HTTP and WS | `packages/app/src/cli/utilities/app/http-reverse-proxy.ts`, app dev process setup | request path/headers/body, WS upgrade, proxy rules from app/web config. | Forwards to local app web processes; header/cookie forwarding; invalid path errors. |
| App dev uninstall webhook sender | Local POST to app server | `http://localhost:<deliveryPort><webhooksPath>` where path defaults `/api/webhooks` or app `webhooks_path` | `packages/app/src/cli/services/dev/processes/uninstall-webhook.ts`, `webhook/send-app-uninstalled-webhook.ts` | `webhooks_path` from app web TOML, local port choice. | Sends signed webhook payload with app shared secret/HMAC context to local server. |

## 4. External/public URLs and APIs touched by CLI

| External endpoint / URL pattern | Direction | Source files | Sensitive material | Security notes |
|---|---|---|---|---|
| `https://${identityFqdn}/oauth/device_authorization` | CLI → Shopify Identity | `cli-kit/src/private/node/session/device-authorization.ts` | client ID, requested scopes, device/user codes | Device polling, phishing/UX, debug output. |
| `https://${identityFqdn}/oauth/token` | CLI → Shopify Identity | `cli-kit/src/private/node/session/exchange.ts` | subject/access/refresh/device tokens in POST body | Body avoids URL leakage; token source for app tokens. |
| `https://${store}/admin/oauth/authorize` | Browser → Shopify store | `store/auth/pkce.ts` | scopes, state, code challenge, redirect URI | PKCE S256 and state required. |
| `https://${store}/admin/oauth/access_token` | GraphiQL server → store | `app/src/cli/services/dev/graphiql/server.ts` | app `client_id`/`client_secret`; access token response | Token cached in local GraphiQL server. |
| `https://${store}/admin/api/${version}/graphql.json` | CLI/local server → Admin API | `cli-kit/src/public/node/api/admin.ts`, GraphiQL server, store execute | Admin/store tokens, GraphQL query/variables. | API version validation differs by flow; token-bearing. |
| Partners/App Management/Business Platform GraphQL endpoints | CLI → Shopify platform | `app/src/cli/utilities/developer-platform-client/**`, `cli-kit/src/private/node/api.ts` | Partners/App Management/BP tokens, app/org IDs. | Deploy/release/config mutation authority. |
| Storefront renderer/CDN (`https://${storeFqdn}`, `https://cdn.shopify.com`) | theme dev → Shopify/CDN | `theme-environment/proxy.ts`, `storefront-renderer.ts` | Storefront token, cookies, theme ID, request headers. | Manual redirects, host checks, header filtering. |
| GitHub template repositories | CLI → GitHub | `app/src/cli/services/init/init.ts`, `cli-kit/src/public/node/git.ts`, `github.ts` | user-selected template URL/ref/subdirectory | Custom templates become local code and package scripts. |
| Cloudflare quick tunnel domain (`*.trycloudflare.com` by default) | local server ↔ internet | `plugin-cloudflare/src/tunnel.ts` | public tunnel URL to local dev server. | Remote attackers can reach local routes once tunnel URL is known. |
| Cloudflared release downloads | CLI → GitHub releases | `plugin-cloudflare/src/install-cloudflared.ts` | executable bytes | No checksum/signature observed; env path override. |
| Function toolchain downloads | CLI → GitHub/CDN/jsDelivr | `app/src/cli/services/function/binaries.ts`, `mkcert.ts` | executable/WASM bytes | Download → chmod/move → exec; integrity gap. |
| Webhook trigger address | Shopify/platform or CLI → user-specified endpoint | `app/src/cli/services/webhook/trigger*.ts` | sample payload, HMAC headers/client secret-derived signature | Localhost delivery does direct fetch; remote delivery handled by Shopify service. |

## 5. Attacker-controlled source inventory

| Source type | Concrete examples | Primary trust boundary crossed | Representative source files |
|---|---|---|---|
| CLI flags/argv/prompts/stdin | `--path`, `--store`, `--host`, `--port`, `--query`, `--query-file`, `--variables`, `--output-file`, `--template`, `--tunnel-url`, `--notify`, `--address`, `--input`, `--schema-path`, `--query-path`, package manager choice. | User shell/CI → CLI process. | command classes under `packages/*/src/cli/commands/**`; `flags.ts`; `base-command.ts`. |
| Environment variables | `SHOPIFY_APP_AUTOMATION_TOKEN`, `SHOPIFY_CLI_PARTNERS_TOKEN`, `SHOPIFY_CLI_IDENTITY_TOKEN`, `SHOPIFY_CLI_REFRESH_TOKEN`, `SHOPIFY_CLI_THEME_TOKEN`, `SHOPIFY_FLAG_*`, `SHOPIFY_CLI_CLOUDFLARED_PATH`, `SHOPIFY_CLI_MKCERT_BINARY`, `SHOPIFY_CLI_OTEL_EXPORTER_OTLP_ENDPOINT`, proxy variables under `SHOPIFY_`, `XDG_*`. | Shell/CI/local malware → auth/network/process/filesystem. | `cli-kit/src/private/node/constants.ts`, `environment.ts`, `plugin-cloudflare`, `app/constants.ts`, `bootstrap.ts`. |
| Local project/config files | `shopify.app.toml`, `shopify.web.toml`, extension TOML, `package.json`, `.env`, `pnpm-workspace.yaml`, `.cli-liquid-bypass`, theme Liquid/JSON/assets, symlinks, ignore files. | Untrusted repo/template → CLI execution/filesystem/network. | app loaders/spec schemas, `include-assets`, `theme-fs`, `recursiveLiquidTemplateCopy`. |
| Browser/local HTTP requests | GraphiQL, extension server, theme dev, store callback, app reverse proxy. | Browser/tunnel → local developer machine. | `graphiql/server.ts`, `extension/server/**`, `theme-environment/**`, `store/auth/callback.ts`, `http-reverse-proxy.ts`. |
| WebSocket/SSE messages | `/extensions` WS JSON events/logs; theme hot reload SSE and `hr-log` query. | Browser/tunnel → local server state/logs. | `extension/websocket/handlers.ts`, `theme-environment/hot-reload/server.ts`. |
| Remote API responses | Shopify Identity/Admin/Partners/BP, storefront renderer, template specs, GitHub releases, CDN. | Shopify/GitHub/CDN/network → CLI/browser/local files. | `cli-kit/api/**`, developer platform clients, `http.ts`, downloads. |
| Downloaded executable/template artifacts | app templates, `cloudflared`, `mkcert`, `function-runner`, `javy`, `wasm-opt`, trampoline, plugin WASM. | Internet/CDN/GitHub → local executable/code trust. | `init/init.ts`, `plugin-cloudflare`, `function/binaries.ts`, `mkcert.ts`. |
| CI/GitHub events | PR title/body/branch, issue text, workflow_dispatch inputs, release tags. | GitHub event → workflow shell/release tokens. | `.github/workflows/**`, `bin/**`, `package.json` scripts. |

## 6. High-value sink inventory

| Sink kind | Concrete sinks | Representative files | Notes for SAST |
|---|---|---|---|
| Command execution | `exec`, `execCommand`, `captureCommandWithExitCode`, `execa`, `execaCommand`, `child_process.exec`, `execSync`, `execFileSync`, `spawn`, `treeKill`, package-manager installs/builds, downloaded tools. | `cli-kit/src/public/node/system.ts`, `tree-kill.ts`, `node-package-manager.ts`, `app/services/web.ts`, `app/services/function/**`, `plugin-cloudflare/**`, `mkcert.ts`. | Highest local-compromise sink; model `LocalUserInput` and `EnvironmentVariable`. |
| File read/write/copy/archive | `readFile`, `writeFile`, `copyFile`, `copyDirectoryContents`, `moveFile`, `glob`, `zip`, `archiver`, theme package/push/pull, local asset serving. | `include-assets/**`, `cli-kit/liquid.ts`, `theme-environment/local-assets.ts`, `theme/services/package.ts`, `cli-kit/archiver.ts`. | Require path normalization + realpath containment + symlink policy. |
| Token-bearing HTTP/API | `shopifyFetch`, `graphqlRequest`, `adminRequestDoc`, GraphiQL `fetch(graphqlUrl)`, theme proxy `fetch(url)`, webhook fetch. | `cli-kit/http.ts`, `api/graphql.ts`, `api/admin.ts`, `graphiql/server.ts`, `theme-environment/proxy.ts`, `webhook/trigger-local-webhook.ts`. | Model URL/headers/body and auth-header forwarding. |
| Credential storage | `LocalStorage<ConfSchema>`, store app session storage, cache. | `cli-kit/src/private/node/conf-store.ts`, `cli-kit/src/public/node/local-storage.ts`, `store/auth/session-store.ts`, `session/store.ts`. | Plaintext tokens; validate permissions and corruption handling. |
| Browser-rendered HTML/JS | GraphiQL template, unauthorized callback pages, dev-console assets, theme hot-reload injection/error pages. | `graphiql/templates/*.tsx`, `store/auth/callback.ts`, `extension/templates.ts`, `theme-environment/hot-reload/server.ts`, `hot-reload/error-page.ts`. | XSS/script-context escaping and external CDN scripts. |
| Deployment/state mutation | app deploy/release/config, theme push/delete/publish, Admin GraphQL execute, webhooks. | `app/services/deploy/**`, `release.ts`, `theme/services/**`, `execute-operation.ts`, `store/execute/**`. | Confused-deputy and destructive operation controls. |
| Telemetry/logging | `outputDebug`, `outputResult`, `recordEvent`, `addPublicMetadata`, Bugsnag/OTLP. | `cli-kit/src/private/node/analytics.ts`, `metadata.ts`, `output.ts`, command services. | Token/secret taint to output or remote telemetry. |

## 7. Key source file map for later phases

| Review theme | Key files/directories |
|---|---|
| CLI bootstrap/command routing | `packages/cli/src/bootstrap.ts`, `packages/cli/src/index.ts`, `packages/cli/src/command-registry.ts`, `packages/cli-kit/src/public/node/cli.ts`, `packages/cli-kit/src/public/node/base-command.ts`. |
| Auth/session/OAuth/JWT | `packages/cli-kit/src/private/node/session/**`, `packages/cli-kit/src/private/node/conf-store.ts`, `packages/cli-kit/src/public/node/local-storage.ts`, `packages/store/src/cli/services/store/auth/**`. |
| GraphQL/API clients | `packages/cli-kit/src/public/node/api/**`, `packages/app/src/cli/services/execute-operation.ts`, `packages/app/src/cli/services/graphql/common.ts`, `packages/store/src/cli/services/store/execute/**`, `packages/app/src/cli/utilities/developer-platform-client/**`. |
| GraphiQL local server | `packages/app/src/cli/services/dev/graphiql/server.ts`, `packages/app/src/cli/services/dev/graphiql/templates/graphiql.tsx`, `templates/unauthorized.tsx`, `utilities.ts`. |
| UI extension local server/WS | `packages/app/src/cli/services/dev/extension/server.ts`, `server/middlewares.ts`, `websocket.ts`, `websocket/handlers.ts`, `payload/**`, `packages/ui-extensions-dev-console/src/**`, `packages/ui-extensions-server-kit/src/**`. |
| Theme dev/proxy/hot reload | `packages/theme/src/cli/services/dev.ts`, `packages/theme/src/cli/utilities/theme-environment/**`, `theme-ext-environment/**`, `theme-fs.ts`, `theme-uploader.ts`. |
| Build/include-assets/filesystem | `packages/app/src/cli/services/build/**`, especially `steps/include-assets*`; `packages/cli-kit/src/public/node/fs.ts`, `path.ts`, `liquid.ts`, `archiver.ts`. |
| Process/native binaries | `packages/cli-kit/src/public/node/system.ts`, `tree-kill.ts`, `node-package-manager.ts`, `packages/app/src/cli/services/function/**`, `packages/plugin-cloudflare/src/**`, `packages/app/src/cli/utilities/mkcert.ts`. |
| App init/templates/supply chain | `packages/app/src/cli/services/init/**`, `packages/app/src/cli/services/generate/**`, `packages/cli-kit/src/public/node/git.ts`, `github.ts`, `liquid.ts`. |
| App/theme config parsing | `packages/app/src/cli/models/app/loader.ts`, `models/extensions/**`, `packages/theme/src/cli/flags.ts`, `utilities/theme-listing.ts`, TOML/YAML helpers in `cli-kit`. |
| Webhook/proxy/SSRF | `packages/app/src/cli/services/webhook/**`, `packages/app/src/cli/utilities/app/http-reverse-proxy.ts`, `packages/theme/src/cli/utilities/theme-environment/proxy.ts`, `storefront-renderer.ts`. |
| CI/CD | `.github/workflows/**`, `bin/**`, root `package.json` scripts, release/config files. |

## 8. Phase 4 source/sink modeling hints

| Flow family | Expected source type | Expected sink kinds |
|---|---|---|
| Browser/tunnel → GraphiQL/extension/theme HTTP | `RemoteFlowSource` | `http-request`, `file-access`, `code-execution` (HTML/JS), `deserialization`. |
| Browser/tunnel → WS/SSE | `RemoteFlowSource` | `deserialization`, `code-execution`/state mutation, log/terminal sinks. |
| CLI/env/config → process/native binary | `LocalUserInput`, `EnvironmentVariable` | `command-execution`. |
| Project/template/theme files → fs/archive/deploy | `LocalUserInput` | `file-access`, `deserialization`, `http-request` (deploy/upload). |
| OAuth/env/session tokens → logs/API/proxy/storage | `EnvironmentVariable`, `RemoteFlowSource`, local storage sources | `http-request`, `file-access`, telemetry/log/response sinks. |
| Download/template URLs → executed files/templates | `RemoteFlowSource`, `LocalUserInput` | `command-execution`, `file-access`, `deserialization`. |
