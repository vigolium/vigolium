# Attack Surface Map: SQL Expressions, Plugin System, Image Renderer

## Entry Points

### SQL Expressions (`pkg/expr/sql/`)
- `pkg/expr/nodes.go:126-131` -- `buildCMDNode` -- Feature flag gate for `sqlExpressions`; if enabled, user-supplied SQL expression from `POST /api/ds/query` body reaches execution
- `pkg/expr/sql/db.go:47` -- `AllowQuery(name, query)` -- Parses raw SQL string from user input and checks allowlist
- `pkg/expr/sql/db.go:98` -- `engine.Query(mCtx, query)` -- Executes user-supplied SQL against go-mysql-server in-process engine
- `pkg/expr/sql/parser.go:15` -- `TablesList(ctx, rawSQL)` -- Parses user SQL to extract table names (double-parse)
- `pkg/expr/sql/parser_allow.go:13` -- `AllowQuery(refID, rawSQL)` -- AST allowlist check on user-supplied SQL

### Image Renderer (`pkg/services/rendering/`, `pkg/api/render.go`)
- `pkg/api/render.go:18` -- `RenderHandler` -- HTTP handler for `/render/*`; takes width, height, timeout, scale, theme, encoding, path from query params
- `pkg/api/render.go:90` -- `web.Params(c.Req)["*"] + queryParams` -- Path parameter from URL directly concatenated into rendering path
- `pkg/api/render.go:122` -- `http.ServeFile(c.Resp, c.Req, result.FilePath)` -- Serves file from `result.FilePath` with NO directory confinement check
- `pkg/services/rendering/auth.go:34` -- `GetRenderUser(ctx, key)` -- Authenticates render callback requests using JWT or cache key
- `pkg/services/rendering/auth.go:56-67` -- `getRenderUserFromJWT(key)` -- JWT validation with `RendererAuthToken` (default: `"-"`)
- `pkg/services/rendering/http_mode.go:71` -- `queryParams.Add("url", url)` -- Callback URL sent to remote renderer; includes user-controlled path
- `pkg/services/rendering/http_mode.go:148` -- `req.Header.Set(authTokenHeader, rs.Cfg.RendererAuthToken)` -- Auth token sent to renderer in header

### Plugin System (`pkg/plugins/storage/fs.go`)
- `pkg/plugins/storage/fs.go:39` -- `Extract` -- Plugin zip extraction entry point
- `pkg/plugins/storage/fs.go:88` -- `filepath.Join(fs.pluginsDir, zf.Name)` -- Zip entry name used in path construction
- `pkg/plugins/storage/fs.go:99` -- `filepath.Clean(filepath.Join(..., removeGitBuildFromName(zf.Name, pluginDirName)))` -- Actual destination path (different from ZipSlip check path!)
- `pkg/plugins/storage/fs.go:121-126` -- `extractSymlink` -- Symlink extraction with relative path check
- `pkg/plugins/storage/fs.go:141` -- `extractSymlink(installDir, zf, dstPath)` -- Symlink target validation

## Trust Boundary Crossings

- **TB-10: SQL Expression Engine** -- User-controlled SQL string from HTTP request crosses into in-process go-mysql-server engine. Engine runs with full Grafana process privileges (same PID, same filesystem access).
- **TB-7: Plugin gRPC Boundary** -- Image renderer communicates via HTTP/gRPC. Default auth token is `"-"` (hardcoded in `pkg/setting/setting.go:2070`), making JWT forgery trivial for network attackers.
- **TB-1: HTTP to Render** -- `http.ServeFile` at `render.go:122` serves arbitrary file path returned by renderer service with no directory confinement.
- **Plugin Install** -- Zip files from external plugin repository are extracted to filesystem. ZipSlip check and symlink confinement are the security boundaries.

## Parser / Serialization Functions

- `pkg/expr/sql/parser_allow.go:14` -- `sqlparser.Parse(rawSQL)` -- Parses user SQL via vitess SQL parser
- `pkg/expr/sql/parser.go:17` -- `sqlparser.Parse(rawSQL)` -- Same parser used for table extraction
- `pkg/services/rendering/auth.go:58` -- `jwt.ParseWithClaims(key, claims, ...)` -- JWT parsing for render auth
- `pkg/services/rendering/auth.go:80` -- `gob.NewDecoder(buf).Decode(&ru)` -- Gob deserialization of render user from cache
- `pkg/plugins/storage/fs.go:85-131` -- zip archive iteration -- Parses zip file entries for plugin extraction

## Auth / AuthZ Decision Points

- `pkg/expr/nodes.go:128` -- `toggles.IsEnabledGlobally(FlagSqlExpressions)` -- Feature flag gate; if disabled, SQL expressions are rejected entirely
- `pkg/services/rendering/auth.go:41` -- `looksLikeJWT(key) && rs.features.IsEnabled(ctx, FlagRenderAuthJWT)` -- Decides whether to validate render key as JWT or cache lookup
- `pkg/services/rendering/auth.go:58-65` -- JWT validation with `RendererAuthToken` -- Default secret is `"-"`; `WithValidMethods([]string{HS512})` is set
- `pkg/setting/setting.go:2070` -- `cfg.RendererAuthToken = valueAsString(renderSec, "renderer_token", "-")` -- Default auth token is dash character

## Validation / Sanitization Functions

- `pkg/expr/sql/parser_allow.go:49-176` -- `allowedNode` -- AST node type allowlist; **FLAW: includes `*sqlparser.Into` at line 113**
- `pkg/expr/sql/parser_allow.go:179-309` -- `allowedFunction` -- SQL function name allowlist (case-insensitive)
- `pkg/expr/sql/db.go:82-84` -- `sqle.Config{IsReadOnly: true}` -- Engine config set to read-only; **FLAW: `INTO` node's `IsReadOnly()` delegates to child SELECT, returning true**
- `pkg/expr/sql/db.go:76-77` -- commented-out `secure_file_priv` -- **FLAW: not active**
- `pkg/plugins/storage/fs.go:91-97` -- ZipSlip check -- Validates zip entry paths don't escape plugin directory
- `pkg/plugins/storage/fs.go:99` -- `removeGitBuildFromName` + `filepath.Clean` -- Path used for actual extraction (different variable than ZipSlip check!)
- `pkg/plugins/storage/fs.go:165-180` -- `isSymlinkRelativeTo` -- Validates symlink targets stay within plugin directory

## KB Domain Research Highlights

### go-mysql-server File Write Chain
1. `*sqlparser.Into` is on the allowlist (`parser_allow.go:113`), permitting `SELECT ... INTO OUTFILE '/path/file'`
2. `sqle.Config{IsReadOnly: true}` does NOT block INTO because `plan.Into.IsReadOnly()` delegates to the child SELECT node which returns `true`
3. `mysql.WithDisableFileWrites(true)` is the correct mitigation but is NOT called when creating the context (`db.go:71`)
4. `secure_file_priv` session variable is commented out (`db.go:76-77`)
5. The SQL engine runs in-process as the Grafana server user -- any file write goes to the Grafana process's filesystem with its permissions

### JWT Renderer Auth Weakness
1. Default `renderer_token` is `"-"` (`setting.go:2070`)
2. JWT is signed with HS512 using this token as the key
3. Network attacker who can reach the renderer callback URL can forge JWTs
4. JWT claims include `OrgID`, `UserID`, `OrgRole` -- forgery allows impersonating any user's render permissions
5. No `nbf` claim enforcement (M19 from KB)

### Plugin Zip Extraction TOCTOU
1. ZipSlip check at line 91 uses `filepath.Join(fs.pluginsDir, zf.Name)`
2. Actual extraction at line 99 uses `filepath.Clean(filepath.Join(fs.pluginsDir, removeGitBuildFromName(zf.Name, pluginDirName)))`
3. `removeGitBuildFromName` applies a regex replacement that could potentially transform the path differently than what was validated
4. Symlink extraction validates targets but only relative path check -- TOCTOU between check and creation possible

### ServeFile Without Directory Confinement
1. `http.ServeFile(c.Resp, c.Req, result.FilePath)` at `render.go:122`
2. `result.FilePath` comes from renderer service response (stored in temp dir or error image paths)
3. No validation that `FilePath` is within expected directories (ImagesDir, PDFsDir)
4. If renderer response can be manipulated (e.g., via SSRF or compromised renderer), arbitrary file read is possible
