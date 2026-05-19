# Source-to-sink flows (all severities)

Generated during P4 static analysis with CodeQL structural extraction, CodeQL run-all, Semgrep Pro, custom CodeQL slice queries, and custom Semgrep rules.

## Attacker-controlled / trust-boundary sources
- `environment`: 243
- `view-component-input`: 83
- `file`: 58
- `commandargs`: 46
- `response`: 23
- `remote`: 16
- `stdin`: 3

### Representative entry points
- `file` `FileSystemReadAccess` `bin/bundling/esbuild-plugin-graphiql-imports.js:12` — await r ... 'utf8')
- `file` `FileSystemReadAccess` `bin/bundling/esbuild-plugin-stacktracey.js:8` — await r ... 'utf8')
- `file` `FileSystemReadAccess` `bin/bundling/esbuild-plugin-vscode.js:19` — readFil ... 'utf8')
- `file` `FileSystemReadAccess` `bin/cache-inputs.js:27` — await r ... yaml"))
- `file` `FileSystemReadAccess` `bin/create-cli-duplicate-package.js:5` — await r ... .json')
- `file` `FileSystemReadAccess` `bin/create-cli-duplicate-package.js:9` — await r ... .json')
- `file` `FileSystemReadAccess` `bin/create-doc-pr.js:22` — await r ... eName))
- `file` `FileSystemReadAccess` `bin/create-doc-pr.js:55` — await r ... onPath)
- `commandargs` `CommandLineArguments` `bin/create-homebrew-pr.js:23` — program ... .action
- `commandargs` `CommandLineArguments` `bin/create-homebrew-pr.js:23` — program ... dOption
- `commandargs` `CommandLineArguments` `bin/create-homebrew-pr.js:23` — program ... ription
- `file` `FileSystemReadAccess` `bin/create-homebrew-pr.js:47` — await r ... i.rb"))
- `file` `FileSystemReadAccess` `bin/create-homebrew-pr.js:54` — await r ... e.rb"))
- `file` `FileSystemReadAccess` `bin/create-homebrew-pr.js:57` — await r ... y.rb"))
- `commandargs` `CommandLineArguments` `bin/create-homebrew-pr.js:103` — program.parse
- `file` `FileSystemReadAccess` `bin/create-homebrew-pr.js:107` — await r ... onPath)
- `file` `FileSystemReadAccess` `bin/create-homebrew-pr.js:120` — await r ... tePath)
- `response` `HTTP response data` `bin/create-homebrew-pr.js:138` — fetch(` ... {pkg}`)
- `response` `HTTP response data` `bin/create-homebrew-pr.js:152` — fetch(url)
- `file` `FileSystemReadAccess` `bin/create-homebrew-pr.js:186` — await r ... emPath)
- `file` `FileSystemReadAccess` `bin/create-notification-pr.js:101` — await r ... onPath)
- `commandargs` `CommandLineArguments` `bin/create-test-app.js:25` — program ... .action
- `commandargs` `CommandLineArguments` `bin/create-test-app.js:25` — program ... .option
- `commandargs` `CommandLineArguments` `bin/create-test-app.js:25` — program ... .option
- `commandargs` `CommandLineArguments` `bin/create-test-app.js:25` — program ... .option
- `commandargs` `CommandLineArguments` `bin/create-test-app.js:25` — program ... .option
- `commandargs` `CommandLineArguments` `bin/create-test-app.js:25` — program ... .option
- `commandargs` `CommandLineArguments` `bin/create-test-app.js:25` — program ... .option
- `commandargs` `CommandLineArguments` `bin/create-test-app.js:25` — program ... .option
- `commandargs` `CommandLineArguments` `bin/create-test-app.js:25` — program ... .option
- `commandargs` `CommandLineArguments` `bin/create-test-app.js:25` — program ... .option
- `commandargs` `CommandLineArguments` `bin/create-test-app.js:25` — program ... .option
- `commandargs` `CommandLineArguments` `bin/create-test-app.js:25` — program ... .option
- `commandargs` `CommandLineArguments` `bin/create-test-app.js:25` — program ... ription
- `commandargs` `CommandLineArguments` `bin/create-test-app.js:326` — program.parse
- `commandargs` `CommandLineArguments` `bin/create-test-theme.js:22` — program ... .action
- `commandargs` `CommandLineArguments` `bin/create-test-theme.js:22` — program ... .option
- `commandargs` `CommandLineArguments` `bin/create-test-theme.js:22` — program ... .option
- `commandargs` `CommandLineArguments` `bin/create-test-theme.js:22` — program ... dOption
- `commandargs` `CommandLineArguments` `bin/create-test-theme.js:22` — program ... .option
- `commandargs` `CommandLineArguments` `bin/create-test-theme.js:22` — program ... ription
- `environment` `process.env` `bin/create-test-theme.js:56` — process.env
- `environment` `process.env` `bin/create-test-theme.js:57` — process.env
- `commandargs` `CommandLineArguments` `bin/create-test-theme.js:179` — program.parse
- `response` `HTTP response data` `bin/get-graphql-schemas.js:123` — fetch(download_url)
- `environment` `process.env` `bin/get-graphql-schemas.js:216` — process.env
- `environment` `process.env` `bin/github-utils.js:35` — process.env
- `environment` `process.env` `bin/github-utils.js:36` — process.env
- `commandargs` `process.argv` `bin/pin-github-actions.js:14` — process.argv
- `file` `FileSystemReadAccess` `bin/prettify-manifests.js:15` — fs.read ... c(file)
- `file` `FileSystemReadAccess` `bin/update-bugsnag.js:14` — fs.read ... .json`)
- `commandargs` `process.argv` `bin/update-bugsnag.js:17` — process.argv
- `file` `FileSystemReadAccess` `bin/update-cli-kit-version.js:12` — readFil ... utf-8')
- `file` `FileSystemReadAccess` `bin/update-observe.js:87` — readFil ... utf-8')
- `response` `HTTP response data` `bin/update-observe.js:354` — fetch(c ... ),\n  })
- `environment` `process.env` `bin/update-observe.js:377` — process.env
- `environment` `process.env` `bin/update-observe.js:378` — process.env
- `file` `FileSystemReadAccess` `bin/update-observe.js:385` — readFil ... utf-8')
- `stdin` `Source node (stdin) [from data-extension]` `bin/update-observe.js:434` — ch
- `environment` `process.env` `bin/update-observe.js:479` — process.env
- `environment` `process.env` `bin/update-observe.js:480` — process.env
- `environment` `process.env` `bin/update-observe.js:490` — process.env
- `environment` `process.env` `configurations/vite.config.ts:18` — process.env
- `environment` `process.env` `configurations/vite.config.ts:19` — process.env
- `environment` `process.env` `configurations/vite.config.ts:22` — process.env
- `environment` `process.env` `configurations/vite.config.ts:24` — process.env
- `environment` `process.env` `configurations/vite.config.ts:26` — process.env
- `environment` `process.env` `configurations/vite.config.ts:44` — process.env
- `environment` `process.env` `configurations/vitest/setup.js:4` — process.env
- `environment` `process.env` `packages/app/src/cli/hooks/clear_command_cache.ts:9` — process.env
- `environment` `process.env` `packages/app/src/cli/models/app/identifiers.ts:51` — process.env
- `environment` `process.env` `packages/app/src/cli/models/app/identifiers.ts:101` — process.env
- `environment` `process.env` `packages/app/src/cli/models/extensions/extension-instance.test.ts:775` — process.env
- `environment` `process.env` `packages/app/src/cli/models/extensions/extension-instance.test.ts:781` — process.env
- `environment` `process.env` `packages/app/src/cli/models/extensions/extension-instance.ts:488` — process.env
- `file` `FileSystemReadAccess` `packages/app/src/cli/models/extensions/specifications/flow_template.ts:89` — fs.read ... ase64')
- `view-component-input` `React props` `packages/app/src/cli/services/app-logs/logs-command/ui/components/Logs.tsx:38` — {\n  pol ... onId,\n}
- `file` `FileSystemReadAccess` `packages/app/src/cli/services/dev/graphiql/server.ts:124` — readFil ... onPath)
- `file` `FileSystemReadAccess` `packages/app/src/cli/services/dev/graphiql/server.ts:126` — readFil ... 'utf8')
- `view-component-input` `React props` `packages/app/src/cli/services/dev/graphiql/templates/graphiql.tsx:352` — {storeF ... appUrl}

## Security-sensitive sinks
- `file-access`: 224
- `command-execution`: 56
- `http-response-body`: 42
- `http-request-url`: 23
- `http-request-data`: 13

### Representative sinks
- `file-access` `bin/bundling/esbuild-plugin-graphiql-imports.js:12` — args.path
- `file-access` `bin/bundling/esbuild-plugin-stacktracey.js:8` — args.path
- `file-access` `bin/bundling/esbuild-plugin-vscode.js:19` — args.pa ...  'esm')
- `command-execution` `bin/cache-inputs.js:25` — join(ro ... n/tsc")
- `command-execution` `bin/cache-inputs.js:26` — "git"
- `file-access` `bin/cache-inputs.js:27` — join(ro ... .yaml")
- `file-access` `bin/create-cli-duplicate-package.js:3` — './packages/cli'
- `file-access` `bin/create-cli-duplicate-package.js:3` — './pack ... i-copy'
- `file-access` `bin/create-cli-duplicate-package.js:5` — './pack ... e.json'
- `file-access` `bin/create-cli-duplicate-package.js:9` — './pack ... t.json'
- `file-access` `bin/create-cli-duplicate-package.js:16` — './pack ... e.json'
- `file-access` `bin/create-cli-duplicate-package.js:17` — './pack ... t.json'
- `file-access` `bin/create-doc-pr.js:22` — path.jo ... leName)
- `file-access` `bin/create-doc-pr.js:55` — cliKitP ... sonPath
- `file-access` `bin/create-homebrew-pr.js:47` — path.jo ... li.rb")
- `file-access` `bin/create-homebrew-pr.js:54` — path.jo ... re.rb")
- `file-access` `bin/create-homebrew-pr.js:57` — path.jo ... ly.rb")
- `file-access` `bin/create-homebrew-pr.js:107` — cliKitP ... sonPath
- `file-access` `bin/create-homebrew-pr.js:120` — templatePath
- `http-request-url` `bin/create-homebrew-pr.js:138` — `https: ... ${pkg}`
- `http-request-url` `bin/create-homebrew-pr.js:152` — url
- `file-access` `bin/create-homebrew-pr.js:165` — to
- `file-access` `bin/create-homebrew-pr.js:166` — to
- `file-access` `bin/create-homebrew-pr.js:168` — to
- `file-access` `bin/create-homebrew-pr.js:177` — templateItemPath
- `file-access` `bin/create-homebrew-pr.js:179` — templateItemPath
- `file-access` `bin/create-homebrew-pr.js:180` — outputPath
- `file-access` `bin/create-homebrew-pr.js:183` — path.di ... utPath)
- `file-access` `bin/create-homebrew-pr.js:184` — path.di ... utPath)
- `file-access` `bin/create-homebrew-pr.js:186` — templateItemPath
- `file-access` `bin/create-homebrew-pr.js:191` — templateItemPath
- `file-access` `bin/create-homebrew-pr.js:191` — outputP ... tLiquid
- `file-access` `bin/create-homebrew-pr.js:192` — outputP ... tLiquid
- `file-access` `bin/create-homebrew-pr.js:194` — templateItemPath
- `file-access` `bin/create-homebrew-pr.js:194` — outputPath
- `file-access` `bin/create-notification-pr.js:101` — cliKitP ... sonPath
- `command-execution` `bin/create-test-app.js:84` — os.plat ... "which"
- `command-execution` `bin/create-test-app.js:121` — "shopify"
- `command-execution` `bin/create-test-app.js:128` — nodePackageManager
- `command-execution` `bin/create-test-app.js:134` — "npm"
- `command-execution` `bin/create-test-app.js:141` — command
- `command-execution` `bin/create-test-app.js:160` — "yarn"
- `command-execution` `bin/create-test-app.js:162` — packageManager
- `file-access` `bin/create-test-app.js:169` — appPath
- `file-access` `bin/create-test-app.js:178` — appPath
- `file-access` `bin/create-test-app.js:200` — lockFilePath
- `file-access` `bin/create-test-app.js:201` — lockFilePath
- `command-execution` `bin/create-test-app.js:212` — "shopify"
- `command-execution` `bin/create-test-app.js:218` — "npm"
- `command-execution` `bin/create-test-app.js:232` — nodePackageManager
- `command-execution` `bin/create-test-app.js:243` — "npm"
- `command-execution` `bin/create-test-app.js:302` — nodePackageManager
- `file-access` `bin/create-test-app.js:319` — appPath
- `command-execution` `bin/create-test-theme.js:62` — "brew"
- `command-execution` `bin/create-test-theme.js:64` — "brew"
- `command-execution` `bin/create-test-theme.js:67` — "shopify-nightly"
- `command-execution` `bin/create-test-theme.js:72` — "pnpm"
- `command-execution` `bin/create-test-theme.js:76` — "node"
- `command-execution` `bin/create-test-theme.js:81` — os.plat ... "which"
- `command-execution` `bin/create-test-theme.js:92` — "npm"
- `command-execution` `bin/create-test-theme.js:98` — "shopify"
- `file-access` `bin/create-test-theme.js:106` — themePath
- `file-access` `bin/create-test-theme.js:113` — themePath
- `command-execution` `bin/create-test-theme.js:152` — "brew"
- `command-execution` `bin/create-test-theme.js:160` — "npm"
- `file-access` `bin/create-test-theme.js:172` — themePath
- `command-execution` `bin/deploy-experimental.js:5` — "git"
- `command-execution` `bin/deploy-experimental.js:14` — "git"
- `command-execution` `bin/deploy-experimental.js:18` — "git"
- `command-execution` `bin/deploy-experimental.js:22` — "git"
- `command-execution` `bin/deploy-experimental.js:26` — "git"
- `command-execution` `bin/deploy-experimental.js:28` — "git"
- `command-execution` `bin/deploy-experimental.js:34` — "git"
- `command-execution` `bin/deploy-experimental.js:37` — "open"
- `http-request-url` `bin/get-graphql-schemas.js:123` — download_url
- `file-access` `bin/get-graphql-schemas.js:148` — dir
- `file-access` `bin/get-graphql-schemas.js:149` — localFilePath
- `command-execution` `bin/get-graphql-schemas.js:206` — `/opt/d ... alDir}`
- `file-access` `bin/get-graphql-schemas.js:210` — sourcePath
- `file-access` `bin/get-graphql-schemas.js:210` — localPath
- `command-execution` `bin/pin-github-actions.js:32` — `GH_ADM ... -empty`
- `file-access` `bin/prettify-manifests.js:15` — file
- `file-access` `bin/prettify-manifests.js:17` — file
- `command-execution` `bin/run-command.js:10` — command
- `file-access` `bin/update-bugsnag.js:14` — `${__di ... e.json`
- `file-access` `bin/update-bugsnag.js:32` — path.jo ... opify')
- `file-access` `bin/update-bugsnag.js:33` — path.jo ... Name}`)
- `file-access` `bin/update-bugsnag.js:36` — sourceDirectory
- `file-access` `bin/update-bugsnag.js:36` — temporaryPackageCopy
- `file-access` `bin/update-bugsnag.js:48` — temporaryDirectory
- `file-access` `bin/update-bugsnag.js:57` — sourcemap
- `file-access` `bin/update-cli-kit-version.js:12` — packageJsonPath
- `file-access` `bin/update-cli-kit-version.js:15` — versionFilePath
- `file-access` `bin/update-observe.js:87` — join(__ ... .json')
- `http-request-url` `bin/update-observe.js:354` — config.endpoint
- `http-request-data` `bin/update-observe.js:356` — {'Conte ... COOKIE}
- `http-request-data` `bin/update-observe.js:357` — JSON.st ... ables})
- `file-access` `bin/update-observe.js:384` — path
- `file-access` `bin/update-observe.js:385` — path
- `file-access` `bin/update-observe.js:391` — dirname(path)

## CodeQL structural source-to-sink slices
### DFD-1 GraphiQL local proxy
- Reachable: `True`
- Path count: `13`
- Path 1: `packages/app/src/cli/services/dev/graphiql/server.ts:237` → `packages/app/src/cli/services/dev/graphiql/server.ts:244` → `packages/cli-kit/src/public/node/api/admin.ts:218` → `packages/cli-kit/src/public/node/api/admin.ts:219` → `packages/cli-kit/src/public/node/api/admin.ts:223` → `packages/cli-kit/src/public/node/api/admin.ts:221` → `packages/cli-kit/src/public/node/api/admin.ts:225` → `packages/app/src/cli/services/dev/graphiql/server.ts:244` → `packages/app/src/cli/services/dev/graphiql/server.ts:261`
- Path 2: `packages/app/src/cli/services/dev/graphiql/server.ts:237` → `packages/app/src/cli/services/dev/graphiql/server.ts:244` → `packages/cli-kit/src/public/node/api/admin.ts:218` → `packages/cli-kit/src/public/node/api/admin.ts:219` → `packages/cli-kit/src/public/node/api/admin.ts:223` → `packages/cli-kit/src/public/node/api/admin.ts:221` → `packages/cli-kit/src/public/node/api/admin.ts:225` → `packages/app/src/cli/services/dev/graphiql/server.ts:244` → `packages/app/src/cli/services/dev/graphiql/server.ts:261` → `packages/cli-kit/src/public/node/http.ts:171` → `packages/cli-kit/src/public/node/http.ts:176` → `packages/cli-kit/src/public/node/http.ts:175` → `packages/cli-kit/src/public/node/http.ts:184` → `packages/cli-kit/src/public/node/http.ts:119` → `packages/cli-kit/src/public/node/http.ts:142`
- Path 3: `packages/app/src/cli/services/dev/graphiql/server.ts:237` → `packages/app/src/cli/services/dev/graphiql/server.ts:244` → `packages/cli-kit/src/public/node/api/admin.ts:218` → `packages/cli-kit/src/public/node/api/admin.ts:219` → `packages/cli-kit/src/public/node/api/admin.ts:223` → `packages/cli-kit/src/public/node/api/admin.ts:221` → `packages/cli-kit/src/public/node/api/admin.ts:225` → `packages/app/src/cli/services/dev/graphiql/server.ts:244` → `packages/app/src/cli/services/dev/graphiql/server.ts:261` → `packages/cli-kit/src/public/node/http.ts:171` → `packages/cli-kit/src/public/node/http.ts:176` → `packages/cli-kit/src/public/node/http.ts:175` → `packages/cli-kit/src/public/node/http.ts:184` → `packages/cli-kit/src/public/node/http.ts:119` → `packages/cli-kit/src/public/node/http.ts:147` → `packages/cli-kit/src/public/node/http.ts:146` → `packages/cli-kit/src/private/node/api.ts:270` → `packages/cli-kit/src/private/node/api.ts:273` → `packages/cli-kit/src/private/node/api.ts:170` → `packages/cli-kit/src/private/node/api.ts:178` → `packages/cli-kit/src/private/node/api.ts:141` → `packages/cli-kit/src/private/node/api.ts:163` → `packages/cli-kit/src/public/node/output.ts:314` → `packages/cli-kit/src/public/node/output.ts:315` → `packages/cli-kit/src/public/node/output.ts:240` → `packages/cli-kit/src/public/node/output.ts:244` → `packages/cli-kit/src/public/node/output.ts:347` → `packages/cli-kit/src/public/node/output.ts:351` → `packages/cli-kit/src/public/node/output.ts:244` → `packages/cli-kit/src/public/node/output.ts:246` → `packages/cli-kit/src/public/node/output.ts:230` → `packages/cli-kit/src/public/node/testing/output.ts:1` → `packages/cli-kit/src/public/node/testing/output.ts:20` → `packages/app/src/cli/services/organization/list.test.ts:48`
- Path 4: `packages/app/src/cli/services/dev/graphiql/server.ts:237` → `packages/app/src/cli/services/dev/graphiql/server.ts:244` → `packages/cli-kit/src/public/node/api/admin.ts:218` → `packages/cli-kit/src/public/node/api/admin.ts:219` → `packages/cli-kit/src/public/node/api/admin.ts:223` → `packages/cli-kit/src/public/node/api/admin.ts:221` → `packages/cli-kit/src/public/node/api/admin.ts:225` → `packages/app/src/cli/services/dev/graphiql/server.ts:244` → `packages/app/src/cli/services/dev/graphiql/server.ts:261` → `packages/cli-kit/src/public/node/http.ts:171` → `packages/cli-kit/src/public/node/http.ts:176` → `packages/cli-kit/src/public/node/http.ts:175` → `packages/cli-kit/src/public/node/http.ts:184` → `packages/cli-kit/src/public/node/http.ts:119` → `packages/cli-kit/src/public/node/http.ts:147` → `packages/cli-kit/src/public/node/http.ts:146` → `packages/cli-kit/src/private/node/api.ts:270` → `packages/cli-kit/src/private/node/api.ts:273` → `packages/cli-kit/src/private/node/api.ts:170` → `packages/cli-kit/src/private/node/api.ts:178` → `packages/cli-kit/src/private/node/api.ts:141` → `packages/cli-kit/src/private/node/api.ts:163` → `packages/cli-kit/src/public/node/output.ts:314` → `packages/cli-kit/src/public/node/output.ts:315` → `packages/cli-kit/src/public/node/output.ts:240` → `packages/cli-kit/src/public/node/output.ts:244` → `packages/cli-kit/src/public/node/output.ts:347` → `packages/cli-kit/src/public/node/output.ts:351` → `packages/cli-kit/src/public/node/output.ts:244` → `packages/cli-kit/src/public/node/output.ts:246` → `packages/cli-kit/src/public/node/output.ts:230` → `packages/cli-kit/src/public/node/testing/output.ts:1` → `packages/cli-kit/src/public/node/testing/output.ts:20` → `packages/app/src/cli/services/organization/list.test.ts:64`
- Path 5: `packages/app/src/cli/services/dev/graphiql/server.ts:237` → `packages/app/src/cli/services/dev/graphiql/server.ts:244` → `packages/cli-kit/src/public/node/api/admin.ts:218` → `packages/cli-kit/src/public/node/api/admin.ts:219` → `packages/cli-kit/src/public/node/api/admin.ts:223` → `packages/cli-kit/src/public/node/api/admin.ts:221` → `packages/cli-kit/src/public/node/api/admin.ts:225` → `packages/app/src/cli/services/dev/graphiql/server.ts:244` → `packages/app/src/cli/services/dev/graphiql/server.ts:261` → `packages/cli-kit/src/public/node/http.ts:171` → `packages/cli-kit/src/public/node/http.ts:176` → `packages/cli-kit/src/public/node/http.ts:175` → `packages/cli-kit/src/public/node/http.ts:184` → `packages/cli-kit/src/public/node/http.ts:119` → `packages/cli-kit/src/public/node/http.ts:147` → `packages/cli-kit/src/public/node/http.ts:146` → `packages/cli-kit/src/private/node/api.ts:270` → `packages/cli-kit/src/private/node/api.ts:273` → `packages/cli-kit/src/private/node/api.ts:170` → `packages/cli-kit/src/private/node/api.ts:178` → `packages/cli-kit/src/private/node/api.ts:141` → `packages/cli-kit/src/private/node/api.ts:163` → `packages/cli-kit/src/public/node/output.ts:314` → `packages/cli-kit/src/public/node/output.ts:316` → `packages/cli-kit/src/public/node/output.ts:347` → `packages/cli-kit/src/public/node/output.ts:351` → `packages/cli-kit/src/public/node/output.ts:316` → `packages/cli-kit/src/public/node/output.ts:317` → `packages/cli-kit/src/public/node/output.ts:386` → `packages/cli-kit/src/public/node/output.ts:391` → `packages/cli-kit/src/private/node/output.ts:41` → `packages/cli-kit/src/private/node/output.ts:42` → `packages/cli-kit/src/private/node/output.ts:19` → `packages/cli-kit/src/private/node/output.ts:21` → `packages/cli-kit/src/private/node/output.ts:42`

### DFD-2 Extension dev server
- Reachable: `True`
- Path count: `11`
- Path 1: `packages/app/src/cli/services/dev/extension/websocket/handlers.test.ts:241`
- Path 2: `packages/app/src/cli/services/dev/extension/websocket/handlers.test.ts:299`
- Path 3: `packages/app/src/cli/services/dev/extension/websocket/handlers.ts:36`
- Path 4: `packages/app/src/cli/services/dev/extension/websocket/handlers.ts:106`
- Path 5: `packages/app/src/cli/services/dev/extension/websocket/handlers.ts:54` → `packages/cli-kit/src/private/node/content-tokens.ts:59` → `packages/cli-kit/src/public/node/output.ts:347` → `packages/cli-kit/src/public/node/output.ts:351` → `packages/cli-kit/src/private/node/content-tokens.ts:59` → `packages/app/src/cli/services/dev/extension/websocket/handlers.ts:54` → `packages/app/src/cli/services/dev/extension/websocket/handlers.ts:51` → `packages/app/src/cli/services/dev/extension/websocket/handlers.ts:61`

### DFD-3 Theme dev server
- Reachable: `True`
- Path count: `17`
- Path 1: `packages/theme/src/cli/utilities/theme-fs.ts:573` → `packages/theme/src/cli/utilities/theme-fs.ts:576` → `packages/theme/src/cli/utilities/theme-fs.ts:574` → `packages/theme/src/cli/utilities/theme-environment/hot-reload/server.ts:225` → `packages/cli-kit/src/public/node/fs.ts:121` → `packages/cli-kit/src/public/node/fs.ts:125`
- Path 2: `packages/theme/src/cli/services/info.ts:65` → `packages/theme/src/cli/services/info.ts:60` → `packages/theme/src/cli/commands/theme/info.ts:53` → `packages/cli-kit/src/public/node/output.ts:260` → `packages/cli-kit/src/public/node/output.ts:261` → `packages/cli-kit/src/private/node/output.ts:53` → `packages/cli-kit/src/private/node/output.ts:54` → `packages/cli-kit/src/public/node/output.ts:240` → `packages/cli-kit/src/public/node/output.ts:244` → `packages/cli-kit/src/public/node/output.ts:347` → `packages/cli-kit/src/public/node/output.ts:351` → `packages/cli-kit/src/public/node/output.ts:244` → `packages/cli-kit/src/public/node/output.ts:246` → `packages/cli-kit/src/public/node/output.ts:230` → `packages/cli-kit/src/public/node/testing/output.ts:1` → `packages/cli-kit/src/public/node/testing/output.ts:20` → `packages/app/src/cli/services/organization/list.test.ts:48`
- Path 3: `packages/theme/src/cli/services/info.ts:65` → `packages/theme/src/cli/services/info.ts:60` → `packages/theme/src/cli/commands/theme/info.ts:53` → `packages/cli-kit/src/public/node/output.ts:260` → `packages/cli-kit/src/public/node/output.ts:261` → `packages/cli-kit/src/private/node/output.ts:53` → `packages/cli-kit/src/private/node/output.ts:54` → `packages/cli-kit/src/public/node/output.ts:240` → `packages/cli-kit/src/public/node/output.ts:244` → `packages/cli-kit/src/public/node/output.ts:347` → `packages/cli-kit/src/public/node/output.ts:351` → `packages/cli-kit/src/public/node/output.ts:244` → `packages/cli-kit/src/public/node/output.ts:246` → `packages/cli-kit/src/public/node/output.ts:230` → `packages/cli-kit/src/public/node/testing/output.ts:1` → `packages/cli-kit/src/public/node/testing/output.ts:20` → `packages/app/src/cli/services/organization/list.test.ts:64`
- Path 4: `packages/theme/src/cli/services/info.ts:65` → `packages/theme/src/cli/services/info.ts:60` → `packages/theme/src/cli/commands/theme/info.ts:53` → `packages/cli-kit/src/public/node/output.ts:260` → `packages/cli-kit/src/public/node/output.ts:261` → `packages/cli-kit/src/private/node/output.ts:53` → `packages/cli-kit/src/private/node/output.ts:55` → `packages/cli-kit/src/public/node/output.ts:347` → `packages/cli-kit/src/public/node/output.ts:351` → `packages/cli-kit/src/private/node/output.ts:55` → `packages/cli-kit/src/private/node/output.ts:56` → `packages/cli-kit/src/public/node/output.ts:386` → `packages/cli-kit/src/public/node/output.ts:391` → `packages/cli-kit/src/private/node/output.ts:32` → `packages/cli-kit/src/private/node/output.ts:33` → `packages/cli-kit/src/private/node/output.ts:19` → `packages/cli-kit/src/private/node/output.ts:21` → `packages/cli-kit/src/private/node/output.ts:33`
- Path 5: `packages/theme/src/cli/services/info.ts:65` → `packages/theme/src/cli/services/info.ts:60` → `packages/theme/src/cli/commands/theme/info.ts:53` → `packages/cli-kit/src/public/node/output.ts:260` → `packages/cli-kit/src/public/node/output.ts:261` → `packages/cli-kit/src/private/node/output.ts:53` → `packages/cli-kit/src/private/node/output.ts:55` → `packages/cli-kit/src/public/node/output.ts:347` → `packages/cli-kit/src/public/node/output.ts:351` → `packages/cli-kit/src/private/node/output.ts:55` → `packages/cli-kit/src/private/node/output.ts:56` → `packages/cli-kit/src/public/node/output.ts:386` → `packages/cli-kit/src/public/node/output.ts:391` → `packages/cli-kit/src/private/node/output.ts:41` → `packages/cli-kit/src/private/node/output.ts:42` → `packages/cli-kit/src/private/node/output.ts:19` → `packages/cli-kit/src/private/node/output.ts:21` → `packages/cli-kit/src/private/node/output.ts:42`

### DFD-4 Build/package include-assets
- Reachable: `True`
- Path count: `6`
- Path 1: `packages/theme/src/cli/utilities/theme-fs.ts:573` → `packages/theme/src/cli/utilities/theme-fs.ts:576` → `packages/theme/src/cli/utilities/theme-fs.ts:574` → `packages/theme/src/cli/utilities/theme-environment/hot-reload/server.ts:225` → `packages/cli-kit/src/public/node/fs.ts:121` → `packages/cli-kit/src/public/node/fs.ts:125`
- Path 2: `packages/theme/src/cli/utilities/repl/repl.ts:25` → `packages/theme/src/cli/utilities/repl/repl.ts:27` → `packages/theme/src/cli/utilities/repl/repl.ts:33` → `packages/theme/src/cli/utilities/repl/repl.ts:45` → `packages/theme/src/cli/utilities/repl/evaluator.ts:19` → `packages/theme/src/cli/utilities/repl/evaluator.ts:22` → `packages/theme/src/cli/utilities/repl/evaluator.ts:39` → `packages/theme/src/cli/utilities/repl/evaluator.ts:42` → `packages/theme/src/cli/utilities/repl/evaluator.ts:47`
- Path 3: `packages/theme/src/cli/utilities/repl/evaluator.ts:34` → `packages/theme/src/cli/utilities/repl/evaluator.ts:36` → `packages/theme/src/cli/utilities/repl/evaluator.ts:133` → `packages/theme/src/cli/utilities/repl/evaluator.ts:134` → `packages/theme/src/cli/utilities/repl/evaluator.ts:141` → `packages/theme/src/cli/utilities/repl/evaluator.ts:142` → `packages/theme/src/cli/utilities/repl/evaluator.ts:145` → `packages/theme/src/cli/utilities/repl/evaluator.ts:134` → `packages/theme/src/cli/utilities/repl/evaluator.ts:136`
- Path 4: `packages/theme/src/cli/services/info.ts:65` → `packages/theme/src/cli/services/info.ts:60` → `packages/theme/src/cli/commands/theme/info.ts:53` → `packages/cli-kit/src/public/node/output.ts:260` → `packages/cli-kit/src/public/node/output.ts:261` → `packages/cli-kit/src/private/node/output.ts:53` → `packages/cli-kit/src/private/node/output.ts:54` → `packages/cli-kit/src/public/node/output.ts:240` → `packages/cli-kit/src/public/node/output.ts:244` → `packages/cli-kit/src/public/node/output.ts:347` → `packages/cli-kit/src/public/node/output.ts:351` → `packages/cli-kit/src/public/node/output.ts:244` → `packages/cli-kit/src/public/node/output.ts:246` → `packages/cli-kit/src/public/node/output.ts:230` → `packages/cli-kit/src/public/node/testing/output.ts:1` → `packages/cli-kit/src/public/node/testing/output.ts:20` → `packages/app/src/cli/services/organization/list.test.ts:48`
- Path 5: `packages/theme/src/cli/services/info.ts:65` → `packages/theme/src/cli/services/info.ts:60` → `packages/theme/src/cli/commands/theme/info.ts:53` → `packages/cli-kit/src/public/node/output.ts:260` → `packages/cli-kit/src/public/node/output.ts:261` → `packages/cli-kit/src/private/node/output.ts:53` → `packages/cli-kit/src/private/node/output.ts:54` → `packages/cli-kit/src/public/node/output.ts:240` → `packages/cli-kit/src/public/node/output.ts:244` → `packages/cli-kit/src/public/node/output.ts:347` → `packages/cli-kit/src/public/node/output.ts:351` → `packages/cli-kit/src/public/node/output.ts:244` → `packages/cli-kit/src/public/node/output.ts:246` → `packages/cli-kit/src/public/node/output.ts:230` → `packages/cli-kit/src/public/node/testing/output.ts:1` → `packages/cli-kit/src/public/node/testing/output.ts:20` → `packages/app/src/cli/services/organization/list.test.ts:64`

### DFD-5 Process/native binary execution
- Reachable: `True`
- Path count: `6`
- Path 1: `packages/cli-kit/src/public/node/notifications-system.ts:178` → `packages/cli-kit/src/public/node/notifications-system.ts:185` → `packages/cli-kit/src/public/node/notifications-system.ts:190`
- Path 2: `packages/plugin-cloudflare/src/install-cloudflared.ts:61` → `packages/plugin-cloudflare/src/install-cloudflared.ts:63` → `packages/plugin-cloudflare/src/install-cloudflared.ts:80` → `packages/plugin-cloudflare/src/install-cloudflared.ts:85`
- Path 3: `packages/app/src/cli/utilities/mkcert.ts:141` → `packages/app/src/cli/utilities/mkcert.ts:173` → `packages/app/src/cli/utilities/mkcert.ts:27` → `packages/app/src/cli/utilities/mkcert.ts:31` → `packages/app/src/cli/utilities/mkcert.ts:33` → `packages/app/src/cli/utilities/mkcert.ts:173` → `packages/app/src/cli/utilities/mkcert.ts:186`
- Path 4: `packages/app/src/cli/utilities/mkcert.ts:141` → `packages/app/src/cli/utilities/mkcert.ts:173` → `packages/app/src/cli/utilities/mkcert.ts:27` → `packages/app/src/cli/utilities/mkcert.ts:31` → `packages/app/src/cli/utilities/mkcert.ts:33` → `packages/app/src/cli/utilities/mkcert.ts:173` → `packages/app/src/cli/utilities/mkcert.ts:186` → `packages/cli-kit/src/public/node/system.ts:236` → `packages/cli-kit/src/public/node/system.ts:243` → `packages/cli-kit/src/public/node/system.ts:291` → `packages/cli-kit/src/public/node/system.ts:302`
- Path 5: `packages/app/src/cli/services/function/ui/components/Replay/Replay.tsx:23` → `packages/app/src/cli/services/function/ui/components/Replay/Replay.tsx:26` → `packages/app/src/cli/services/dev/app-events/app-event-watcher.ts:101` → `packages/app/src/cli/services/dev/app-events/app-event-watcher.ts:103` → `packages/app/src/cli/services/function/ui/components/Replay/Replay.tsx:26` → `packages/app/src/cli/services/function/ui/components/Replay/Replay.tsx:32` → `packages/app/src/cli/services/function/ui/components/Replay/Replay.tsx:27` → `packages/app/src/cli/services/function/ui/components/Replay/hooks/useFunctionWatcher.ts:23` → `packages/app/src/cli/services/function/ui/components/Replay/hooks/useFunctionWatcher.ts:28` → `packages/app/src/cli/services/function/ui/components/Replay/hooks/useFunctionWatcher.ts:93` → `packages/app/src/cli/services/dev/app-events/app-event-watcher.ts:127` → `packages/app/src/cli/services/dev/app-events/file-watcher.ts:66` → `packages/app/src/cli/services/dev/app-events/file-watcher.ts:70` → `packages/app/src/cli/services/dev/app-events/app-event-watcher.ts:127` → `packages/app/src/cli/services/dev/app-events/app-event-watcher.ts:158` → `packages/app/src/cli/services/dev/app-events/file-watcher.ts:113` → `packages/app/src/cli/services/dev/app-events/file-watcher.ts:153` → `packages/app/src/cli/services/dev/app-events/file-watcher.ts:155` → `packages/app/src/cli/models/extensions/extension-instance.ts:459` → `packages/app/src/cli/models/extensions/extension-instance.ts:495` → `packages/app/src/cli/models/extensions/extension-instance.ts:277` → `packages/app/src/cli/models/extensions/extension-instance.ts:245` → `packages/app/src/cli/models/extensions/extension-instance.ts:246` → `packages/app/src/cli/models/extensions/extension-instance.ts:277` → `packages/app/src/cli/models/extensions/extension-instance.ts:278` → `packages/cli-kit/src/public/node/import-extractor.ts:152` → `packages/cli-kit/src/public/node/import-extractor.ts:153` → `packages/cli-kit/src/public/node/import-extractor.ts:156` → `packages/cli-kit/src/public/node/import-extractor.ts:175`

### DFD-6 OAuth/session/API
- Reachable: `True`
- Path count: `48`
- Path 1: `packages/cli-kit/src/private/node/api/graphql.ts:15`
- Path 2: `packages/cli-kit/src/private/node/api/graphql.ts:143`
- Path 3: `packages/cli-kit/src/private/node/session/device-authorization.ts:67`
- Path 4: `packages/cli-kit/src/private/node/session/device-authorization.ts:48` → `packages/cli-kit/src/private/node/session/device-authorization.ts:63`
- Path 5: `packages/theme/src/cli/utilities/theme-environment/storefront-session.ts:117` → `packages/theme/src/cli/utilities/theme-environment/storefront-session.ts:115` → `packages/cli-kit/src/public/node/output.ts:314` → `packages/cli-kit/src/public/node/output.ts:316` → `packages/cli-kit/src/public/node/output.ts:347` → `packages/cli-kit/src/public/node/output.ts:351` → `packages/cli-kit/src/public/node/output.ts:316` → `packages/cli-kit/src/public/node/output.ts:317` → `packages/cli-kit/src/public/node/output.ts:386` → `packages/cli-kit/src/public/node/output.ts:391` → `packages/cli-kit/src/private/node/output.ts:41` → `packages/cli-kit/src/private/node/output.ts:42` → `packages/cli-kit/src/private/node/output.ts:19` → `packages/cli-kit/src/private/node/output.ts:21` → `packages/cli-kit/src/private/node/output.ts:42`

### DFD-7 Template/init/generate
- Reachable: `False`
- Path count: `0`
- No CodeQL path found with current custom model.

### SSRF/proxy/webhook cross-cut
- Reachable: `True`
- Path count: `5`
- Path 1: `packages/app/src/cli/services/dev/graphiql/server.ts:237` → `packages/app/src/cli/services/dev/graphiql/server.ts:244` → `packages/cli-kit/src/public/node/api/admin.ts:218` → `packages/cli-kit/src/public/node/api/admin.ts:219` → `packages/cli-kit/src/public/node/api/admin.ts:223` → `packages/cli-kit/src/public/node/api/admin.ts:221` → `packages/cli-kit/src/public/node/api/admin.ts:225` → `packages/app/src/cli/services/dev/graphiql/server.ts:244` → `packages/app/src/cli/services/dev/graphiql/server.ts:261`
- Path 2: `packages/theme/src/cli/utilities/theme-environment/proxy.ts:280` → `packages/theme/src/cli/utilities/theme-environment/proxy.ts:294` → `packages/theme/src/cli/utilities/theme-environment/proxy.ts:319` → `packages/theme/src/cli/utilities/theme-environment/proxy.ts:323` → `packages/theme/src/cli/utilities/theme-environment/proxy.ts:322` → `packages/theme/src/cli/utilities/theme-environment/proxy.ts:334` → `packages/theme/src/cli/utilities/theme-environment/storefront-utils.ts:30` → `packages/theme/src/cli/utilities/theme-environment/storefront-utils.ts:34` → `packages/theme/src/cli/utilities/theme-environment/proxy.ts:334` → `packages/theme/src/cli/utilities/theme-environment/proxy.ts:343`
- Path 3: `packages/app/src/cli/services/dev/graphiql/server.ts:237` → `packages/app/src/cli/services/dev/graphiql/server.ts:244` → `packages/cli-kit/src/public/node/api/admin.ts:218` → `packages/cli-kit/src/public/node/api/admin.ts:219` → `packages/cli-kit/src/public/node/api/admin.ts:223` → `packages/cli-kit/src/public/node/api/admin.ts:221` → `packages/cli-kit/src/public/node/api/admin.ts:225` → `packages/app/src/cli/services/dev/graphiql/server.ts:244` → `packages/app/src/cli/services/dev/graphiql/server.ts:261` → `packages/cli-kit/src/public/node/http.ts:171` → `packages/cli-kit/src/public/node/http.ts:176` → `packages/cli-kit/src/public/node/http.ts:175` → `packages/cli-kit/src/public/node/http.ts:184` → `packages/cli-kit/src/public/node/http.ts:119` → `packages/cli-kit/src/public/node/http.ts:142`
- Path 4: `packages/theme/src/cli/utilities/theme-environment/proxy.ts:280` → `packages/theme/src/cli/utilities/theme-environment/proxy.ts:294` → `packages/theme/src/cli/utilities/theme-environment/html.ts:55` → `packages/theme/src/cli/utilities/theme-environment/html.ts:49` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:10` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:12` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:68` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:72` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:76` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:81` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:80` → `packages/theme/src/cli/utilities/theme-environment/storefront-utils.ts:30` → `packages/theme/src/cli/utilities/theme-environment/storefront-utils.ts:34` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:80` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:72` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:12` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:27` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:26`
- Path 5: `packages/theme/src/cli/utilities/theme-environment/proxy.ts:280` → `packages/theme/src/cli/utilities/theme-environment/proxy.ts:294` → `packages/theme/src/cli/utilities/theme-environment/html.ts:55` → `packages/theme/src/cli/utilities/theme-environment/html.ts:49` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:10` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:12` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:68` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:72` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:76` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:81` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:80` → `packages/theme/src/cli/utilities/theme-environment/storefront-utils.ts:30` → `packages/theme/src/cli/utilities/theme-environment/storefront-utils.ts:34` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:80` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:72` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:12` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:40` → `packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:39`

### Token leakage cross-cut
- Reachable: `True`
- Path count: `109`
- Path 1: `bin/github-utils.js:36` → `bin/github-utils.js:37`
- Path 2: `bin/update-observe.js:377` → `bin/update-observe.js:373` → `bin/update-observe.js:379` → `bin/update-observe.js:383` → `bin/update-observe.js:384`
- Path 3: `bin/update-observe.js:377` → `bin/update-observe.js:373` → `bin/update-observe.js:379` → `bin/update-observe.js:383` → `bin/update-observe.js:385`
- Path 4: `bin/update-observe.js:377` → `bin/update-observe.js:373` → `bin/update-observe.js:379` → `bin/update-observe.js:390` → `bin/update-observe.js:391`
- Path 5: `bin/update-observe.js:377` → `bin/update-observe.js:373` → `bin/update-observe.js:379` → `bin/update-observe.js:390` → `bin/update-observe.js:392`

## Kept P4 findings and source-to-sink paths
### p4-001
- Classification: likely security
- Attacker control: downstream plugin/local caller controls pid
- Boundary: local plugin/library input -> Windows shell
- CodeQL reachability: no-slice
- Primary location: `packages/cli-kit/src/public/node/tree-kill.ts:76`

### p4-002
- Classification: likely security
- Attacker control: malicious website controls cross-origin request
- Boundary: browser origin -> local GraphiQL HTTP JSON
- CodeQL reachability: reachable
- Primary location: `packages/app/src/cli/services/dev/graphiql/server.ts:130`
- Matching slices: DFD-1 GraphiQL local proxy, DFD-1 GraphiQL local proxy, DFD-1 GraphiQL local proxy

### p4-003
- Classification: likely security
- Attacker control: client with GraphiQL key controls api_version query parameter
- Boundary: browser/local HTTP -> token-bearing Shopify Admin request
- CodeQL reachability: reachable

### p4-004
- Classification: likely security
- Attacker control: malicious project/browser controls asset path
- Boundary: browser route/project symlink -> local file read
- CodeQL reachability: no-slice
- Primary location: `packages/app/src/cli/services/dev/extension/server/middlewares.ts:102`

### p4-005
- Classification: likely security
- Attacker control: browser controls app asset filePath route parameter
- Boundary: browser/local HTTP -> local filesystem read
- CodeQL reachability: reachable

### p4-006
- Classification: likely security
- Attacker control: release/cache/env controls binary path
- Boundary: download/env binary -> exec
- CodeQL reachability: reachable
- Primary location: `packages/plugin-cloudflare/src/install-cloudflared.ts:135`
- Matching slices: DFD-5 Process/native binary execution, DFD-5 Process/native binary execution, DFD-5 Process/native binary execution

### p4-006
- Classification: likely security
- Attacker control: release/cache/env controls binary path
- Boundary: download/env binary -> exec
- CodeQL reachability: reachable
- Primary location: `packages/plugin-cloudflare/src/install-cloudflared.ts:135`
- Matching slices: DFD-5 Process/native binary execution, DFD-5 Process/native binary execution, DFD-5 Process/native binary execution

### p4-006
- Classification: likely security
- Attacker control: release/cache/network supply-chain controls artifact
- Boundary: network artifact -> local executable
- CodeQL reachability: reachable
- Primary location: `packages/plugin-cloudflare/src/install-cloudflared.ts:124`
- Matching slices: DFD-5 Process/native binary execution, DFD-5 Process/native binary execution, DFD-5 Process/native binary execution

### p4-007
- Classification: likely security
- Attacker control: GitHub issue author controls issue body/title fetched by Claude
- Boundary: untrusted issue text -> write-capable CI agent
- CodeQL reachability: no-slice

### p4-008
- Classification: likely security
- Attacker control: malicious website/link controls request URL
- Boundary: browser URL -> localhost HTTP response
- CodeQL reachability: no-slice
- Primary location: `packages/app/src/cli/utilities/app/http-reverse-proxy.ts:90`

### p4-009
- Classification: likely security
- Attacker control: client with GraphiQL key controls query/variables
- Boundary: browser URL -> local GraphiQL inline script
- CodeQL reachability: no-slice
- Primary location: `packages/app/src/cli/services/dev/graphiql/templates/graphiql.tsx:261`

## Enrichment verdicts (all non-low candidates)

| Finding | Classification | Attacker Control | Boundary | CodeQL Reachability | Verdict |
|---|---|---|---|---|---|
| p4-001 | security | downstream plugin/local caller controls pid | local plugin/library input -> Windows shell | no-slice | keep |
| p4-002 | security | malicious website controls cross-origin request | browser origin -> local GraphiQL HTTP JSON | reachable | keep |
| p4-003 | security | client with GraphiQL key controls api_version query parameter | browser/local HTTP -> token-bearing Shopify Admin request | reachable | keep |
| p4-004 | security | malicious project/browser controls asset path | browser route/project symlink -> local file read | no-slice | keep |
| p4-005 | security | browser controls app asset filePath route parameter | browser/local HTTP -> local filesystem read | reachable | keep |
| p4-006 | security | release/cache/env controls binary path | download/env binary -> exec | reachable | keep |
| p4-006 | security | release/cache/env controls binary path | download/env binary -> exec | reachable | keep |
| p4-006 | security | release/cache/network supply-chain controls artifact | network artifact -> local executable | reachable | keep |
| p4-007 | security | GitHub issue author controls issue body/title fetched by Claude | untrusted issue text -> write-capable CI agent | no-slice | keep |
| p4-008 | security | malicious website/link controls request URL | browser URL -> localhost HTTP response | no-slice | keep |
| p4-009 | security | client with GraphiQL key controls query/variables | browser URL -> local GraphiQL inline script | no-slice | keep |
| codeql:js/client-side-request-forgery:packages/ui-extensions-server-kit/src/ExtensionServerClient/ExtensionServerClient.ts:202 | correctness/robustness | mostly configured Shopify/store URLs or wrapper arguments | same-user/network wrapper | no-slice | drop |
| codeql:js/client-side-unvalidated-url-redirection:packages/ui-extensions-dev-console/src/sections/Extensions/Extensions.tsx:34 | correctness/robustness | not confirmed | no demonstrated exploit path | no-slice | drop |
| codeql:js/client-side-unvalidated-url-redirection:packages/ui-extensions-dev-console/src/sections/Extensions/components/PreviewLink/PreviewLink.tsx:48 | correctness/robustness | not confirmed | no demonstrated exploit path | no-slice | drop |
| codeql:js/command-line-injection:bin/pin-github-actions.js:32 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | no-slice | drop |
| codeql:js/command-line-injection:packages/cli-kit/src/public/node/system.ts:302 | environment/tooling/admin-only | local CLI config/env or wrapper caller | same-user local process execution | reachable | drop |
| codeql:js/command-line-injection:packages/plugin-cloudflare/src/install-cloudflared.ts:85 | environment/tooling/admin-only | local CLI config/env or wrapper caller | same-user local process execution | reachable | drop |
| codeql:js/file-access-to-http:bin/update-observe.js:354 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | reachable | drop |
| codeql:js/file-access-to-http:bin/update-observe.js:356 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | reachable | drop |
| codeql:js/file-access-to-http:bin/update-observe.js:357 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | reachable | drop |
| codeql:js/file-system-race:bin/create-homebrew-pr.js:186 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | no-slice | drop |
| codeql:js/file-system-race:packages/cli-kit/src/public/node/vendor/dev_server/network/host.ts:15 | correctness/robustness | local path/config in same-user CLI runtime | same-user filesystem | no-slice | drop |
| codeql:js/file-system-race:packages/e2e/setup/app.ts:90 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/file-system-race:packages/e2e/setup/app.ts:91 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/incomplete-hostname-regexp:packages/app/src/cli/services/function/binaries.test.ts:331 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/incomplete-multi-character-sanitization:packages/theme/src/cli/utilities/theme-environment/hot-reload/server.ts:468 | correctness/robustness | none confirmed | no demonstrated trust boundary | reachable | drop |
| codeql:js/incomplete-sanitization:packages/cli/src/cli/commands/docs/generate.ts:89 | correctness/robustness | none confirmed | no demonstrated trust boundary | no-slice | drop |
| codeql:js/incomplete-sanitization:packages/cli/src/cli/commands/docs/generate.ts:91 | correctness/robustness | none confirmed | no demonstrated trust boundary | no-slice | drop |
| codeql:js/incomplete-sanitization:packages/theme/src/cli/utilities/repl/evaluator.ts:42 | correctness/robustness | none confirmed | no demonstrated trust boundary | reachable | drop |
| codeql:js/incomplete-url-substring-sanitization:packages/cli-kit/src/public/node/context/fqdn.ts:142 | correctness/robustness | none confirmed | no demonstrated trust boundary | no-slice | drop |
| codeql:js/incomplete-url-substring-sanitization:packages/e2e/setup/store.ts:51 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/incomplete-url-substring-sanitization:packages/e2e/setup/store.ts:65 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/indirect-command-line-injection:bin/pin-github-actions.js:32 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | no-slice | drop |
| codeql:js/insecure-temporary-file:packages/cli-kit/src/public/node/fs.ts:229 | correctness/robustness | local path/config in same-user CLI runtime | same-user filesystem | reachable | drop |
| codeql:js/insecure-temporary-file:packages/cli-kit/src/public/node/import-extractor.ts:38 | correctness/robustness | local path/config in same-user CLI runtime | same-user filesystem | reachable | drop |
| codeql:js/missing-await:packages/theme/src/cli/utilities/theme-fs.ts:146 | correctness/robustness | none confirmed | no demonstrated trust boundary | reachable | drop |
| codeql:js/overwritten-property:packages/create-app/bin/bundle.js:31 | correctness/robustness | not confirmed | no demonstrated exploit path | no-slice | drop |
| codeql:js/path-injection:bin/update-bugsnag.js:33 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | no-slice | drop |
| codeql:js/path-injection:bin/update-bugsnag.js:36 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | no-slice | drop |
| codeql:js/path-injection:bin/update-observe.js:384 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | reachable | drop |
| codeql:js/path-injection:bin/update-observe.js:385 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | reachable | drop |
| codeql:js/path-injection:bin/update-observe.js:391 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | reachable | drop |
| codeql:js/path-injection:bin/update-observe.js:392 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | reachable | drop |
| codeql:js/path-injection:bin/update-observe.js:394 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | reachable | drop |
| codeql:js/path-injection:bin/update-observe.js:402 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | reachable | drop |
| codeql:js/path-injection:packages/cli-kit/src/public/node/fs.ts:125 | correctness/robustness | local path/config in same-user CLI runtime | same-user filesystem | reachable | drop |
| codeql:js/path-injection:packages/cli-kit/src/public/node/fs.ts:280 | correctness/robustness | local path/config in same-user CLI runtime | same-user filesystem | reachable | drop |
| codeql:js/path-injection:packages/cli-kit/src/public/node/fs.ts:393 | correctness/robustness | local path/config in same-user CLI runtime | same-user filesystem | reachable | drop |
| codeql:js/path-injection:packages/cli-kit/src/public/node/fs.ts:427 | correctness/robustness | local path/config in same-user CLI runtime | same-user filesystem | reachable | drop |
| codeql:js/path-injection:packages/cli-kit/src/public/node/fs.ts:479 | correctness/robustness | local path/config in same-user CLI runtime | same-user filesystem | reachable | drop |
| codeql:js/path-injection:packages/cli-kit/src/public/node/fs.ts:540 | correctness/robustness | local path/config in same-user CLI runtime | same-user filesystem | reachable | drop |
| codeql:js/path-injection:packages/cli-kit/src/public/node/system.ts:49 | correctness/robustness | local path/config in same-user CLI runtime | same-user filesystem | reachable | drop |
| codeql:js/path-injection:packages/e2e/setup/auth.ts:43 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/path-injection:packages/e2e/setup/auth.ts:44 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/path-injection:packages/e2e/setup/auth.ts:45 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/path-injection:packages/e2e/setup/auth.ts:46 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/path-injection:packages/e2e/setup/auth.ts:51 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/path-injection:packages/e2e/setup/auth.ts:52 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/path-injection:packages/e2e/setup/auth.ts:53 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/path-injection:packages/e2e/setup/auth.ts:54 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/path-injection:packages/e2e/setup/browser.ts:60 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/path-injection:packages/e2e/setup/env.ts:139 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/path-injection:packages/e2e/setup/global-auth.ts:40 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/path-injection:packages/e2e/setup/store.ts:56 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/polynomial-redos:packages/eslint-plugin-cli/rules/banner-headline-format.js:19 | correctness/robustness | none confirmed | no demonstrated trust boundary | no-slice | drop |
| codeql:js/regex-injection:packages/plugin-cloudflare/src/tunnel.ts:178 | correctness/robustness | not confirmed | no demonstrated exploit path | no-slice | drop |
| codeql:js/regex/missing-regexp-anchor:packages/app/src/cli/services/function/binaries.test.ts:128 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/regex/missing-regexp-anchor:packages/app/src/cli/services/function/binaries.test.ts:229 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/regex/missing-regexp-anchor:packages/app/src/cli/services/function/binaries.test.ts:249 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/regex/missing-regexp-anchor:packages/app/src/cli/services/function/binaries.test.ts:50 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/regex/missing-regexp-anchor:packages/app/src/cli/services/function/binaries.test.ts:70 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/regex/missing-regexp-anchor:packages/e2e/setup/store.ts:112 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/remote-property-injection:packages/cli-kit/src/public/node/vendor/dev_server/network/host.ts:29 | correctness/robustness | local app state/config keys; no confirmed cross-tenant impact | same-user state | no-slice | drop |
| codeql:js/remote-property-injection:packages/e2e/setup/global-auth.ts:76 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/remote-property-injection:packages/ui-extensions-server-kit/src/ExtensionServerClient/ExtensionServerClient.ts:244 | correctness/robustness | local app state/config keys; no confirmed cross-tenant impact | same-user state | no-slice | drop |
| codeql:js/remote-property-injection:workspace/src/major-change-check.js:104 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/request-forgery:bin/create-homebrew-pr.js:152 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | no-slice | drop |
| codeql:js/request-forgery:bin/update-observe.js:354 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | reachable | drop |
| codeql:js/request-forgery:packages/cli-kit/src/public/node/http.ts:142 | correctness/robustness | mostly configured Shopify/store URLs or wrapper arguments | same-user/network wrapper | reachable | drop |
| codeql:js/request-forgery:packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:23 | correctness/robustness | mostly configured Shopify/store URLs or wrapper arguments | same-user/network wrapper | reachable | drop |
| codeql:js/request-forgery:packages/theme/src/cli/utilities/theme-environment/storefront-renderer.ts:37 | correctness/robustness | mostly configured Shopify/store URLs or wrapper arguments | same-user/network wrapper | reachable | drop |
| codeql:js/shell-command-injection-from-environment:bin/pin-github-actions.js:32 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | no-slice | drop |
| codeql:js/superfluous-trailing-arguments:packages/cli-kit/src/public/node/plugins/tunnel.test.ts:13 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| codeql:js/trivial-conditional:packages/app/src/cli/models/app/loader.ts:634 | correctness/robustness | none confirmed | no demonstrated trust boundary | no-slice | drop |
| codeql:js/trivial-conditional:packages/app/src/cli/models/app/loader.ts:653 | correctness/robustness | none confirmed | no demonstrated trust boundary | no-slice | drop |
| codeql:js/trivial-conditional:packages/ui-extensions-dev-console/src/sections/Extensions/components/Status/Status.tsx:18 | correctness/robustness | none confirmed | no demonstrated trust boundary | no-slice | drop |
| codeql:js/user-controlled-bypass:bin/pin-github-actions.js:15 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | no-slice | drop |
| codeql:js/user-controlled-bypass:bin/update-bugsnag.js:18 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | no-slice | drop |
| codeql:js/user-controlled-bypass:bin/update-observe.js:484 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | reachable | drop |
| codeql:js/weak-cryptographic-algorithm:packages/cli-kit/src/public/node/crypto.ts:40 | correctness/robustness | none; helper uses legacy hash for non-secret identifiers/file hashes | none | no-slice | drop |
| codeql:js/xss:packages/ui-extensions-dev-console/src/sections/Extensions/Extensions.tsx:34 | correctness/robustness | not confirmed | no demonstrated exploit path | no-slice | drop |
| codeql:js/xss:packages/ui-extensions-dev-console/src/sections/Extensions/components/PreviewLink/PreviewLink.tsx:48 | correctness/robustness | not confirmed | no demonstrated exploit path | no-slice | drop |
| semgrep-baseline:javascript.lang.security.audit.unknown-value-with-script-tag.unknown-value-with-script-tag:packages/theme/src/cli/services/profile.ts:89 | correctness/robustness | none confirmed | no demonstrated trust boundary | no-slice | drop |
| semgrep-baseline:javascript.lang.security.detect-child-process.detect-child-process:bin/run-command.js:10 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | no-slice | drop |
| semgrep-baseline:javascript.node-stdlib.cryptography.crypto-weak-algorithm.crypto-weak-algorithm:bin/cache-inputs.js:33 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | no-slice | drop |
| semgrep-baseline:javascript.node-stdlib.cryptography.crypto-weak-algorithm.crypto-weak-algorithm:packages/cli-kit/src/public/node/crypto.ts:40 | correctness/robustness | none; helper uses legacy hash for non-secret identifiers/file hashes | none | no-slice | drop |
| semgrep-baseline:javascript.node-stdlib.cryptography.crypto-weak-algorithm.crypto-weak-algorithm:packages/cli-kit/src/public/node/crypto.ts:50 | correctness/robustness | none; helper uses legacy hash for non-secret identifiers/file hashes | none | no-slice | drop |
| semgrep-baseline:javascript.node-stdlib.cryptography.crypto-weak-algorithm.crypto-weak-algorithm:packages/cli-kit/src/public/node/crypto.ts:84 | correctness/robustness | none; helper uses legacy hash for non-secret identifiers/file hashes | none | no-slice | drop |
| semgrep-baseline:yaml.github-actions.security.run-shell-injection.run-shell-injection:.github/workflows/gardener-investigate-issue.yml:37 | environment/tooling/admin-only | GitHub event metadata, quoted/numeric or handled via artifact | CI workflow | no-slice | drop |
| semgrep-baseline:yaml.github-actions.security.run-shell-injection.run-shell-injection:.github/workflows/release.yml:192 | environment/tooling/admin-only | workflow_dispatch input by maintainer | admin CI | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.auth-header-forwarded-to-proxy:bin/update-observe.js:356 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.auth-header-forwarded-to-proxy:packages/cli-kit/src/public/node/api/admin.test.ts:165 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.auth-header-forwarded-to-proxy:packages/theme/src/cli/utilities/theme-environment/storefront-renderer.test.ts:24 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.auth-header-forwarded-to-proxy:packages/theme/src/cli/utilities/theme-environment/storefront-session.ts:151 | correctness/robustness | mostly configured Shopify/store URLs or wrapper arguments | same-user/network wrapper | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.auth-header-forwarded-to-proxy:packages/theme/src/cli/utilities/theme-environment/storefront-utils.test.ts:10 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.child-process-exec-template-string:bin/get-graphql-schemas.js:206 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.graphql-parse-without-mutation-guard:packages/app/src/cli/services/graphql/common.ts:125 | correctness/robustness | rule matched validator/helper parse sites | validation helper | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.graphql-parse-without-mutation-guard:packages/app/src/cli/services/graphql/common.ts:31 | correctness/robustness | rule matched validator/helper parse sites | validation helper | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.graphql-parse-without-mutation-guard:packages/cli-kit/src/public/node/dot-env.ts:33 | correctness/robustness | rule matched validator/helper parse sites | validation helper | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.graphql-parse-without-mutation-guard:packages/cli-kit/src/public/node/path.ts:105 | correctness/robustness | rule matched validator/helper parse sites | validation helper | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.graphql-parse-without-mutation-guard:packages/store/src/cli/services/store/execute/request.ts:92 | correctness/robustness | rule matched validator/helper parse sites | validation helper | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.lodash-tainted-key-footgun:packages/cli-kit/src/public/common/object.ts:104 | correctness/robustness | local app state/config keys; no confirmed cross-tenant impact | same-user state | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.lodash-tainted-key-footgun:packages/cli-kit/src/public/common/object.ts:115 | correctness/robustness | local app state/config keys; no confirmed cross-tenant impact | same-user state | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.lodash-tainted-key-footgun:packages/ui-extensions-server-kit/src/state/reducers/extensionServerReducer.ts:51 | correctness/robustness | local app state/config keys; no confirmed cross-tenant impact | same-user state | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.lodash-tainted-key-footgun:packages/ui-extensions-server-kit/src/state/reducers/extensionServerReducer.ts:63 | correctness/robustness | local app state/config keys; no confirmed cross-tenant impact | same-user state | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.lodash-tainted-key-footgun:packages/ui-extensions-server-kit/src/state/reducers/extensionServerReducer.ts:65 | correctness/robustness | local app state/config keys; no confirmed cross-tenant impact | same-user state | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.lodash-tainted-key-footgun:packages/ui-extensions-server-kit/src/state/reducers/extensionServerReducer.ts:77 | correctness/robustness | local app state/config keys; no confirmed cross-tenant impact | same-user state | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.lodash-tainted-key-footgun:packages/ui-extensions-server-kit/src/utilities/set.test.ts:10 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.missing-realpath-containment:packages/cli-kit/src/public/node/path.ts:157 | correctness/robustness | none confirmed | no demonstrated trust boundary | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:bin/github-utils.js:37 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:bin/github-utils.js:43 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:bin/update-observe.js:466 | environment/tooling/admin-only | repo maintainer/CI invocation | developer/release tooling | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/services/app-logs/utils.ts:223 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/services/app/env/show.ts:25 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/services/bulk-operations/bulk-operation-status.ts:201 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/services/dev/extension/websocket/handlers.ts:36 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/services/dev/fetch.ts:26 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/services/dev/graphiql/server.ts:270 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/services/dev/graphiql/server.ts:94 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/services/dev/processes/dev-session/dev-session-logger.ts:20 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/services/dev/processes/dev-session/dev-session-logger.ts:24 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/services/function/info.ts:90 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/services/generate/shop-import/declarative-definitions.ts:698 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/services/generate/shop-import/declarative-definitions.ts:700 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/services/init/validate.ts:20 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/services/init/validate.ts:59 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/services/local-storage.ts:35 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/services/local-storage.ts:44 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/services/local-storage.ts:53 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/utilities/extensions/fetch-product-variant.ts:19 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/utilities/mkcert.ts:176 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/utilities/mkcert.ts:185 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/utilities/mkcert.ts:187 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/utilities/mkcert.ts:44 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/app/src/cli/utilities/mkcert.ts:78 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/private/node/api/graphql.ts:15 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/private/node/otel-metrics.ts:165 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/private/node/otel-metrics.ts:176 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/private/node/session.ts:310 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/private/node/session.ts:314 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/private/node/session.ts:319 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/private/node/session/device-authorization.ts:135 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/private/node/session/device-authorization.ts:67 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/private/node/session/device-authorization.ts:85 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/private/node/session/device-authorization.ts:95 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/private/node/session/validate.ts:62 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/analytics.ts:62 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/analytics.ts:69 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/archiver.ts:200 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/archiver.ts:37 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/dot-env.ts:26 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:122 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:135 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:157 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:162 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:172 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:182 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:193 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:228 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:239 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:249 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:259 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:269 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:279 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:290 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:314 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:328 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:350 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:361 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:372 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:383 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/fs.ts:437 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/git.ts:162 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/git.ts:422 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/git.ts:54 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/git.ts:89 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/github.ts:150 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/github.ts:172 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/hidden-folder.ts:20 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/hidden-folder.ts:24 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/http.ts:241 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/liquid.ts:40 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/monorail.ts:224 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/node-package-manager.ts:155 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/node-package-manager.ts:756 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/node-package-manager.ts:770 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/session.ts:216 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/tcp.ts:36 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/ui.tsx:689 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/upgrade.ts:275 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/upgrade.ts:279 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/upgrade.ts:74 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/vscode.ts:12 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/cli-kit/src/public/node/vscode.ts:33 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/store/src/cli/services/store/auth/callback.ts:135 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/store/src/cli/services/store/auth/callback.ts:166 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/store/src/cli/services/store/auth/callback.ts:218 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/store/src/cli/services/store/auth/existing-scopes.ts:43 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/store/src/cli/services/store/auth/existing-scopes.ts:50 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/store/src/cli/services/store/auth/index.ts:114 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/store/src/cli/services/store/auth/index.ts:47 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/store/src/cli/services/store/auth/pkce.ts:69 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/store/src/cli/services/store/auth/result.ts:46 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/store/src/cli/services/store/auth/result.ts:52 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/store/src/cli/services/store/auth/scopes.ts:46 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/store/src/cli/services/store/auth/session-lifecycle.ts:102 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/store/src/cli/services/store/auth/session-lifecycle.ts:51 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/store/src/cli/services/store/auth/session-lifecycle.ts:67 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/store/src/cli/services/store/auth/token-client.ts:113 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/store/src/cli/services/store/auth/token-client.ts:149 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/store/src/cli/services/store/auth/token-client.ts:53 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/store/src/cli/services/store/auth/token-client.ts:68 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/store/src/cli/services/store/auth/token-client.ts:84 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/store/src/cli/services/store/auth/token-client.ts:97 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/theme/src/cli/services/local-storage.ts:105 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/theme/src/cli/services/local-storage.ts:114 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/theme/src/cli/services/local-storage.ts:122 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/theme/src/cli/utilities/log-request-line.ts:32 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/theme/src/cli/utilities/repl/evaluator.test.ts:115 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/theme/src/cli/utilities/repl/evaluator.test.ts:133 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/theme/src/cli/utilities/repl/evaluator.ts:56 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/theme/src/cli/utilities/repl/evaluator.ts:83 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/theme/src/cli/utilities/repl/evaluator.ts:89 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/theme/src/cli/utilities/repl/presenter.test.ts:31 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/theme/src/cli/utilities/repl/presenter.test.ts:43 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/theme/src/cli/utilities/repl/presenter.test.ts:56 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/theme/src/cli/utilities/repl/presenter.ts:36 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/theme/src/cli/utilities/theme-environment/theme-polling.ts:150 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/theme/src/cli/utilities/theme-environment/theme-polling.ts:174 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/theme/src/cli/utilities/theme-fs.ts:567 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | reachable | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/theme/src/cli/utilities/theme-store.ts:14 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.token-to-output-log-telemetry:packages/theme/src/cli/utilities/theme-store.ts:16 | correctness/robustness | rule matched token-like variable/function names, not confirmed secret value | logging/telemetry pattern only | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.wildcard-cors-local-route:packages/app/src/cli/services/dev/extension/server/middlewares.ts:15 | correctness/robustness | none confirmed | no demonstrated trust boundary | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.workflow-expression-injection-run:.github/workflows/gardener-investigate-issue.yml:37 | environment/tooling/admin-only | GitHub event metadata, quoted/numeric or handled via artifact | CI workflow | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.workflow-expression-injection-run:.github/workflows/gardener-notify-slack.yml:14 | environment/tooling/admin-only | GitHub event metadata, quoted/numeric or handled via artifact | CI workflow | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.workflow-expression-injection-run:.github/workflows/release.yml:60 | environment/tooling/admin-only | workflow_dispatch input by maintainer | admin CI | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.workflow-expression-injection-run:.github/workflows/shopify-dev-preview-automation.yml:50 | environment/tooling/admin-only | GitHub event metadata, quoted/numeric or handled via artifact | CI workflow | no-slice | drop |
| semgrep-custom:piolium.semgrep-rules.shopify-cli.workflow-expression-injection-run:.github/workflows/tests-pr.yml:37 | environment/tooling/admin-only | test/dev fixture only | test-only | no-slice | drop |
