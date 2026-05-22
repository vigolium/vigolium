# [p12] Extension template Liquid include can disclose local root files

## Summary

`shopify app generate extension` accepts a custom extension-template repository through the hidden `--clone-url` flag / `SHOPIFY_FLAG_CLONE_URL` environment variable, then renders downloaded `.liquid` files with the shared Liquid template helper. Because that helper creates a default `new Liquid()` engine instead of pinning include/layout roots to the downloaded template directory, a malicious template can include files from the developer's current working directory, such as `.env`, into generated extension files. PoC-Status: `executed`.

## Details

The command exposes attacker-controlled template input through [`--clone-url`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/commands/app/generate/extension.ts#L42-L47) and passes it into the extension generation service as `cloneUrl` ([source](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/commands/app/generate/extension.ts#L87-L93)):

```ts
'clone-url': Flags.string({
  hidden: true,
  char: 'u',
  description:
    'The Git URL to clone the function extensions templates from. Defaults to: https://github.com/Shopify/function-examples',
  env: 'SHOPIFY_FLAG_CLONE_URL',
})

await generate({
  directory: flags.path,
  cloneUrl: flags['clone-url'],
  template: flags.template,
  flavor: flags.flavor,
  // ...
})
```

The generation service prefers the supplied clone URL over the built-in template URL, downloads that repository, and sends the resulting template directory through `recursiveLiquidTemplateCopy()` for theme, function, and UI extension initialization ([source](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/generate/extension.ts#L91-L105), [theme path](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/generate/extension.ts#L141-L148), [function path](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/generate/extension.ts#L167-L175), [UI path](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/generate/extension.ts#L237-L244)):

```ts
const directory = await ensureExtensionDirectoryExists({app: options.app, name: extensionName})
const url = options.cloneUrl ?? options.extensionTemplate.url

const initOptions: ExtensionInitOptions = {
  directory,
  url,
  onGetTemplateRepository:
    options.onGetTemplateRepository ??
    (async (url, destination) => {
      await downloadGitRepository({repoUrl: url, destination, shallow: true})
    }),
}

// e.g. theme extension generation
await recursiveLiquidTemplateCopy(templateDirectory, directory, {name, type, uid: nonRandomUUID(slugify(name))})
```

The decisive issue is in the shared Liquid helper. [`renderLiquidTemplate()`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/cli-kit/src/public/node/liquid.ts#L24-L26) constructs the engine without `root`, `partials`, or `layouts` restrictions, and [`recursiveLiquidTemplateCopy()`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/cli-kit/src/public/node/liquid.ts#L65-L72) renders attacker-controlled `.liquid` file contents through that engine:

```ts
export function renderLiquidTemplate(templateContent: string, data: object): Promise<string> {
  const engine = new Liquid()
  return engine.render(engine.parse(templateContent), data)
}

// ...
} else if (templateItemPath.endsWith('.liquid') && !bypass) {
  await mkdir(dirname(outputPath))
  const content = await readFile(templateItemPath)
  const contentOutput = await renderLiquidTemplate(content, data)
  const outputPathWithoutLiquid = outputPath.replace('.liquid', '')
  await writeFile(outputPathWithoutLiquid, contentOutput)
}
```

A downloaded template file containing `{% include ".env" %}` is therefore interpreted by Liquid during scaffolding. With the process current working directory set to the victim app directory, Liquid resolves and embeds the victim app's `.env` into the generated extension file instead of limiting includes to the downloaded template tree.

## Root Cause

Untrusted extension template contents are rendered with a Liquid engine that has filesystem include capabilities but no root confinement to the template directory. The code treats downloaded `.liquid` files as safe scaffolding templates, yet it does not disable or sandbox Liquid tags such as `include`/`render`/`layout`, nor does it reject paths that resolve outside the downloaded template repository.

## Proof of Concept (PoC)

The checked-in PoC at `piolium/findings/p12-extension-generate-liquid-root-file-disclosure/poc.js` executed successfully. It creates a temporary victim app containing `.env`, creates a malicious local Git template with `leak.txt.liquid` set to `{% include ".env" %}`, invokes `AppGenerateExtension.run()` with `--template theme --name leaky-ext --clone-url file://...`, and verifies the generated `extensions/leaky-ext/leak.txt` contains the `.env` marker.

Run from the finding directory:

```sh
node ./poc.js
```

`evidence/exploit.log` shows the exploit completed and the marker was observed:

```text
[+] Generated extension file: /var/folders/2k/z4j3lfxj5fv7r20hswc8sj8r0000gn/T/shopify-cli-poc-eJl95e/victim-app/extensions/leaky-ext/leak.txt
[+] Leaked marker observed: PIOLIUM_SECRET_1777623664531
{"status":"confirmed","evidence":"generated extension leak.txt contains PIOLIUM_SECRET marker from victim .env","notes":"impact saved to /Users/j3ssie/Desktop/oss-to-run/shopify-cli/piolium/findings/p12-extension-generate-liquid-root-file-disclosure/evidence/impact.log"}
```

`evidence/impact.log` contains the generated file contents proving local file disclosure into the scaffold:

```text
generated_file_contents:
PIOLIUM_SECRET=PIOLIUM_SECRET_1777623664531
```

## Impact

An attacker who convinces a developer to generate an extension from a malicious `--clone-url` can cause local files readable by the CLI process and resolvable from the developer's current working directory to be copied into generated extension files. The demonstrated effect is disclosure of a victim app `.env` secret into `extensions/leaky-ext/leak.txt`. Direct attacker access still depends on follow-on exposure, such as the developer committing, sharing, deploying, logging, or otherwise processing the generated scaffold, but the CLI creates the secret-bearing file without warning. The affected surface includes theme, function, and UI extension generation paths because all of them call the same Liquid copy helper.

## Remediation

Render downloaded templates with a sandboxed Liquid configuration. Pass the template root into the renderer and set Liquid `root`/`partials`/`layouts` to that directory, reject absolute paths and `..` traversal after canonicalization, or disable filesystem-backed `include`/`render`/`layout` tags for untrusted templates entirely. Add regression coverage that a malicious extension template containing `{% include ".env" %}` cannot read a `.env` from the app working directory and that all extension initialization paths use the confined renderer.

## Confirmation (V4)
Confirm-Status: blocked
Confirm-Timestamp: 2026-05-01T09:00:36Z
Confirm-Evidence: piolium/findings/p12-extension-generate-liquid-root-file-disclosure/evidence/confirmed-20260501T090022Z.log
Confirm-Variant-Count: 0
Confirm-FpCheck: not-run
Confirm-Notes: Local-only exploit path is routed to V5 per V4 instructions; no network PoC executed
Confirm-Queued-V5: yes

## Confirmation (V5 generated test)
Confirm-Status: confirmed-test
Confirm-Method: generated-test
Confirm-Test: piolium/findings/p12-extension-generate-liquid-root-file-disclosure/confirm-test.test.js
Confirm-Test-Output: piolium/findings/p12-extension-generate-liquid-root-file-disclosure/evidence/confirm-test-output.log
Confirm-Evidence: piolium/findings/p12-extension-generate-liquid-root-file-disclosure/evidence/confirm-test-output.log; piolium/findings/p12-extension-generate-liquid-root-file-disclosure/evidence/confirm-test-observation.json; piolium/findings/p12-extension-generate-liquid-root-file-disclosure/evidence/confirm-test-command.sh
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-05-01T09:10:04Z
Confirm-Notes: Vitest executed the shared Liquid template copy used by extension generation from a victim app CWD; {% include ".env" %} copied the victim marker into the generated extension file.
