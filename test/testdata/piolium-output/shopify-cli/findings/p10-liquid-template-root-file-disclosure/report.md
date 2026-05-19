# [p10] Custom app templates can include files from the developer's working directory

## Summary

`shopify app init --template` accepts custom GitHub template repositories and renders attacker-controlled `.liquid` files with LiquidJS' default filesystem lookup settings. Because the Liquid engine is not rooted to the downloaded template directory, a malicious template can use tags such as `{% include ".env" %}` to read files from the developer process' current working directory and write their contents into the generated app scaffold.

## Details

The attack surface is the custom app template path. The CLI advertises that the `--template` flag may point to any GitHub repository in [`packages/app/src/cli/commands/app/init.ts`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/commands/app/init.ts#L41-L45), and validation in [`packages/app/src/cli/services/init/validate.ts`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/init/validate.ts#L11-L16) only rejects non-GitHub origins:

```ts
const url = safeParseURL(template)
if (url && url.origin !== 'https://github.com')
  throw new AbortError(
    'Only GitHub repository references are supported, ' +
      'e.g., https://github.com/Shopify/<repository>/[subpath]#[branch]',
  )
```

After downloading the repository, the init service renders the selected template directory into a temporary scaffold via `recursiveLiquidTemplateCopy()` in [`packages/app/src/cli/services/init/init.ts`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/init/init.ts#L72-L101). That helper then treats `.liquid` files from the downloaded template as templates and writes the rendered output into the generated project.

The decisive renderer path is in [`packages/cli-kit/src/public/node/liquid.ts`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/cli-kit/src/public/node/liquid.ts#L24-L72):

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
  const isExecutable = await fileHasExecutablePermissions(templateItemPath)
  const outputPathWithoutLiquid = outputPath.replace('.liquid', '')
  await copyFile(templateItemPath, outputPathWithoutLiquid)
  await writeFile(outputPathWithoutLiquid, contentOutput)
```

`new Liquid()` is created without `root`, `partials`, `layouts`, `relativeReference`, or an equivalent in-memory loader bound to the downloaded template tree. Per the audit evidence, LiquidJS' default template lookup can resolve include/render/layout filesystem references from the process working directory. Therefore, when a developer runs the CLI from a directory containing `.env`, a template-controlled file such as `leaked-env.txt.liquid` can include `.env`; the helper writes the rendered contents to `leaked-env.txt` in the scaffold.

The init flow then continues operating on the rendered scaffold, including dependency installation from `templateScaffoldDir` in [`packages/app/src/cli/services/init/init.ts`](https://github.com/shopify/cli/blob/c3e54bea421d23743b5f2b83b34347f5bb729cc4/packages/app/src/cli/services/init/init.ts#L174-L179). The file disclosure is already complete when the scaffold file is written; later install, commit, or sharing steps can make the leaked content leave the developer machine.

## Root Cause

The renderer crosses the trust boundary between an untrusted downloaded template repository and the developer's local filesystem. Template content is attacker controlled, but the Liquid engine is constructed with default filesystem resolution instead of being constrained to the downloaded template directory or to a non-filesystem template loader. As a result, filesystem tags in the untrusted template are evaluated with access to files outside the template tree.

## Proof of Concept (PoC)

PoC status: `executed`.

The provided PoC script at `piolium/findings/p10-liquid-template-root-file-disclosure/poc.sh` creates:

1. a victim current working directory containing `.env` with a unique `SHOPIFY_API_SECRET` marker;
2. a malicious downloaded-template directory containing `leaked-env.txt.liquid` with `{% include ".env" %}`;
3. a small runner that invokes the repository's actual `recursiveLiquidTemplateCopy()` while the process CWD is the victim directory.

Run from the repository root:

```bash
./piolium/findings/p10-liquid-template-root-file-disclosure/poc.sh
```

The execution log confirms the real renderer copied the victim `.env` marker into the generated scaffold:

```text
[*] Victim CWD contains .env marker: PIOLIUM_LIQUID_SECRET_1777623336_55039
[*] Malicious template payload: {% include ".env" %}
[*] Invoking actual recursiveLiquidTemplateCopy() from cli-kit with victim CWD...
[+] Generated scaffold file contains victim .env contents: /Users/bytedance/Desktop/oss-to-run/shopify-cli/piolium/findings/p10-liquid-template-root-file-disclosure/evidence/work/generated-app/leaked-env.txt
{"status":"confirmed","evidence":"victim .env marker copied into generated scaffold","notes":"actual recursiveLiquidTemplateCopy() rendered attacker include from process CWD"}
```

`evidence/impact.log` contains the disclosed secret material in the generated file:

```text
Generated scaffold file: /Users/bytedance/Desktop/oss-to-run/shopify-cli/piolium/findings/p10-liquid-template-root-file-disclosure/evidence/work/generated-app/leaked-env.txt
Leaked marker observed in generated scaffold: PIOLIUM_LIQUID_SECRET_1777623336_55039
--- generated file ---
SHOPIFY_API_SECRET=PIOLIUM_LIQUID_SECRET_1777623336_55039
```

## Impact

A malicious or compromised GitHub app template can disclose files that the developer process can read from the directory where `shopify app init` is launched, such as `.env` secrets, local app configuration, or other predictable project files. The demonstrated effect is local file disclosure into the newly generated scaffold. From there, the exposed data may be exfiltrated by template-controlled dependency installation behavior, accidentally committed, or shared with the generated project.

The attacker-controlled input is the template repository content; the attacker does not need Shopify credentials. The practical precondition is that a victim developer chooses or is directed to initialize an app from the malicious GitHub template while running the CLI from a directory containing sensitive files.

## Remediation

Render untrusted templates with a Liquid engine whose filesystem lookup is restricted to the downloaded template directory, or disable filesystem-backed include/render/layout tags for custom templates entirely. For example, construct a renderer for each template root with `root`, `partials`, and `layouts` set to that root and reject any resolved path that escapes it. Add a regression test where the process CWD contains `.env` and a template containing `{% include ".env" %}` fails instead of writing the secret to the scaffold. Also avoid running follow-on dependency installation steps until the generated scaffold has been produced without reading outside the template root.

## Confirmation (V4)
Confirm-Status: blocked
Confirm-Timestamp: 2026-05-01T09:00:36Z
Confirm-Evidence: piolium/findings/p10-liquid-template-root-file-disclosure/evidence/confirmed-20260501T090022Z.log
Confirm-Variant-Count: 0
Confirm-FpCheck: not-run
Confirm-Notes: Local-only exploit path is routed to V5 per V4 instructions; no network PoC executed
Confirm-Queued-V5: yes

## Confirmation (V5 generated test)
Confirm-Status: confirmed-test
Confirm-Method: generated-test
Confirm-Test: piolium/findings/p10-liquid-template-root-file-disclosure/confirm-test.test.js
Confirm-Test-Output: piolium/findings/p10-liquid-template-root-file-disclosure/evidence/confirm-test-output.log
Confirm-Evidence: piolium/findings/p10-liquid-template-root-file-disclosure/evidence/confirm-test-output.log; piolium/findings/p10-liquid-template-root-file-disclosure/evidence/confirm-test-observation.json; piolium/findings/p10-liquid-template-root-file-disclosure/evidence/confirm-test-command.sh
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-05-01T09:10:04Z
Confirm-Notes: Vitest executed recursiveLiquidTemplateCopy from a victim CWD; an attacker template containing {% include ".env" %} wrote the victim .env marker into the generated scaffold.
