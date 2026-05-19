import chalk from "chalk";
import { uninstallHarness } from "../engine/harness.js";

export async function uninstallCommand(
  platform: string,
  opts: { json?: boolean } = {},
): Promise<void> {
  if (platform !== "claude" && platform !== "codex") {
    const msg = `platform must be "claude" or "codex"`;
    if (opts.json) process.stdout.write(JSON.stringify({ ok: false, error: msg }) + "\n");
    else console.error(chalk.red(`error: ${msg}`));
    process.exit(2);
  }
  try {
    const { removed } = await uninstallHarness(platform);
    if (opts.json) {
      process.stdout.write(JSON.stringify({ ok: true, platform, removed }) + "\n");
    } else if (removed.length === 0) {
      console.log(`[archon] nothing to remove for ${platform}`);
    } else {
      console.log(chalk.green(`[archon] removed ${removed.length} item(s):`));
      for (const r of removed) console.log(`  - ${r}`);
    }
    process.exit(0);
  } catch (err) {
    if (opts.json) {
      process.stdout.write(JSON.stringify({ ok: false, error: (err as Error).message }) + "\n");
    } else {
      console.error(chalk.red(`[archon] uninstall failed: ${(err as Error).message}`));
    }
    process.exit(1);
  }
}
