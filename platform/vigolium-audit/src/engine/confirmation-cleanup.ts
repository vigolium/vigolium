import { spawnSync } from "child_process";
import { appendFile, readFile, rm } from "fs/promises";
import { join } from "path";

export interface ConfirmationCleanupResult {
  session: string | null;
  containersRemoved: number;
  processKilled: boolean;
  warnings: string[];
}

/**
 * Tear down confirmation resources using structured, engine-owned metadata.
 * No value read from an agent artifact is ever evaluated by a shell.
 */
export async function cleanupConfirmationResources(resultsDir: string): Promise<ConfirmationCleanupResult> {
  const workspace = join(resultsDir, "confirm-workspace");
  const lockPath = join(workspace, ".lock");
  const connectionPath = join(workspace, "env-connection.json");
  const pidPath = join(workspace, "app.pid");
  const logPath = join(workspace, "cleanup.log");
  const warnings: string[] = [];

  const session =
    extractSession(await readJson(lockPath)) ??
    extractSession(await readJson(connectionPath));

  let containersRemoved = 0;
  if (session !== null) {
    const listed = spawnSync(
      "docker",
      ["ps", "-aq", "--filter", `label=vigolium-audit.session=${session}`],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 5_000 },
    );
    if (listed.status === 0) {
      const ids = listed.stdout
        .split(/\s+/)
        .filter((value) => /^[a-f0-9]{12,64}$/i.test(value));
      if (ids.length > 0) {
        const removed = spawnSync("docker", ["rm", "-f", ...ids], {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
          timeout: 15_000,
        });
        if (removed.status === 0) containersRemoved = ids.length;
        else warnings.push(`docker cleanup failed: ${oneLine(removed.stderr)}`);
      }
    } else if (listed.error && (listed.error as NodeJS.ErrnoException).code !== "ENOENT") {
      warnings.push(`docker resource lookup failed: ${listed.error.message}`);
    }
  } else {
    warnings.push("no valid confirmation session UUID; skipped container cleanup");
  }

  let processKilled = false;
  const pid = await readPid(pidPath);
  if (pid !== null && session !== null) {
    if (processBelongsToSession(pid, session)) {
      try {
        process.kill(pid, "SIGTERM");
        processKilled = true;
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code !== "ESRCH") warnings.push(`process cleanup failed for PID ${pid}: ${(err as Error).message}`);
      }
    } else {
      warnings.push(`refused to kill PID ${pid}: process is not stamped with confirmation session ${session}`);
    }
  }

  await rm(pidPath, { force: true }).catch(() => {});
  await rm(lockPath, { force: true }).catch(() => {});

  const summary = [
    `[engine-cleanup] session=${session ?? "unknown"}`,
    `containers_removed=${containersRemoved}`,
    `process_killed=${processKilled}`,
    ...warnings.map((warning) => `warning=${warning}`),
  ].join(" ");
  await appendFile(logPath, `${summary}\n`, "utf8").catch(() => {});

  return { session, containersRemoved, processKilled, warnings };
}

async function readJson(path: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch {
    return null;
  }
}

function extractSession(value: unknown): string | null {
  if (!value || typeof value !== "object") return null;
  const session = (value as { session?: unknown }).session;
  if (typeof session !== "string") return null;
  return /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/.test(session) ? session : null;
}

async function readPid(path: string): Promise<number | null> {
  try {
    const raw = (await readFile(path, "utf8")).trim();
    if (!/^\d+$/.test(raw)) return null;
    const pid = Number(raw);
    if (!Number.isSafeInteger(pid) || pid <= 1 || pid === process.pid) return null;
    return pid;
  } catch {
    return null;
  }
}

function processBelongsToSession(pid: number, session: string): boolean {
  const inspected = spawnSync("ps", ["eww", "-p", String(pid), "-o", "command="], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 2_000,
  });
  if (inspected.status !== 0) return false;
  return inspected.stdout.includes(`VIGOLIUM_AUDIT_SESSION_UUID=${session}`);
}

function oneLine(value: string): string {
  return value.trim().replace(/\s+/g, " ").slice(0, 300);
}
