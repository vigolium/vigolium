import { createInterface } from "readline";
import { resolve } from "path";
import {
  applyBridgeAuth,
  buildBridgeAdapter,
  describeInvocation,
  resolveBridgeInvocation,
  runBridge,
  type BridgeOptions,
} from "../engine/bridge.js";
import { listBridgeTasks } from "../engine/bridge-tasks.js";
import type { AgentPlatform } from "../engine/types.js";
import { emitJsonEvent, serializeAdapterEvent } from "./run-render.js";
import { resolveModel } from "./run-models.js";
import type { BridgeCliOptions } from "./bridge.js";

/**
 * `bridge serve` — the long-lived daemon. Reads newline-delimited
 * JSON requests on stdin and writes newline-delimited JSON responses on stdout,
 * keeping the Node process (and the loaded SDK / content) warm across calls so
 * the caller avoids cold-start on every triage/exploit/plan.
 *
 * Wire protocol (one JSON object per line):
 *
 *   → { "id": "r1", "method": "run", "params": { "action": "triage", ... } }
 *   ← { "id": "r1", "kind": "accepted", ... }
 *   ← { "id": "r1", "kind": "event", "event": { ... } }        (many)
 *   ← { "id": "r1", "kind": "result", "result": { ... } }
 *
 *   → { "id": "r1", "method": "cancel" }        // aborts run r1
 *   → { "method": "ping" }   ← { "kind": "pong" }
 *   → { "method": "shutdown" }   ← { "kind": "bye" }
 *
 * Runs are concurrent and demultiplexed by `id`; the caller may have several in
 * flight at once. Auth is established once at startup (from flags/env), not per
 * request.
 */

interface RunParams {
  action?: string;
  agent?: string;
  cwd?: string;
  prompt?: string;
  input?: string;
  systemPrompt?: string;
  skills?: string[];
  tools?: string[];
  denyTools?: string[];
  disallowedTools?: string[];
  model?: string;
  maxTurns?: number;
  resume?: string;
  output?: string;
  bypassPermissions?: boolean;
}

interface Request {
  id?: string;
  method?: string;
  params?: RunParams & { id?: string };
}

function toBridgeOptions(params: RunParams, defaults: { platform: AgentPlatform; cwd: string }): BridgeOptions {
  const platform: AgentPlatform = params.agent === "codex" ? "codex" : params.agent === "claude" ? "claude" : defaults.platform;
  const model = resolveModel(params.model); // request model → VIGOLIUM_AUDIT_MODEL → default
  return {
    action: params.action ?? "run",
    platform,
    cwd: resolve(params.cwd ?? defaults.cwd),
    skills: params.skills ?? [],
    disallowedTools: params.denyTools ?? params.disallowedTools ?? [],
    bypassPermissions: params.bypassPermissions ?? true,
    ...(params.prompt !== undefined ? { prompt: params.prompt } : {}),
    ...(params.input !== undefined ? { input: params.input } : {}),
    ...(params.systemPrompt !== undefined ? { systemPrompt: params.systemPrompt } : {}),
    ...(params.tools !== undefined ? { tools: params.tools } : {}),
    ...(model !== undefined ? { model } : {}),
    ...(params.maxTurns !== undefined ? { maxTurns: params.maxTurns } : {}),
    ...(params.resume !== undefined ? { resume: params.resume } : {}),
    ...(params.output === "json" || params.output === "text" ? { output: params.output } : {}),
  };
}

export async function serveBridge(opts: BridgeCliOptions): Promise<void> {
  const defaults = {
    platform: (opts.agent ?? "claude") as AgentPlatform,
    cwd: resolve(opts.cwd ?? opts.target ?? "."),
  };

  // One global auth context for the daemon's lifetime.
  applyBridgeAuth({
    platform: defaults.platform,
    ...(opts.apiKey !== undefined ? { apiKey: opts.apiKey } : {}),
    ...(opts.oauthToken !== undefined ? { oauthToken: opts.oauthToken } : {}),
    ...(opts.oauthCredFile !== undefined ? { oauthCredFile: opts.oauthCredFile } : {}),
  });

  const active = new Map<string, AbortController>();
  let draining = false;

  const maybeExit = (): void => {
    if (draining && active.size === 0) {
      emitJsonEvent({ kind: "bye" });
      process.exit(0);
    }
  };

  const handleRun = (id: string, params: RunParams): void => {
    if (active.has(id)) {
      emitJsonEvent({ id, kind: "error", error: `duplicate run id: ${id}` });
      return;
    }
    const abort = new AbortController();
    active.set(id, abort);
    void (async () => {
      try {
        const bo = toBridgeOptions(params, defaults);
        const { adapter, choice } = buildBridgeAdapter(bo.platform, bo.model);
        const inv = await resolveBridgeInvocation(bo);
        emitJsonEvent({ id, kind: "accepted", ...describeInvocation(inv, choice) });
        const result = await runBridge(
          inv,
          adapter,
          { onEvent: (e) => emitJsonEvent({ id, kind: "event", event: serializeAdapterEvent(e) }) },
          { abortSignal: abort.signal },
        );
        emitJsonEvent({ id, kind: "result", result: result as unknown as Record<string, unknown> });
      } catch (err) {
        emitJsonEvent({ id, kind: "error", error: (err as Error).message });
      } finally {
        active.delete(id);
        maybeExit();
      }
    })();
  };

  const dispatch = (line: string): void => {
    const trimmed = line.trim();
    if (trimmed.length === 0) return;
    let req: Request;
    try {
      req = JSON.parse(trimmed) as Request;
    } catch {
      emitJsonEvent({ kind: "error", error: "malformed request (invalid JSON)" });
      return;
    }
    switch (req.method) {
      case "run": {
        if (!req.id) {
          emitJsonEvent({ kind: "error", error: "run requires an id" });
          return;
        }
        if (draining) {
          emitJsonEvent({ id: req.id, kind: "error", error: "daemon is shutting down" });
          return;
        }
        handleRun(req.id, req.params ?? {});
        break;
      }
      case "cancel": {
        const target = req.params?.id ?? req.id;
        if (target && active.has(target)) {
          active.get(target)!.abort(new Error("cancelled"));
          emitJsonEvent({ id: target, kind: "cancelled" });
        } else {
          emitJsonEvent({ ...(target ? { id: target } : {}), kind: "error", error: "no such active run" });
        }
        break;
      }
      case "ping":
        emitJsonEvent({ kind: "pong" });
        break;
      case "shutdown":
        draining = true;
        for (const ctrl of active.values()) ctrl.abort(new Error("shutdown"));
        maybeExit();
        break;
      default:
        emitJsonEvent({ ...(req.id ? { id: req.id } : {}), kind: "error", error: `unknown method: ${req.method ?? "(none)"}` });
    }
  };

  emitJsonEvent({ kind: "ready-daemon", tasks: listBridgeTasks(), defaultPlatform: defaults.platform, cwd: defaults.cwd });

  const rl = createInterface({ input: process.stdin });
  rl.on("line", dispatch);
  rl.on("close", () => {
    // stdin closed: finish in-flight runs, then exit.
    draining = true;
    if (active.size === 0) {
      emitJsonEvent({ kind: "bye" });
      process.exit(0);
    }
  });

  // Keep the process alive until an explicit exit.
  await new Promise<void>(() => {});
}
