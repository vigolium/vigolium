import { existsSync, readdirSync } from "fs";
import { readFile } from "fs/promises";
import { join } from "path";
import { z } from "zod";
import { parseFrontmatter, resolveRoots } from "../content-loader.js";
import { parseToolsField } from "./prompts.js";

/**
 * Bridge task presets — the semantic jobs the `bridge` command exposes
 * (triage / exploit / plan). Each is a markdown file under
 * `src/content/bridge-tasks/<name>.md` (bundled into the compiled binary) with
 * frontmatter declaring the skills / tools / model / output shape and a body
 * that is the task's system prompt.
 *
 * The task layer is where prompt engineering lives, so the calling Go binary
 * passes structured inputs (a finding, a target) and never assembles prompts.
 * Per-user overrides at `$VIGOLIUM_AUDIT_CONFIG_DIR/bridge-tasks/<name>.md`
 * take precedence, mirroring the agent/skill override mechanism.
 */
export interface BridgeTask {
  name: string;
  description: string;
  /** Skills to load in addition to the always-on `vigolium-scanner`. */
  skills: string[];
  /** Optional allow-list of tools; when empty the runtime default applies. */
  tools: string[];
  /** Optional default model when neither the request nor env overrides it. */
  model?: string;
  /** Whether the task should end with a machine-parseable JSON block. */
  output: "json" | "text";
  /** Human-readable JSON schema hint appended to the system prompt. */
  outputSchema?: string;
  /**
   * Least-privilege profile the task runs under (read-only / workspace-write /
   * full-access). Omitted → full-access for backward compatibility.
   */
  permission?: "read-only" | "workspace-write" | "full-access";
  /** Whether network egress is permitted; omitted → the profile's default. */
  network?: boolean;
  /** System prompt body (markdown after the frontmatter). */
  systemPrompt: string;
}

const FrontmatterSchema = z.object({
  name: z.string().optional(),
  description: z.string().optional(),
  skills: z.array(z.string()).optional(),
  tools: z.union([z.array(z.string()), z.string()]).optional(),
  model: z.string().optional(),
  output: z.enum(["json", "text"]).optional(),
  output_schema: z.string().optional(),
  permission: z.enum(["read-only", "workspace-write", "full-access"]).optional(),
  network: z.boolean().optional(),
});

function bridgeTasksDirs(): { override: string; content: string } {
  const roots = resolveRoots();
  return {
    override: join(roots.overrideRoot, "bridge-tasks"),
    content: join(roots.contentRoot, "bridge-tasks"),
  };
}

function resolveTaskPath(name: string): string | null {
  const dirs = bridgeTasksDirs();
  const override = join(dirs.override, `${name}.md`);
  if (existsSync(override)) return override;
  const content = join(dirs.content, `${name}.md`);
  if (existsSync(content)) return content;
  return null;
}

/** Names of the built-in (and any overridden) task presets, sorted. */
export function listBridgeTasks(): string[] {
  const dirs = bridgeTasksDirs();
  const names = new Set<string>();
  for (const dir of [dirs.content, dirs.override]) {
    if (!existsSync(dir)) continue;
    for (const f of readdirSync(dir)) {
      if (f.endsWith(".md")) names.add(f.replace(/\.md$/, ""));
    }
  }
  return [...names].sort();
}

function parseTools(value: string[] | string | undefined): string[] {
  if (Array.isArray(value)) return value.filter((v) => typeof v === "string");
  return parseToolsField(value);
}

/** Load a task preset by name. Throws with the available names on a miss. */
export async function loadBridgeTask(name: string): Promise<BridgeTask> {
  const path = resolveTaskPath(name);
  if (!path) {
    const available = listBridgeTasks();
    throw new Error(
      `unknown bridge task: ${name}` +
        (available.length ? ` (available: ${available.join(", ")})` : ""),
    );
  }
  const src = await readFile(path, "utf8");
  const { data, body } = parseFrontmatter(src);
  const fm = FrontmatterSchema.parse(data);
  return {
    name: fm.name ?? name,
    description: fm.description ?? "",
    skills: fm.skills ?? [],
    tools: parseTools(fm.tools),
    ...(fm.model !== undefined ? { model: fm.model } : {}),
    output: fm.output ?? "text",
    ...(fm.output_schema !== undefined ? { outputSchema: fm.output_schema } : {}),
    ...(fm.permission !== undefined ? { permission: fm.permission } : {}),
    ...(fm.network !== undefined ? { network: fm.network } : {}),
    systemPrompt: body.trim(),
  };
}
