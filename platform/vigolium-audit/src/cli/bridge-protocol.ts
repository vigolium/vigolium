import { z } from "zod";

/**
 * The `bridge serve` NDJSON wire protocol: a versioned, runtime-validated
 * request contract. Every line the daemon reads is parsed against this schema
 * before it reaches execution, so a malformed request (wrong field type, `null`,
 * an array, an unknown method) becomes a structured `invalid_request` error
 * instead of crashing dispatch or being silently coerced.
 */

/** Bumped when the wire contract changes incompatibly. Advertised in the handshake. */
export const PROTOCOL_VERSION = 1;

/** Stable terminal error codes a client can branch on without parsing prose. */
export type BridgeErrorCode =
  | "invalid_request"
  | "queue_full"
  | "deadline_exceeded"
  | "cancelled"
  | "internal_error";

/** Parameters for a `run` request. Mirrors the one-shot CLI's inputs. */
export const RunParamsSchema = z
  .object({
    action: z.string().optional(),
    agent: z.enum(["claude", "codex"]).optional(),
    cwd: z.string().optional(),
    prompt: z.string().optional(),
    input: z.string().optional(),
    systemPrompt: z.string().optional(),
    skills: z.array(z.string()).optional(),
    tools: z.array(z.string()).optional(),
    denyTools: z.array(z.string()).optional(),
    disallowedTools: z.array(z.string()).optional(),
    model: z.string().optional(),
    maxTurns: z.number().int().positive().optional(),
    resume: z.string().optional(),
    output: z.enum(["json", "text"]).optional(),
    permission: z.enum(["read-only", "workspace-write", "full-access"]).optional(),
    network: z.boolean().optional(),
    bypassPermissions: z.boolean().optional(),
    /** Per-run wall-clock deadline (ms), including queue wait and retries. */
    timeoutMs: z.number().int().positive().optional(),
  })
  // Lenient on unknown fields (forward-compat with newer clients); strict on the
  // *types* of known fields, which is what actually crashes dispatch.
  .passthrough();

export type RunParams = z.infer<typeof RunParamsSchema>;

const RunRequestSchema = z.object({
  method: z.literal("run"),
  id: z.string().min(1),
  params: RunParamsSchema.optional(),
});
const CancelRequestSchema = z.object({
  method: z.literal("cancel"),
  id: z.string().optional(),
  params: z.object({ id: z.string().optional() }).passthrough().optional(),
});
const PingRequestSchema = z.object({ method: z.literal("ping"), id: z.string().optional() });
const ShutdownRequestSchema = z.object({ method: z.literal("shutdown"), id: z.string().optional() });

export const WireRequestSchema = z.discriminatedUnion("method", [
  RunRequestSchema,
  CancelRequestSchema,
  PingRequestSchema,
  ShutdownRequestSchema,
]);

export type WireRequest = z.infer<typeof WireRequestSchema>;

export type ParsedWireRequest =
  | { ok: true; req: WireRequest }
  | { ok: false; id?: string; error: string };

const KNOWN_METHODS = new Set(["run", "cancel", "ping", "shutdown"]);

/**
 * Validate one decoded wire request. Never throws — returns a discriminated
 * result so the daemon can reply with a structured error (correlating the
 * request `id` when one is recoverable).
 */
export function parseWireRequest(raw: unknown): ParsedWireRequest {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, error: "request must be a JSON object" };
  }
  const obj = raw as Record<string, unknown>;
  const id = typeof obj.id === "string" ? obj.id : undefined;
  const withId = (error: string): ParsedWireRequest => ({ ok: false, ...(id ? { id } : {}), error });

  if (typeof obj.method !== "string") {
    return withId('request is missing a string "method"');
  }
  if (!KNOWN_METHODS.has(obj.method)) {
    return withId(`unknown method: ${obj.method}`);
  }

  const parsed = WireRequestSchema.safeParse(raw);
  if (parsed.success) return { ok: true, req: parsed.data };
  return withId(`invalid ${obj.method} request: ${summarizeZodError(parsed.error)}`);
}

/** Compact "path: message" for the first validation issue. */
function summarizeZodError(err: z.ZodError): string {
  const issue = err.issues[0];
  if (!issue) return "validation failed";
  const path = issue.path.join(".");
  return path ? `${path}: ${issue.message}` : issue.message;
}
