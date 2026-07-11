import { describe, expect, test } from "bun:test";
import { parseWireRequest } from "../../src/cli/bridge-protocol.js";

/** Convenience: parse a value and assert it failed, returning the message. */
function reject(raw: unknown): { id?: string; error: string } {
  const r = parseWireRequest(raw);
  if (r.ok) throw new Error(`expected rejection, got ${JSON.stringify(r)}`);
  return { ...(r.id ? { id: r.id } : {}), error: r.error };
}

describe("parseWireRequest — valid", () => {
  test("run with params", () => {
    const r = parseWireRequest({ id: "r1", method: "run", params: { action: "triage", skills: ["fp-check"] } });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.req.method).toBe("run");
      expect(r.req.id).toBe("r1");
    }
  });

  test("run without params is allowed", () => {
    expect(parseWireRequest({ id: "r1", method: "run" }).ok).toBe(true);
  });

  test("cancel / ping / shutdown", () => {
    expect(parseWireRequest({ method: "cancel", params: { id: "r1" } }).ok).toBe(true);
    expect(parseWireRequest({ method: "cancel", id: "r1" }).ok).toBe(true);
    expect(parseWireRequest({ method: "ping" }).ok).toBe(true);
    expect(parseWireRequest({ method: "shutdown" }).ok).toBe(true);
  });

  test("unknown params fields are tolerated (forward-compat)", () => {
    const r = parseWireRequest({ id: "r1", method: "run", params: { action: "run", somethingNew: 42 } });
    expect(r.ok).toBe(true);
  });

  test("accepts the new permission/network/timeout params", () => {
    const r = parseWireRequest({
      id: "r1",
      method: "run",
      params: { action: "triage", permission: "read-only", network: true, timeoutMs: 30000 },
    });
    expect(r.ok).toBe(true);
  });
});

describe("parseWireRequest — malformed shapes cannot reach dispatch", () => {
  test("non-object primitives", () => {
    expect(reject(5).error).toMatch(/must be a JSON object/);
    expect(reject("hello").error).toMatch(/must be a JSON object/);
    expect(reject(null).error).toMatch(/must be a JSON object/);
    expect(reject([]).error).toMatch(/must be a JSON object/);
  });

  test("missing or non-string method", () => {
    expect(reject({ id: "r1" }).error).toMatch(/missing a string "method"/);
    expect(reject({ id: "r1", method: 3 }).error).toMatch(/missing a string "method"/);
  });

  test("unknown method names", () => {
    expect(reject({ method: "frobnicate" }).error).toMatch(/unknown method: frobnicate/);
  });

  test("run requires a non-empty id (error correlates nothing to fake)", () => {
    const r = reject({ method: "run", params: { action: "triage" } });
    expect(r.error).toMatch(/invalid run request/);
    expect(r.id).toBeUndefined();
  });

  test("wrong field types are rejected with the field path", () => {
    expect(reject({ id: "r1", method: "run", params: { skills: "fp-check" } }).error).toMatch(/skills/);
    expect(reject({ id: "r1", method: "run", params: { agent: "gpt" } }).error).toMatch(/agent/);
    expect(reject({ id: "r1", method: "run", params: { maxTurns: 0 } }).error).toMatch(/maxTurns/);
    expect(reject({ id: "r1", method: "run", params: { maxTurns: -3 } }).error).toMatch(/maxTurns/);
    expect(reject({ id: "r1", method: "run", params: { timeoutMs: -1 } }).error).toMatch(/timeoutMs/);
  });

  test("a recoverable id is echoed back so the client can correlate the error", () => {
    const r = reject({ id: "r9", method: "run", params: { skills: 123 } });
    expect(r.id).toBe("r9");
  });
});
