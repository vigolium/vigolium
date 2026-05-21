import { describe, expect, test } from "bun:test";
import { scheduleBatches } from "../../src/engine/phase.js";
import type { PhaseDef } from "../../src/engine/types.js";

function phase(id: string, dependsOn: string[] = [], parallelWith: string[] = []): PhaseDef {
  return {
    id,
    title: id,
    agent: null,
    requires_git: false,
    depends_on: dependsOn,
    parallel_with: parallelWith,
  };
}

describe("scheduleBatches", () => {
  test("returns one phase per batch when nothing is mutually parallel", () => {
    const batches = scheduleBatches([phase("a"), phase("b", ["a"]), phase("c", ["b"])]);
    expect(batches.map((b) => b.map((p) => p.id))).toEqual([["a"], ["b"], ["c"]]);
  });

  test("groups mutually-declared parallel_with phases into one batch", () => {
    // lite's shape: L2 and L3 both depend on L1 and declare each other parallel.
    const batches = scheduleBatches([
      phase("L1"),
      phase("L2", ["L1"], ["L3"]),
      phase("L3", ["L1"], ["L2"]),
    ]);
    expect(batches.map((b) => b.map((p) => p.id))).toEqual([["L1"], ["L2", "L3"]]);
  });

  test("ignores one-sided parallel_with declarations", () => {
    // A says it's parallel with B, but B doesn't reciprocate → serial.
    const batches = scheduleBatches([
      phase("root"),
      phase("a", ["root"], ["b"]),
      phase("b", ["root"]),
    ]);
    expect(batches.map((b) => b.map((p) => p.id))).toEqual([["root"], ["a"], ["b"]]);
  });

  test("requires every batched phase to be mutually parallel with every other", () => {
    // 3-way: A↔B, A↔C, B↔C. All three batch together.
    const tri = scheduleBatches([
      phase("root"),
      phase("a", ["root"], ["b", "c"]),
      phase("b", ["root"], ["a", "c"]),
      phase("c", ["root"], ["a", "b"]),
    ]);
    expect(tri.map((b) => b.map((p) => p.id))).toEqual([["root"], ["a", "b", "c"]]);

    // 3-way with missing edge: A↔B, A↔C but B–C absent → only A,B batch.
    const missing = scheduleBatches([
      phase("root"),
      phase("a", ["root"], ["b", "c"]),
      phase("b", ["root"], ["a"]),
      phase("c", ["root"], ["a"]),
    ]);
    expect(missing.map((b) => b.map((p) => p.id))).toEqual([["root"], ["a", "b"], ["c"]]);
  });

  test("flattening batches recreates the topological order", () => {
    const phases = [
      phase("1"),
      phase("2", ["1"], ["3"]),
      phase("3", ["1"], ["2"]),
      phase("4", ["2", "3"]),
    ];
    const flat = scheduleBatches(phases).flat();
    expect(flat.map((p) => p.id)).toEqual(["1", "2", "3", "4"]);
  });
});
