import { describe, expect, test } from "bun:test";
import { parsePositiveUsd } from "../../src/cli/util.js";

describe("parsePositiveUsd", () => {
  test("accepts positive numbers and numeric strings", () => {
    expect(parsePositiveUsd(20)).toBe(20);
    expect(parsePositiveUsd("20")).toBe(20);
    expect(parsePositiveUsd("0.5")).toBe(0.5);
    expect(parsePositiveUsd("1e2")).toBe(100);
  });

  test("rejects non-numeric input as null (so callers can error, not silently drop the cap)", () => {
    expect(parsePositiveUsd("abc")).toBeNull();
    expect(parsePositiveUsd("20abc")).toBeNull();
    expect(parsePositiveUsd("")).toBeNull(); // Number("") === 0 → not positive
  });

  test("rejects NaN and non-finite values", () => {
    expect(parsePositiveUsd(NaN)).toBeNull();
    expect(parsePositiveUsd(Number.POSITIVE_INFINITY)).toBeNull();
    expect(parsePositiveUsd(Number.NEGATIVE_INFINITY)).toBeNull();
  });

  test("rejects zero and negatives — a cap of <= 0 is meaningless", () => {
    expect(parsePositiveUsd(0)).toBeNull();
    expect(parsePositiveUsd("0")).toBeNull();
    expect(parsePositiveUsd(-5)).toBeNull();
    expect(parsePositiveUsd("-5")).toBeNull();
  });
});
