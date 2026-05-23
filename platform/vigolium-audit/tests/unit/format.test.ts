import { describe, expect, test } from "bun:test";
import { formatDuration, formatTokens } from "../../src/cli/run-render.js";

describe("formatTokens", () => {
  test("returns raw integer below 1k", () => {
    expect(formatTokens(0)).toBe("0");
    expect(formatTokens(523)).toBe("523");
    expect(formatTokens(999)).toBe("999");
  });

  test("uses one decimal between 1k and 10k where the magnitude shifts", () => {
    expect(formatTokens(1_000)).toBe("1.0k");
    expect(formatTokens(1_234)).toBe("1.2k");
    expect(formatTokens(9_999)).toBe("10.0k");
  });

  test("drops decimals between 10k and 1M — the noise isn't worth it", () => {
    expect(formatTokens(10_000)).toBe("10k");
    expect(formatTokens(100_000)).toBe("100k");
    expect(formatTokens(234_567)).toBe("235k");
  });

  test("uses one decimal in the low millions, integer past 10M", () => {
    expect(formatTokens(1_500_000)).toBe("1.5M");
    expect(formatTokens(9_999_999)).toBe("10.0M");
    expect(formatTokens(12_345_678)).toBe("12M");
    expect(formatTokens(100_000_000)).toBe("100M");
  });

  test("non-finite / negative inputs collapse to 0", () => {
    expect(formatTokens(NaN)).toBe("0");
    expect(formatTokens(-1)).toBe("0");
    expect(formatTokens(Number.POSITIVE_INFINITY)).toBe("0");
  });
});

describe("formatDuration", () => {
  test("milliseconds for sub-second", () => {
    expect(formatDuration(0)).toBe("0ms");
    expect(formatDuration(234)).toBe("234ms");
    expect(formatDuration(999)).toBe("999ms");
  });

  test("seconds with one decimal under a minute", () => {
    expect(formatDuration(1_000)).toBe("1.0s");
    expect(formatDuration(12_300)).toBe("12.3s");
    expect(formatDuration(59_900)).toBe("59.9s");
  });

  test("minutes + seconds under an hour", () => {
    expect(formatDuration(60_000)).toBe("1m 0s");
    expect(formatDuration(330_000)).toBe("5m 30s");
    expect(formatDuration(3_599_000)).toBe("59m 59s");
  });

  test("hours + minutes past an hour — the example case", () => {
    expect(formatDuration(3_600_000)).toBe("1h 0m");
    expect(formatDuration(2_421_213)).toBe("40m 21s"); // sub-hour, sanity check
    expect(formatDuration(8_421_213)).toBe("2h 20m");
    expect(formatDuration(36_000_000)).toBe("10h 0m");
  });

  test("non-finite / negative inputs collapse to 0ms", () => {
    expect(formatDuration(NaN)).toBe("0ms");
    expect(formatDuration(-1)).toBe("0ms");
  });
});
