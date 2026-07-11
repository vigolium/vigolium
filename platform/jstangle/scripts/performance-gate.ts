#!/usr/bin/env bun

import { jstangle } from '../src/index';
import type { AnalysisProfile } from '../src/protocol';

async function elapsed(source: string, profile: AnalysisProfile, maxRequests: number): Promise<number> {
  const started = performance.now();
  const result = await jstangle(source, {
    profile,
    limits: { maxRequests, maxAstNodes: 1_000_000, deadlineMs: 120_000 },
  });
  if (result.status !== 'complete') {
    throw new Error(`${profile} performance corpus did not complete: ${result.status}`);
  }
  return performance.now() - started;
}

function requireRatio(label: string, focused: number, baseline: number, maximum: number): void {
  const ratio = focused / baseline;
  if (ratio > maximum) {
    throw new Error(`${label} regression: ratio=${ratio.toFixed(3)}, maximum=${maximum.toFixed(3)} (${focused.toFixed(1)}ms / ${baseline.toFixed(1)}ms)`);
  }
}

let readable = '';
for (let i = 0; i < 6_000; i++) {
  readable += `function f${i}(x){const u="/api/v1/items/${i}";return fetch(u+"?q="+x,{method:"POST",body:JSON.stringify({x})});}\n`;
}

const endpoints = await elapsed(readable, 'endpoints', 10_000);
const dom = await elapsed(readable, 'dom-security', 10_000);
const full = await elapsed(readable, 'full', 10_000);

// Wall-time gates are intentionally below the reference-run targets (30% and
// 70%) to tolerate shared CI runner noise while still preventing lost profile
// selectivity from passing unnoticed.
requireRatio('endpoint profile', endpoints, full, 0.80);
requireRatio('DOM profile', dom, full, 0.45);

let minified = '';
for (let i = 0; i < 1_000; i++) minified += `function b${i}(x){return fetch("/api/${i}?q="+x)};`;
const beautify = await elapsed(minified, 'beautify', 2_000);
const fullWithBeautify = await elapsed(minified, 'full', 2_000);
requireRatio('beautify-only profile', beautify, fullWithBeautify, 0.60);

process.stdout.write(`${JSON.stringify({
  bytes: readable.length,
  milliseconds: { endpoints, dom, full, beautify, fullWithBeautify },
  ratios: { endpoints: endpoints / full, dom: dom / full, beautify: beautify / fullWithBeautify },
})}\n`);
