import { readFileSync, writeFileSync } from "fs";

const raw = readFileSync("data/sample.jsonl", "utf-8");
const lines = raw.trim().split("\n");

// Store raw lines so the app can parse the envelope format at runtime
writeFileSync("src/data.json", JSON.stringify({ raw: lines }, null, 2));
console.log(`Embedded ${lines.length} records into src/data.json`);
