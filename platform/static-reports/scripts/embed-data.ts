import { readFileSync, writeFileSync, existsSync } from "fs";

const dataFile = process.argv[2] || (
  existsSync("data/archon-harbor-findings.jsonl")
    ? "data/archon-harbor-findings.jsonl"
    : "data/sample.jsonl"
);

const raw = readFileSync(dataFile, "utf-8");
const lines = raw.trim().split("\n");

// Store raw lines so the app can parse the envelope format at runtime
writeFileSync("src/data.json", JSON.stringify({ raw: lines }, null, 2));
console.log(`Embedded ${lines.length} records from ${dataFile} into src/data.json`);
