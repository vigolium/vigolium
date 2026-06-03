#!/usr/bin/env node

import { program } from 'commander';
import { readFile, writeFile } from 'node:fs/promises';
import { jsscan } from './index.js';

const version = '1.0.0';
const description = 'Extract API endpoints and HTTP request patterns from JavaScript bundles';

interface Options {
  force: boolean;
}

async function readStdin() {
  let data = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

program
  .version(version)
  .description(description)
  .option('-f, --force', 'overwrite input file with deobfuscated code')
  .argument('[file]', 'input file, defaults to stdin')
  .action(async (input: string | undefined) => {
    const { force, ...options } = program.opts<Options>();
    const code = await (input ? readFile(input, 'utf8') : readStdin());

    const result = await jsscan(code, options);

    const filename = input ?? 'deobfuscated.js';

    // If -f flag and input is file path, overwrite the original file
    if (force && input) {
      await writeFile(input, result.code, 'utf8');
    }

    // Output extractedRequests as JSON lines
    // Each URL variant is now emitted as a separate record from transforms
    for (const req of result.extractedRequests) {
      console.log(JSON.stringify(req));
    }

    // Output DOM-XSS source→sink taint flows as JSON lines
    for (const flow of result.domFlows) {
      console.log(JSON.stringify(flow));
    }

    // Output code as JSON line to stdout
    const codeRecord = { type: 'code', filename, content: result.code };
    console.log(JSON.stringify(codeRecord));
  })
  .parse();
