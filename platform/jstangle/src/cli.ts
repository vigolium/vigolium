#!/usr/bin/env node

import { randomUUID } from 'node:crypto';
import { statSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { program } from 'commander';
import { isRewriteLevel, jstangle, type RewriteLevel } from './index.js';
import {
  buildAnalysisResultV2,
  fitEnvelope,
  getCapabilities,
  PROTOCOL_VERSION,
  RESULT_SCHEMA_VERSION,
  safeArtifactName,
  writeArtifact,
  type AnalysisProfile,
  type ArtifactDescriptor,
  type Diagnostic,
  type ScanCompletedRecord,
  type ScanStatus,
} from './protocol/index.js';
import { runWorker } from './worker.js';

// Single source of truth: package.json version, injected at build time as
// __JSTANGLE_TOOL_VERSION__ (falls back to a -dev string when run uncompiled).
const version = getCapabilities().toolVersion;
const description = 'Extract API endpoints and HTTP request patterns from JavaScript bundles';

const validProfiles = new Set<AnalysisProfile>([
  'legacy', 'endpoints', 'dom-security', 'beautify', 'discovery', 'discovery-lite', 'full', 'inspect',
]);

interface CliOptions {
  force: boolean;
  beautify: boolean;
  unpackModules: boolean;
  capabilities: boolean;
  profile: string;
  rewriteLevel: string;
  scanId?: string;
  maxRequests: number;
  maxAstNodes: number;
  maxOutputBytes: number;
  deadlineMs: number;
  sourceUrl?: string;
  sourceName?: string;
  mediaType?: string;
  artifactDir?: string;
  maxArtifactBytes: number;
  worker: boolean;
}

async function readStdin() {
  let data = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

function isReadableFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

interface ResolvedInput {
  code: string;
  filename: string;
  /** Set only when the input was read from a real file (enables --force write-back). */
  filePath?: string;
}

/**
 * Resolve the JavaScript source from (in order of precedence): the first
 * positional argument, or piped stdin. The positional may be either a path to
 * an existing file or the raw JS source itself.
 */
async function resolveInput(arg: string | undefined): Promise<ResolvedInput> {
  if (arg === undefined) {
    return { code: await readStdin(), filename: 'stdin.js' };
  }
  if (isReadableFile(arg)) {
    return { code: await readFile(arg, 'utf8'), filename: basename(arg), filePath: arg };
  }
  return { code: arg, filename: 'inline.js' };
}

class JsonlEmitter {
  bytes = 0;

  constructor(readonly maxBytes: number) {}

  emit(record: unknown, mandatory = false): boolean {
    const line = `${JSON.stringify(record)}\n`;
    const bytes = Buffer.byteLength(line);
    if (!mandatory && this.bytes + bytes > this.maxBytes) {
      return false;
    }
    process.stdout.write(line);
    this.bytes += bytes;
    return true;
  }
}

program
  .version(version)
  .description(description)
  .option('-f, --force', 'overwrite input file with deobfuscated code')
  .option('-b, --beautify', 'also unminify + unpack bundles and emit a beautified record')
  .option('--unpack-modules', 'unpack detected bundles and re-scan each module for endpoints')
  .option('--profile <profile>', 'analysis profile', 'legacy')
  .option('--rewrite-level <level>', 'deobfuscation aggressiveness (strict|standard|aggressive)', 'standard')
  .option('--scan-id <id>', 'caller-supplied correlation ID')
  .option('--max-requests <count>', 'maximum retained endpoint facts', (value) => Number(value), 1000)
  .option('--max-ast-nodes <count>', 'maximum parsed AST nodes before graceful failure', (value) => Number(value), 500_000)
  .option('--max-output-bytes <bytes>', 'maximum non-control JSONL bytes', (value) => Number(value), 16 * 1024 * 1024)
  .option('--max-artifact-bytes <bytes>', 'maximum bytes for each derived artifact', (value) => Number(value), 32 * 1024 * 1024)
  .option('--deadline-ms <ms>', 'analysis deadline in milliseconds', (value) => Number(value), 60_000)
  .option('--source-url <url>', 'URL of the JavaScript asset being analyzed')
  .option('--source-name <name>', 'logical source filename (hides transport temp paths)')
  .option('--media-type <type>', 'source media type')
  .option('--artifact-dir <path>', 'allocated directory for large derived artifacts')
  .option('--capabilities', 'print the machine-readable protocol/capability record and exit')
  .option('--worker', 'run the persistent length-framed worker loop')
  .argument('[input]', 'JavaScript file path or raw JS source; reads stdin when omitted')
  .action(async (input: string | undefined) => {
    const options = program.opts<CliOptions>();
    if (options.worker) {
      await runWorker();
      return;
    }
    if (options.capabilities) {
      process.stdout.write(`${JSON.stringify(getCapabilities())}\n`);
      return;
    }

    if (!validProfiles.has(options.profile as AnalysisProfile)) {
      process.stderr.write(`Unknown analysis profile: ${options.profile}\n`);
      process.exitCode = 2;
      return;
    }
    if (!isRewriteLevel(options.rewriteLevel)) {
      process.stderr.write(`Unknown rewrite level: ${options.rewriteLevel}\n`);
      process.exitCode = 2;
      return;
    }

    const profile = options.profile as AnalysisProfile;
    const rewriteLevel = options.rewriteLevel as RewriteLevel;
    const scanId = options.scanId || randomUUID();
    const emitter = new JsonlEmitter(Math.max(1024, options.maxOutputBytes));
    let inputBytes = 0;
    let completionStatus: ScanStatus = 'failed';
    let completionReason = 'internal_analysis_error';
    let requests = 0;
    let domFlows = 0;
    let diagnostics = 0;
    let artifacts = 0;
    let stageMetrics: ScanCompletedRecord['stageMetrics'];

    try {
      const source = await resolveInput(input);
      const { code } = source;
      const filename = options.sourceName || source.filename;
      inputBytes = Buffer.byteLength(code);
      emitter.emit({
        type: 'scanStarted',
        protocolVersion: PROTOCOL_VERSION,
        schemaVersion: RESULT_SCHEMA_VERSION,
        scanId,
        profile,
        inputBytes,
      }, true);

      const result = await jstangle(code, {
        profile,
        rewriteLevel,
        scanId,
        beautify: options.beautify,
        unpackModules: options.unpackModules,
        sourceUrl: options.sourceUrl,
        filename,
        mediaType: options.mediaType,
        limits: {
          maxRequests: Math.max(1, options.maxRequests),
          maxAstNodes: Math.max(1_000, options.maxAstNodes),
          maxOutputBytes: emitter.maxBytes,
          deadlineMs: Math.max(1, options.deadlineMs),
        },
      });

      if (result.code) {
        if (options.force && source.filePath) await writeFile(source.filePath, result.code, 'utf8');
      }

      const descriptors: ArtifactDescriptor[] = [];
      const artifactDiagnostics: Diagnostic[] = [];
      if (result.code || result.beautified?.changed) {
        if (!options.artifactDir) {
          artifactDiagnostics.push({
            type: 'diagnostic', severity: 'warning', stage: 'artifacts',
            code: 'artifact_directory_unavailable',
            message: 'Generated source was not emitted because --artifact-dir was not provided',
            recoverable: true,
          });
        } else {
          if (result.code) {
            descriptors.push(await writeArtifact(
              options.artifactDir, 'transformedSource',
              safeArtifactName(filename, 'transformed.js'), result.code, options.maxArtifactBytes,
            ));
          }
          if (result.beautified?.changed) {
            descriptors.push(await writeArtifact(
              options.artifactDir, 'beautifiedSource',
              safeArtifactName(filename, 'beautified.js'), result.beautified.content,
              options.maxArtifactBytes,
              result.beautified.format,
              result.beautified.moduleCount,
              result.beautified.modulePaths,
            ));
          }
        }
      }
      const envelope = buildAnalysisResultV2(result, result.analysisContext, {
        sourceUrl: options.sourceUrl,
        filename,
        mediaType: options.mediaType,
        artifacts: descriptors,
      });
      envelope.diagnostics.push(...artifactDiagnostics);
      if (artifactDiagnostics.length && envelope.stats.status === 'complete') envelope.stats.status = 'partial';
      const fitted = fitEnvelope(envelope, emitter.maxBytes);
      emitter.emit(fitted.envelope, true);
      requests = fitted.envelope.records.filter((record) => record.kind === 'httpRequest').length;
      domFlows = fitted.envelope.records.filter((record) => record.kind === 'domFlow').length;
      diagnostics = fitted.envelope.diagnostics.length;
      artifacts = fitted.envelope.artifacts.length;
      completionStatus = fitted.envelope.stats.status;
      completionReason = fitted.omitted > 0
        ? 'output_budget_exceeded'
        : artifactDiagnostics.length > 0
          ? 'artifact_directory_unavailable'
          : result.status === 'failed'
            ? 'analysis_failed'
            : '';

      stageMetrics = result.stageMetrics;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      emitter.emit({
        type: 'diagnostic', severity: 'error', stage: 'scan',
        code: 'internal_analysis_error', message, recoverable: false,
      }, true);
      diagnostics++;
      process.exitCode = 1;
    }

    const completed: ScanCompletedRecord = {
      type: 'scanCompleted',
      protocolVersion: PROTOCOL_VERSION,
      schemaVersion: RESULT_SCHEMA_VERSION,
      scanId,
      profile,
      status: completionStatus,
      ...(completionReason ? { reasonCode: completionReason } : {}),
      counts: { requests, domFlows, diagnostics, artifacts },
      outputBytes: emitter.bytes,
      stageMetrics,
    };
    emitter.emit(completed, true);
    if (completionStatus === 'failed') process.exitCode = 1;
  })
  .parse();
