import { randomUUID } from 'node:crypto';
import type { Readable, Writable } from 'node:stream';
import { isRewriteLevel, jstangle } from './index';
import {
  buildAnalysisResultV2,
  fitEnvelope,
  getCapabilities,
  PROTOCOL_VERSION,
  RESULT_SCHEMA_VERSION,
  safeArtifactName,
  writeArtifact,
  FrameProtocolError,
  FrameReader,
  writeFrame,
  type AnalysisProfile,
  type ArtifactDescriptor,
  type Diagnostic,
  type ScanCompletedRecord,
  type WorkerAnalyzeRequest,
  type WorkerHelloRecord,
  type WorkerRequest,
  type WorkerResultRecord,
} from './protocol';

const DEFAULT_MAX_INPUT_BYTES = 10 * 1024 * 1024;
const DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_ARTIFACT_BYTES = 32 * 1024 * 1024;
const validProfiles = new Set<AnalysisProfile>([
  'legacy', 'endpoints', 'dom-security', 'beautify', 'discovery', 'discovery-lite', 'full', 'inspect',
]);

function boundedInteger(value: number | undefined, fallback: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value)) return fallback;
  return Math.min(maximum, Math.max(minimum, value!));
}

function validateRequest(request: WorkerRequest): asserts request is WorkerAnalyzeRequest {
  if (request.type !== 'analyze') throw new FrameProtocolError(`unexpected worker message: ${request.type}`);
  if (!request.id || request.id.length > 256) throw new FrameProtocolError('invalid job id');
  if (!validProfiles.has(request.profile)) throw new FrameProtocolError(`unsupported profile: ${request.profile}`);
  if (request.rewriteLevel !== undefined && !isRewriteLevel(request.rewriteLevel)) {
    throw new FrameProtocolError(`unsupported rewrite level: ${request.rewriteLevel}`);
  }
  if (!Number.isSafeInteger(request.contentLength) || request.contentLength < 0 || request.contentLength > DEFAULT_MAX_INPUT_BYTES) {
    throw new FrameProtocolError(`invalid content length: ${request.contentLength}`);
  }
  if (!request.artifactDir) throw new FrameProtocolError('artifactDir is required');
}

async function analyzeJob(request: WorkerAnalyzeRequest, content: Buffer): Promise<WorkerResultRecord> {
  const maxRequests = boundedInteger(request.limits?.maxRequests, 1000, 1, 100_000);
  const maxAstNodes = boundedInteger(request.limits?.maxAstNodes, 500_000, 1_000, 5_000_000);
  const maxOutputBytes = boundedInteger(request.limits?.maxOutputBytes, DEFAULT_MAX_OUTPUT_BYTES, 1024, 128 * 1024 * 1024);
  const maxArtifactBytes = boundedInteger(request.limits?.maxArtifactBytes, DEFAULT_MAX_ARTIFACT_BYTES, 1024, 256 * 1024 * 1024);
  const deadlineMs = boundedInteger(request.limits?.deadlineMs, 60_000, 1, 5 * 60_000);
  const filename = request.filename || 'source.js';
  const code = content.toString('utf8');
  const result = await jstangle(code, {
    profile: request.profile,
    rewriteLevel: request.rewriteLevel,
    scanId: request.id,
    beautify: request.beautify,
    unpackModules: request.unpackModules,
    sourceUrl: request.sourceUrl,
    filename,
    mediaType: request.mediaType,
    limits: { maxRequests, maxAstNodes, maxOutputBytes, deadlineMs },
  });

  const descriptors: ArtifactDescriptor[] = [];
  const artifactDiagnostics: Diagnostic[] = [];
  try {
    if (result.code) {
      descriptors.push(await writeArtifact(
        request.artifactDir, 'transformedSource', safeArtifactName(filename, 'transformed.js'),
        result.code, maxArtifactBytes,
      ));
    }
    if (result.beautified?.changed) {
      descriptors.push(await writeArtifact(
        request.artifactDir, 'beautifiedSource', safeArtifactName(filename, 'beautified.js'),
        result.beautified.content, maxArtifactBytes, result.beautified.format,
        result.beautified.moduleCount, result.beautified.modulePaths,
      ));
    }
  } catch (error) {
    artifactDiagnostics.push({
      type: 'diagnostic', severity: 'warning', stage: 'artifacts', code: 'artifact_write_failed',
      message: error instanceof Error ? error.message : String(error), recoverable: true,
    });
  }

  const envelope = buildAnalysisResultV2(result, result.analysisContext, {
    sourceUrl: request.sourceUrl, filename, mediaType: request.mediaType, artifacts: descriptors,
  });
  envelope.diagnostics.push(...artifactDiagnostics);
  if (artifactDiagnostics.length && envelope.stats.status === 'complete') envelope.stats.status = 'partial';
  const fitted = fitEnvelope(envelope, maxOutputBytes);
  const requests = fitted.envelope.records.filter((record) => record.kind === 'httpRequest').length;
  const domFlows = fitted.envelope.records.filter((record) => record.kind === 'domFlow').length;
  const completion: ScanCompletedRecord = {
    type: 'scanCompleted', protocolVersion: PROTOCOL_VERSION, schemaVersion: RESULT_SCHEMA_VERSION,
    scanId: request.id, profile: request.profile, status: fitted.envelope.stats.status,
    ...(fitted.omitted > 0 ? { reasonCode: 'output_budget_exceeded' } : {}),
    counts: {
      requests, domFlows, diagnostics: fitted.envelope.diagnostics.length,
      artifacts: fitted.envelope.artifacts.length,
    },
    outputBytes: Buffer.byteLength(JSON.stringify(fitted.envelope)),
    stageMetrics: fitted.envelope.stats.stageMetrics,
  };
  return { type: 'workerResult', id: request.id, result: fitted.envelope, completion };
}

function failedJob(request: WorkerAnalyzeRequest, error: unknown): WorkerResultRecord {
  const diagnostic: Diagnostic = {
    type: 'diagnostic', severity: 'error', stage: 'worker', code: 'internal_analysis_error',
    message: error instanceof Error ? error.message : String(error), recoverable: false,
  };
  return {
    type: 'workerResult', id: request.id, error: diagnostic,
    completion: {
      type: 'scanCompleted', protocolVersion: PROTOCOL_VERSION, schemaVersion: RESULT_SCHEMA_VERSION,
      scanId: request.id, profile: request.profile, status: 'failed', reasonCode: diagnostic.code,
      counts: { requests: 0, domFlows: 0, diagnostics: 1, artifacts: 0 },
    },
  };
}

/** Run one sequential analysis loop. Parallelism is supplied by Go workers. */
export async function runWorker(
  input: Readable = process.stdin,
  output: Writable = process.stdout,
): Promise<void> {
  const reader = new FrameReader(input, DEFAULT_MAX_INPUT_BYTES + 1024 * 1024);
  const hello: WorkerHelloRecord = {
    type: 'workerHello', workerId: randomUUID(), pid: process.pid, capabilities: getCapabilities(),
  };
  await writeFrame(output, hello);

  while (true) {
    const message = await reader.readJSON<WorkerRequest>();
    if (message === null || message.type === 'shutdown') return;
    validateRequest(message);
    const content = await reader.read();
    if (content === null || content.length !== message.contentLength) {
      throw new FrameProtocolError(`job ${message.id} content length mismatch`);
    }
    let response: WorkerResultRecord;
    try {
      response = await analyzeJob(message, content);
    } catch (error) {
      response = failedJob(message, error);
    }
    await writeFrame(output, response);
  }
}
