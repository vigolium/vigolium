import {
  PROTOCOL_VERSION,
  RESULT_SCHEMA_VERSION,
  type CapabilitiesRecord,
} from './types';

declare const __JSTANGLE_SOURCE_HASH__: string;
declare const __JSTANGLE_TOOL_VERSION__: string;
declare const __JSTANGLE_BUILD_TIMESTAMP__: string;
declare const __JSTANGLE_GIT_COMMIT__: string;
declare const __JSTANGLE_DEPENDENCIES__: string;

function compiledString(name: string, fallback: string): string {
  switch (name) {
    case 'sourceHash':
      return typeof __JSTANGLE_SOURCE_HASH__ === 'undefined'
        ? fallback
        : __JSTANGLE_SOURCE_HASH__;
    case 'toolVersion':
      return typeof __JSTANGLE_TOOL_VERSION__ === 'undefined'
        ? fallback
        : __JSTANGLE_TOOL_VERSION__;
    case 'buildTimestamp':
      return typeof __JSTANGLE_BUILD_TIMESTAMP__ === 'undefined'
        ? fallback
        : __JSTANGLE_BUILD_TIMESTAMP__;
    case 'gitCommit':
      return typeof __JSTANGLE_GIT_COMMIT__ === 'undefined'
        ? fallback
        : __JSTANGLE_GIT_COMMIT__;
    default:
      return fallback;
  }
}

function dependencies(): Record<string, string> {
  if (typeof __JSTANGLE_DEPENDENCIES__ === 'undefined') return {};
  try {
    return JSON.parse(__JSTANGLE_DEPENDENCIES__) as Record<string, string>;
  } catch {
    return {};
  }
}

export function getCapabilities(): CapabilitiesRecord {
  const bunVersion = process.versions.bun;
  const buildTimestamp = compiledString('buildTimestamp', '');
  const commit = compiledString('gitCommit', '');

  return {
    type: 'capabilities',
    protocolVersion: PROTOCOL_VERSION,
    toolVersion: compiledString('toolVersion', '0.2.0-dev'),
    sourceHash: compiledString('sourceHash', 'development'),
    schemaVersions: {
      analysisResult: RESULT_SCHEMA_VERSION,
      extractedRequest: 1,
      // 3: optional auth, callSite, suppressed; query split out of rendered URLs.
      httpRequest: 3,
      domFlow: 2,
      // 3: optional loader; assetType "chunk" for runtime-loaded chunks.
      assetReference: 3,
      graphqlOperation: 2,
      websocket: 2,
      eventSource: 2,
      // 3: optional fullPath and parentId. 4: optional meta and loader.
      clientRoute: 4,
      browserSecurityFlow: 2,
      pathLiteral: 1,
      artifact: 1,
      diagnostic: 1,
    },
    capabilities: [
      'endpoints',
      'domFlows',
      'transformedCode',
      'beautifiedCode',
      'requestEvidence',
      'diagnostics',
      'stageMetrics',
      'assetReferences',
      'graphqlOperations',
      'realtimeProtocols',
      'clientRoutes',
      'browserSecurityFlows',
      'pathLiterals',
      'facts.pathLiteral',
      'facts.httpRequest.auth',
      'facts.httpRequest.callSite',
      'facts.httpRequest.suppressed',
      'facts.httpRequest.urlModel',
      'facts.httpRequest.queryFromUrl',
      'facts.clientRoute.fullPath',
      'facts.clientRoute.meta',
      'completion.truncated',
      'loader.webpack-chunk',
      'loader.vite-preload',
    ],
    profiles: [
      'legacy',
      'endpoints',
      'dom-security',
      'beautify',
      'discovery',
      'discovery-lite',
      'full',
      'inspect',
    ],
    rewriteLevels: ['strict', 'standard', 'aggressive'],
    framing: ['length-prefixed-v2'],
    runtime: {
      name: bunVersion ? 'bun' : 'node',
      version: bunVersion ?? process.versions.node ?? 'unknown',
    },
    build: {
      ...(buildTimestamp ? { timestamp: buildTimestamp } : {}),
      ...(commit ? { commit } : {}),
      dependencies: dependencies(),
    },
  };
}
