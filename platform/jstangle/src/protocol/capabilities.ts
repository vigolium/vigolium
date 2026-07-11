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
    toolVersion: compiledString('toolVersion', '0.1.1-dev'),
    sourceHash: compiledString('sourceHash', 'development'),
    schemaVersions: {
      analysisResult: RESULT_SCHEMA_VERSION,
      extractedRequest: 1,
	  httpRequest: 2,
	  domFlow: 2,
	  assetReference: 2,
	  graphqlOperation: 2,
	  websocket: 2,
	  eventSource: 2,
	  clientRoute: 2,
	  browserSecurityFlow: 2,
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
