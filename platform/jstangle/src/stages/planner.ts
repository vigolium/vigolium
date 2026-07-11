import type { AnalysisCapability } from '../protocol';

export type StageName =
  | 'parse'
  | 'domFlows'
  | 'deobfuscate'
  | 'staticEval'
  | 'structuralIndex'
  | 'functionMapping'
  | 'valueTracking'
  | 'assetDiscovery'
  | 'capabilityPacks'
  | 'requestClients'
  | 'requestFallbacks'
  | 'bundleModuleScan'
  | 'generateCode'
  | 'beautify';

export interface PlannedStage {
  name: StageName;
  enabled: boolean;
  fatal: boolean;
  requires: string[];
  produces: string[];
  mutatesAst: boolean;
  costClass: 'light' | 'medium' | 'heavy';
}

type CapabilitySet = ReadonlySet<AnalysisCapability>;

const needsAst = (capabilities: CapabilitySet) =>
  capabilities.has('endpoints') || capabilities.has('domFlows') || capabilities.has('transformedCode') ||
  capabilities.has('assetReferences') || capabilities.has('graphqlOperations') ||
  capabilities.has('realtimeProtocols') || capabilities.has('clientRoutes') || capabilities.has('browserSecurityFlows');
const needsTransforms = (capabilities: CapabilitySet) =>
  capabilities.has('endpoints') || capabilities.has('transformedCode') || capabilities.has('assetReferences') ||
  capabilities.has('graphqlOperations') || capabilities.has('realtimeProtocols') || capabilities.has('clientRoutes');

export function buildStagePlan(capabilities: CapabilitySet): PlannedStage[] {
  const endpoints = capabilities.has('endpoints');
  const assets = capabilities.has('assetReferences');
  const packs = capabilities.has('graphqlOperations') || capabilities.has('realtimeProtocols') ||
    capabilities.has('clientRoutes') || capabilities.has('browserSecurityFlows');
  return [
    {
      name: 'parse', enabled: needsAst(capabilities), fatal: true,
      requires: ['source'], produces: ['originalAst'], mutatesAst: false, costClass: 'medium',
    },
    {
      name: 'domFlows', enabled: capabilities.has('domFlows'), fatal: false,
      requires: ['originalAst'], produces: ['domFlows'], mutatesAst: false, costClass: 'medium',
    },
    {
      name: 'deobfuscate', enabled: needsTransforms(capabilities), fatal: endpoints,
      requires: ['originalAst'], produces: ['transformedAst'], mutatesAst: true, costClass: 'medium',
    },
    {
      name: 'staticEval', enabled: needsTransforms(capabilities), fatal: false,
      requires: ['transformedAst'], produces: ['transformedAst'], mutatesAst: true, costClass: 'medium',
    },
    {
      name: 'structuralIndex', enabled: endpoints, fatal: false,
      requires: ['transformedAst'], produces: ['structuralIndex'], mutatesAst: false, costClass: 'medium',
    },
    {
      name: 'functionMapping', enabled: endpoints, fatal: false,
      requires: ['transformedAst', 'structuralIndex'], produces: ['functionIndex'], mutatesAst: false, costClass: 'medium',
    },
    {
      name: 'valueTracking', enabled: endpoints || assets || packs, fatal: false,
      requires: ['transformedAst'], produces: ['valueIndex'], mutatesAst: false, costClass: 'medium',
    },
    {
      name: 'assetDiscovery', enabled: assets, fatal: false,
      requires: ['transformedAst', 'valueIndex'], produces: ['assetReferences'], mutatesAst: false, costClass: 'light',
    },
    {
      name: 'capabilityPacks', enabled: packs, fatal: false,
      requires: ['transformedAst', 'valueIndex'], produces: ['protocolFacts', 'clientRoutes', 'browserSecurityFlows'], mutatesAst: false, costClass: 'medium',
    },
    {
      name: 'requestClients', enabled: endpoints, fatal: false,
      requires: ['transformedAst', 'functionIndex', 'valueIndex'], produces: ['requestCandidates'], mutatesAst: false, costClass: 'medium',
    },
    {
      name: 'requestFallbacks', enabled: endpoints, fatal: false,
      requires: ['transformedAst', 'requestCandidates'], produces: ['requestCandidates'], mutatesAst: false, costClass: 'heavy',
    },
    {
      // Opt-in (gated on the unpackModules option in index.ts). Unpacks the
      // bundle via webcrack and re-scans each recovered module independently,
      // merging endpoints with module-path provenance.
      name: 'bundleModuleScan', enabled: endpoints, fatal: false,
      requires: ['source'], produces: ['requestCandidates'], mutatesAst: false, costClass: 'heavy',
    },
    {
      name: 'generateCode', enabled: capabilities.has('transformedCode'), fatal: false,
      requires: ['transformedAst'], produces: ['transformedCode'], mutatesAst: false, costClass: 'heavy',
    },
    {
      name: 'beautify', enabled: capabilities.has('beautifiedCode'), fatal: false,
      requires: ['source'], produces: ['beautifiedCode'], mutatesAst: false, costClass: 'heavy',
    },
  ];
}
