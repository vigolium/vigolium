import type { ParseResult } from '@babel/parser';
import { parse } from '@babel/parser';
import type * as t from '@babel/types';
import debug from 'debug';
import {
  applyTransforms,
  generate,
  type Transform,
} from './ast-utils';
import concatToPlus from './deobfuscate/concat-to-plus';
import controlFlowObject from './deobfuscate/control-flow-object';
import mergeStrings from './deobfuscate/merge-strings';
import { analyzeDomXss, type DomFlow } from './domxss/taint';
import { buildFunctionMap, clearFunctionMap, getWebpackExtractedRequests } from './mapping';
import { createGlobalVariableTracking, clearTrackedVariables, getTrackedVariablesMap } from './requestpattern/globalVariableTracking';
import { createFetchRequestTransform } from './requestpattern/fetchRequest';
import { createAxiosRequestTransform, clearAxiosInstances } from './requestpattern/axiosRequest';
import { createProtocolRequestTransform } from './requestpattern/protocolRequest';
import { createGenericRequestPattern1Transform } from './requestpattern/genericRequestPattern1';
import { createGenericRequestPattern2Transform } from './requestpattern/genericRequestPattern2';
import { createGenericRequestPattern3Transform } from './requestpattern/genericRequestPattern3';
import { createGenericRequestPattern4Transform } from './requestpattern/genericRequestPattern4';
import { createJqueryAjaxTransform } from './requestpattern/jqueryAjax';
import { createJqueryMethodTransform } from './requestpattern/jqueryMethod';
import type { ExtractedRequest } from './requestpattern/types';
import { clearExtractedRequests, getExtractedRequests } from './requestpattern/utils';
import { createVariableContainsURLTransform } from './requestpattern/variableContainsURL';
import { createXhrRequestTransform } from './requestpattern/xhrRequest';

// Re-export tracking utilities for testing
export { getTrackedVariablesMap, clearTrackedVariables } from './requestpattern/globalVariableTracking';

export interface JsscanResult {
  code: string;
  extractedRequests: ExtractedRequest[];
  domFlows: DomFlow[];
}

export interface Options {
  /**
   * @param progress Progress in percent (0-100)
   */
  onProgress?: (progress: number) => void;
}

function mergeOptions(options: Options): asserts options is Required<Options> {
  const mergedOptions: Required<Options> = {
    onProgress: () => { },
    ...options,
  };
  Object.assign(options, mergedOptions);
}

export async function jsscan(
  code: string,
  options: Options = {},
): Promise<JsscanResult> {
  mergeOptions(options);
  options.onProgress(0);

  // Clear state from previous runs
  clearExtractedRequests();
  clearTrackedVariables();
  clearFunctionMap();
  clearAxiosInstances();

  const isBookmarklet = /^javascript:./.test(code);
  if (isBookmarklet) {
    code = code
      .replace(/^javascript:/, '')
      .split(/%(?![a-f\d]{2})/i)
      .map(decodeURIComponent)
      .join('%');
  }

  let ast: ParseResult<t.File> = null!;
  let outputCode = '';
  let domFlows: DomFlow[] = [];

  const stages = [
    // Parse
    () => {
      ast = parse(code, {
        sourceType: 'unambiguous',
        allowReturnOutsideFunction: true,
        errorRecovery: true,
        plugins: [],
      });
      if (ast.errors?.length) {
        debug('jsscan:parse')('Errors', ast.errors);
      }
    },
    // DOM-XSS taint analysis on the pristine AST, so snippet offsets and line
    // numbers line up with the original source. Isolated in try/catch: this
    // stage runs before request extraction/deobfuscation, so a failure here
    // must never abort the rest of the pipeline.
    () => {
      try {
        domFlows = analyzeDomXss(ast, code);
      } catch (err) {
        debug('jsscan:domxss')('analysis failed', err);
        domFlows = [];
      }
    },
    // Essential deobfuscation (concat->plus, string merging, control flow object inlining)
    () => applyTransforms(ast, [concatToPlus, mergeStrings, controlFlowObject]),
    // Build function map (framework-aware mapping) BEFORE request extraction
    () => buildFunctionMap(ast, code),
    // Global variable tracking
    () => applyTransforms(ast, [createGlobalVariableTracking()]),
    // Request patterns (XHR, Fetch, axios, jQuery)
    () => applyTransforms(ast, [
      createXhrRequestTransform(ast, code),
      createFetchRequestTransform(ast, code),
      createAxiosRequestTransform(ast, code),
      createProtocolRequestTransform(ast, code),
      createJqueryAjaxTransform(ast, code),
      createJqueryMethodTransform(ast, code)] as Transform<unknown>[]),
    // Request patterns (Generic)
    () => applyTransforms(ast, [
      createGenericRequestPattern1Transform(ast, code),
      createGenericRequestPattern2Transform(ast, code),
      createGenericRequestPattern3Transform(ast, code),
      createGenericRequestPattern4Transform(ast, code),
      createVariableContainsURLTransform(ast, code),
    ] as Transform<unknown>[]),
    // Generate code
    () => (outputCode = generate(ast)),
  ];

  for (let i = 0; i < stages.length; i++) {
    await stages[i]();
    options.onProgress((100 / stages.length) * (i + 1));
  }

  // Combine regular extracted requests with webpack-extracted requests
  // Webpack requests are preferred because they have scope-aware body extraction
  const regularRequests = getExtractedRequests();
  const trackedVars = getTrackedVariablesMap();
  // Convert TrackedVariableMap (Record<string, string[]>) to Record<string, string>
  // by taking the first value of each array
  const trackedVarsSimple: Record<string, string> = {};
  for (const [key, values] of Object.entries(trackedVars)) {
    if (values && values.length > 0) {
      trackedVarsSimple[key] = values[0];
    }
  }
  const webpackRequests = getWebpackExtractedRequests(trackedVarsSimple);

  // Normalize template variables for deduplication
  const normalizeTemplateVars = (s: string) => s.replace(/\$\{[^}]*\}/g, '${X}');

  // Deduplicate by exact match (URL+method+body)
  // Prefer requests with more complete information (body, headers)
  const seenExact = new Set<string>();
  const allRequests: ExtractedRequest[] = [];

  // Combine all requests with original index for stable sorting
  const combinedRequests = [...regularRequests, ...webpackRequests].map((req, idx) => ({ req, idx }));

  // Sort to prefer requests with body/headers (more complete data first)
  // Use original index as secondary key for stable sorting
  combinedRequests.sort((a, b) => {
    const scoreA = (a.req.body ? 1 : 0) + (a.req.headers?.length ? 1 : 0);
    const scoreB = (b.req.body ? 1 : 0) + (b.req.headers?.length ? 1 : 0);
    if (scoreB !== scoreA) {
      return scoreB - scoreA; // Higher score first
    }
    return a.idx - b.idx; // Preserve original order as tiebreaker
  });

  for (const { req } of combinedRequests) {
    const exactKey = `${normalizeTemplateVars(req.url)}|${req.method}|${normalizeTemplateVars(req.body)}`;
    if (!seenExact.has(exactKey)) {
      seenExact.add(exactKey);
      allRequests.push(req);
    }
  }

  return {
    code: outputCode,
    extractedRequests: allRequests,
    domFlows,
  };
}
