import type { NodePath } from '@babel/traverse';
import type * as t from '@babel/types';
import { createHash } from 'node:crypto';
import type { AnalysisContext } from '../context';
import type { Confidence, HttpClientKind, ResolutionStep } from '../protocol';
import type { TracebackResult } from '../traceback/tracebackVariables';
import type { ExtractedRequest } from './types';

export interface RequestEmission {
    extractor: string;
    client: HttpClientKind;
    confidence: Confidence;
    node?: t.Node | null;
    functionName?: string;
    /** Recovered bundle-module path this request came from, if any. */
    modulePath?: string;
    evidence?: string;
    resolutionSteps?: ResolutionStep[];
}

const CONFIDENCE_RANK: Record<Confidence, number> = {
    low: 0,
    medium: 1,
    high: 2,
};

function recordOrigin(
    context: AnalysisContext,
    index: number,
    emission: RequestEmission | undefined,
    request: ExtractedRequest,
): void {
    const fallback = context.defaultOrigin();
    const node = emission?.node;
    const origin = emission ? {
        client: emission.client,
        provenance: {
            extractor: emission.extractor,
            confidence: emission.confidence,
            ...(emission.functionName ? { functionName: emission.functionName } : {}),
            ...(emission.modulePath ? { modulePath: emission.modulePath } : {}),
            ...(node?.loc?.start ? {
                start: {
                    line: node.loc.start.line,
                    column: node.loc.start.column,
                    ...(typeof node.start === 'number' ? { offset: node.start } : {}),
                },
            } : {}),
            ...(node?.loc?.end ? {
                end: {
                    line: node.loc.end.line,
                    column: node.loc.end.column,
                    ...(typeof node.end === 'number' ? { offset: node.end } : {}),
                },
            } : {}),
            ...(emission.evidence ? { evidence: emission.evidence } : {}),
            ...(emission.resolutionSteps?.length ? { resolutionSteps: emission.resolutionSteps } : {}),
        },
        extractors: [emission.extractor],
        alternatives: { url: [], method: [], params: [], body: [] },
    } : fallback;

    const existing = context.requestOrigins[index];
    if (!existing) {
        context.requestOrigins[index] = origin;
        return;
    }
    existing.extractors = [...new Set([...existing.extractors, ...origin.extractors])];
    const canonical = context.requests[index];
    for (const field of ['url', 'method', 'params', 'body'] as const) {
        if (request[field] !== canonical[field] && !existing.alternatives[field].includes(request[field])) {
            existing.alternatives[field].push(request[field]);
        }
    }
    if (CONFIDENCE_RANK[origin.provenance.confidence] > CONFIDENCE_RANK[existing.provenance.confidence]) {
        existing.client = origin.client;
        existing.provenance = origin.provenance;
    }
}

const MAX_CODE_LENGTH = 5000;

function generateChecksum(code: string): string {
    const hash = createHash('sha256');
    hash.update(code);
    return hash.digest('hex');
}

export function appendPattern(
    context: AnalysisContext,
    result: TracebackResult | (() => TracebackResult),
    patternType: string,
    node?: object,
) {
    if (!context.has('requestEvidence')) return;
    if (typeof result === 'function') {
        if (node && context.pendingEvidenceNodes.has(node)) return;
        // Queue a small multiple of the output budget. Expensive traceback is
        // executed only for nodes that ultimately contributed a retained,
        // deduplicated request candidate.
        if (context.pendingRequestEvidence.length >= context.limits.maxEvidenceRecords * 4) return;
        if (node) context.pendingEvidenceNodes.add(node);
        context.pendingRequestEvidence.push({ patternType, node, build: result });
        return;
    }
    appendResolvedPattern(context, result, patternType);
}

function appendResolvedPattern(
    context: AnalysisContext,
    result: TracebackResult,
    patternType: string,
): void {
    if (result.code === '' || result.code.length > MAX_CODE_LENGTH) {
        return;
    }
    const checksum = generateChecksum(result.code);

    if (!context.patternDedup.has(checksum)) {
        if (context.requestPatterns.length >= context.limits.maxEvidenceRecords) {
            context.partial = true;
            context.addDiagnostic({
                type: 'diagnostic',
                severity: 'warning',
                stage: 'requestEvidence',
                code: 'evidence_limit_reached',
                message: `Request evidence limited to ${context.limits.maxEvidenceRecords} records`,
                recoverable: true,
            });
            return;
        }
        context.patternDedup.add(checksum);

        const newPattern = {
            type: 'requestPattern' as const,
            patternType: patternType,
            code: result.code,
            functionName: result.functionName,
            paramCount: result.paramCount,
            literals: result.literals,
            callSites: result.callSites,
            tracedVariables: [...result.tracedVariables]
        };

        context.requestPatterns.push(newPattern);
    }
}

export function flushPendingPatterns(context: AnalysisContext): void {
    const pending = context.pendingRequestEvidence.splice(0);
    for (const evidence of pending) {
        if (context.requestPatterns.length >= context.limits.maxEvidenceRecords) break;
        if (evidence.node && !context.retainedEvidenceNodes.has(evidence.node)) continue;
        try {
            context.evidenceBuilds++;
            appendResolvedPattern(context, evidence.build(), evidence.patternType);
        } catch (error) {
            context.partial = true;
            context.addDiagnostic({
                type: 'diagnostic', severity: 'warning', stage: 'requestEvidence',
                code: 'evidence_generation_failed',
                message: error instanceof Error ? error.message : String(error),
                recoverable: true,
            });
        }
    }
}

const API_KEYWORDS = ['api', 'v1', 'v2', 'rest', 'graphql', 'endpoint'];
const FILE_EXTENSIONS = ['.aspx', '.php', '.jsp', '.cgi', '.json', '.xml', '.do', '.action', '.svc', '.asmx'];

export function isURLLike(value: string): boolean {
    const countOccurrences = (str: string, char: string) =>
        (str.match(new RegExp(char, 'g')) || []).length;

    // Must have at least 1 letter
    if (!/[a-zA-Z]/.test(value)) return false;

    // Exclude HTML tags and non-URL patterns
    if (value.startsWith('<') || value.endsWith('>')) return false;
    if (value.endsWith('svg')) return false;
    if (value.startsWith('.') || value.startsWith('#')) return false;
    if (value === '/') return false;

    // Exclude special schemes
    if (value.startsWith('path://')) return false;
    if (value.startsWith('image://')) return false;
    if (value.startsWith('relative://')) return false;
    if (value === 'http://' || value === 'https://') return false;
    if (value === 'http:' || value === 'https:') return false;

    // Exclude other patterns
    if (value.includes('w3.org')) return false;
    if (/\s/.test(value)) return false;
    if (countOccurrences(value, '.') >= 2 && countOccurrences(value, '/') === 0) return false;

    // Check URL patterns
    if (value.startsWith('//')) return true;
    if (value.startsWith('http:') || value.startsWith('https:')) return true;
    if (value.startsWith('/') && value.length > 1) return true;

    // Check API keywords
    const lowerValue = value.toLowerCase();
    if (API_KEYWORDS.some(keyword => lowerValue.includes(keyword))) return true;

    // Check file extensions (for endpoints like ajax.aspx, handler.php)
    if (FILE_EXTENSIONS.some(ext => lowerValue.endsWith(ext))) return true;

    // Check path-like patterns (multiple slashes)
    if (countOccurrences(value, '/') >= 2) return true;

    return false;
}

export function collectAPIUrls(path: NodePath): string[] {
    const strings: string[] = [];

    path.traverse({
        StringLiteral(path: NodePath<t.StringLiteral>) {
            const value = path.node.value;
            if (isURLLike(value)) {
                strings.push(value);
            }
        },
        TemplateLiteral(path: NodePath<t.TemplateLiteral>) {
            // Handle template literal only when it has no expressions (quasis.length === 1)
            if (path.node.quasis.length === 1) {
                const value = path.node.quasis[0].value.raw;
                if (isURLLike(value)) {
                    strings.push(value);
                }
            }
        }
    });

    return strings;
}

/**
 * Normalize template variables in a string for deduplication purposes.
 * Replaces ${...} with ${X} to treat all template variables as equivalent.
 */
function normalizeTemplateVars(value: string): string {
    return value.replace(/\$\{[^}]*\}/g, '${X}');
}

/**
 * Check if a URL should be skipped (non-HTTP schemes like data:, javascript:, mailto:, etc.)
 */
function isNonHttpScheme(url: string): boolean {
    const nonHttpSchemes = [
        'data:',
        'javascript:',
        'mailto:',
        'tel:',
        'blob:',
        'file:',
        'about:',
        'chrome:',
        'chrome-extension:',
        'moz-extension:',
        'safari-extension:',
        'edge:',
        'vscode:',
        'vscode-webview:',
        "git@"
    ];
    const lowerUrl = url.toLowerCase();
    return nonHttpSchemes.some(scheme => lowerUrl.startsWith(scheme));
}

/**
 * Check if a URL is purely composed of variable placeholders.
 * Examples:
 * - ${concat()} -> pure variable
 * - ${p1}/${p2}/ -> pure variable path
 * - ${p1}/${p2}/${p3} -> pure variable path
 * - /api/${id} -> NOT pure variable (has /api/ prefix)
 * - ${baseUrl}/users -> NOT pure variable (has /users suffix)
 */
function isPureVariableUrl(url: string): boolean {
    // Remove all ${...} placeholders from the URL
    const withoutPlaceholders = url.replace(/\$\{[^}]*\}/g, '');
    // If only slashes remain (or empty), it's a pure variable URL
    // Also skip if nothing meaningful remains after removing placeholders
    return withoutPlaceholders === '' || /^\/+$/.test(withoutPlaceholders);
}

/**
 * Check if a string looks like a valid URL or URL path for HTTP requests.
 * Filters out common false positives from generic pattern detection.
 */
function isValidHttpUrl(url: string): boolean {
    // Empty or whitespace
    if (!url || !url.trim()) return false;

    // Single character - definitely not a URL
    if (url.length === 1) return false;

    // Very short strings that are likely variable names (2-3 chars without /)
    if (url.length <= 3 && !url.includes('/') && !url.includes('.')) return false;

    // Pure variable placeholders
    if (/^\$\{[^}]+\}$/.test(url)) return false;

    // Common HTTP header names (case-insensitive) - these get detected from header access
    const headerNames = [
        'content-type', 'content-length', 'accept', 'accept-encoding',
        'accept-language', 'authorization', 'cache-control', 'connection',
        'cookie', 'host', 'origin', 'referer', 'user-agent', 'x-requested-with',
        'x-forwarded-for', 'x-forwarded-proto', 'x-csrf-token', 'x-api-key',
        'location', 'etag', 'expires', 'pragma', 'vary', 'allow', 'server',
    ];
    if (headerNames.includes(url.toLowerCase())) return false;

    // Event names commonly used with addEventListener
    const eventNames = [
        'popstate', 'hashchange', 'click', 'submit', 'load', 'unload',
        'beforeunload', 'resize', 'scroll', 'keydown', 'keyup', 'keypress',
        'mousedown', 'mouseup', 'mousemove', 'mouseenter', 'mouseleave',
        'touchstart', 'touchend', 'touchmove', 'focus', 'blur', 'change',
        'input', 'error', 'message', 'storage', 'online', 'offline',
    ];
    if (eventNames.includes(url.toLowerCase())) return false;

    // All caps constants (likely enums/constants, not URLs)
    if (/^[A-Z_]+$/.test(url) && url.length <= 20) return false;

    // Date format patterns (MM/dd/yyyy, YYYY-MM-DD, hh:mm:ss, etc.)
    if (/^[MDYHhmsaAdy\/\-:.\s]+$/.test(url)) return false;

    // Ionic/Cordova lifecycle events in URLs (false positives from minified code)
    // Examples: ionKeyboardDidShow, ionViewWillUnload, ionViewDidEnter
    if (/\bion[A-Z][a-zA-Z]+/.test(url)) return false;

    // SVG path data patterns (M, L, Z commands with numbers)
    // Examples: M6 12L18 12, M0 0L10 10
    if (/[ML]\d+\s+\d+/.test(url)) return false;

    // Malformed URL paths with empty placeholders
    // /:/ or /:/something - empty parameter in path
    if (/\/:\/?/.test(url)) return false;

    // Double slash in middle of path (not protocol)
    if (/[^:]\/\//.test(url)) return false;

    // Static asset paths (images, icons, etc.) - not API endpoints
    if (/^assets\//.test(url) || /\.(png|jpg|jpeg|gif|svg|ico|webp|css|js|woff2?|ttf|eot)$/i.test(url)) return false;

    // Valid URL patterns - must match at least one
    const validPatterns = [
        // Absolute URLs
        /^https?:\/\//i,
        // WebSocket / SSE endpoints (ws://, wss://)
        /^wss?:\/\//i,
        // Protocol-relative URLs
        /^\/\//,
        // Absolute paths starting with /
        /^\//,
        // Relative paths with / in them
        /^[a-zA-Z0-9_]+\//,
        // URLs with query strings
        /\?[a-zA-Z]/,
        // Template URLs with static parts + placeholders
        /^[a-zA-Z0-9_/]+\$\{/,
        /\$\{[^}]+\}[a-zA-Z0-9_/]+/,
        // Server-side script/web app extensions
        /\.(aspx?|php[345]?|jsp|jspx|cfm|cfml|cgi|pl|py|rb|do|action|html?|shtml|xhtml|ashx|asmx|axd|cshtml|vbhtml|nsf|ws|wss|svc)$/i,
    ];

    return validPatterns.some(pattern => pattern.test(url));
}

/**
 * Check if params look like a frontend framework config rather than HTTP request params.
 * Detects React Router, Vue Router, Angular Router, Ionic Router, and React component props.
 *
 * React Router: {path: '/route', exact: true, component: Component}
 * Vue Router: {path: '/route', component: Component, name: 'routeName'}
 * Ionic Router: {routerLink: '/path', routerDirection: 'forward'}
 * React Component: {className: '...', children: [...], onClick: ...}
 */
function isFrontendFrameworkParams(params: string): boolean {
    if (!params) return false;

    // React Router patterns: path=...&exact=... or path=...&component=... or path=...&render=...
    // The 'exact' is often minified as !0 (true) or !1 (false)
    if (/\bpath=/.test(params) && /\b(exact=|component=|render=|strict=|sensitive=)/.test(params)) {
        return true;
    }

    // Ionic Router patterns: routerLink=...&routerDirection=...
    if (/\brouterLink=/.test(params) && /\brouterDirection=/.test(params)) {
        return true;
    }

    // Vue Router patterns: path=...&name=...&component=...
    if (/\bpath=/.test(params) && /\bname=/.test(params) && /\bcomponent=/.test(params)) {
        return true;
    }

    // Angular Router patterns: path=...&redirectTo=... or path=...&loadChildren=...
    if (/\bpath=/.test(params) && /\b(redirectTo=|loadChildren=|canActivate=|canDeactivate=)/.test(params)) {
        return true;
    }

    // React/JSX component props patterns
    // children=... is a React prop, not HTTP params
    // Matches: children=[...], children=${...}, children=Component, etc.
    if (/\bchildren=/.test(params)) {
        return true;
    }

    // className with Ionic/React patterns (ion-*, className combined with id/children)
    if (/\bclassName=/.test(params) && /\b(id=|children=)/.test(params)) {
        return true;
    }

    // Ionic component props: lines=none, autoHide, slot, etc.
    if (/\b(lines=none|autoHide=|slot=|expand=|fill=|size=)/.test(params) && /\b(id=|children=)/.test(params)) {
        return true;
    }

    return false;
}

export function appendExtractedRequest(
    context: AnalysisContext,
    request: ExtractedRequest,
    emission?: RequestEmission,
): boolean {
    // Skip if URL is empty or just a placeholder
    if (!request.url || request.url === '${unknown}') {
        return false;
    }

    // Skip non-HTTP schemes (data:, javascript:, mailto:, etc.)
    if (isNonHttpScheme(request.url)) {
        return false;
    }

    // Skip URLs that are purely variable placeholders
    if (isPureVariableUrl(request.url)) {
        return false;
    }

    // Skip invalid URLs (false positives like HTTP headers, event names, etc.)
    if (!isValidHttpUrl(request.url)) {
        return false;
    }

    // Skip frontend framework configs (React Router, Vue Router, Ionic Router, React components, etc.)
    if (isFrontendFrameworkParams(request.params)) {
        return false;
    }

    const identity = [
        normalizeTemplateVars(request.url),
        request.method.toUpperCase(),
        normalizeTemplateVars(request.params),
        normalizeTemplateVars(request.body),
    ].join('|');
    const existingIndex = context.requestDedup.get(identity);
    if (existingIndex !== undefined) {
        const existing = context.requests[existingIndex];
        existing.headers = [...new Set([...existing.headers, ...request.headers])];
        existing.cookies = [...new Set([...existing.cookies, ...request.cookies])];
        recordOrigin(context, existingIndex, emission, request);
        return true;
    }

    if (context.requests.length >= context.limits.maxRequests) {
        context.partial = true;
        context.addDiagnostic({
            type: 'diagnostic',
            severity: 'warning',
            stage: 'endpoints',
            code: 'request_limit_reached',
            message: `Endpoint output limited to ${context.limits.maxRequests} records`,
            recoverable: true,
        });
        return false;
    }
    const index = context.requests.length;
    context.requestDedup.set(identity, index);
    context.requests.push(request);
    if (emission?.node) context.retainedEvidenceNodes.add(emission.node);
    recordOrigin(context, index, emission, request);
    return true;
}

export function getExtractedRequests(context: AnalysisContext): ExtractedRequest[] {
    return [...context.requests];
}
