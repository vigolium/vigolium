import type { NodePath } from '@babel/traverse';
import type * as t from '@babel/types';
import { createHash } from 'node:crypto';
import type { TracebackResult } from '../traceback/tracebackVariables';
import type { ExtractedRequest } from './types';

const checksums: Set<string> = new Set();
const MAX_CODE_LENGTH = 5000;

function generateChecksum(code: string): string {
    const hash = createHash('sha256');
    hash.update(code);
    return hash.digest('hex');
}

export function appendPattern(result: TracebackResult, patternType: string) {
    if (result.code === '' || result.code.length > MAX_CODE_LENGTH) {
        return;
    }
    const checksum = generateChecksum(result.code);

    if (!checksums.has(checksum)) {
        checksums.add(checksum);

        const newPattern = {
            type: 'requestPattern',
            patternType: patternType,
            code: result.code,
            functionName: result.functionName,
            paramCount: result.paramCount,
            literals: result.literals,
            callSites: result.callSites,
            tracedVariables: [...result.tracedVariables]
        };

        console.log(JSON.stringify(newPattern));
    }
}

const API_KEYWORDS = ['api', 'v1', 'v2', 'rest', 'graphql', 'endpoint'];
const FILE_EXTENSIONS = ['.aspx', '.php', '.jsp', '.cgi', '.json', '.xml', '.do', '.action', '.svc', '.asmx'];

export function isURLLike(value: string): boolean {
    const countOccurrences = (str: string, char: string) =>
        (str.match(new RegExp(char, 'g')) || []).length;

    // Phải có ít nhất 1 chữ cái
    if (!/[a-zA-Z]/.test(value)) return false;

    // Loại trừ HTML tags và patterns không phải URL
    if (value.startsWith('<') || value.endsWith('>')) return false;
    if (value.endsWith('svg')) return false;
    if (value.startsWith('.') || value.startsWith('#')) return false;
    if (value === '/') return false;

    // Loại trừ các scheme đặc biệt
    if (value.startsWith('path://')) return false;
    if (value.startsWith('image://')) return false;
    if (value.startsWith('relative://')) return false;
    if (value === 'http://' || value === 'https://') return false;
    if (value === 'http:' || value === 'https:') return false;

    // Loại trừ các patterns khác
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
            // Xử lý template literal chỉ khi nó không có expressions (quasis.length === 1)
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

const extractedChecksums: Set<string> = new Set();
const extractedRequests: ExtractedRequest[] = [];

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

export function appendExtractedRequest(request: ExtractedRequest) {
    // Skip if URL is empty or just a placeholder
    if (!request.url || request.url === '${unknown}') {
        return;
    }

    // Skip non-HTTP schemes (data:, javascript:, mailto:, etc.)
    if (isNonHttpScheme(request.url)) {
        return;
    }

    // Skip URLs that are purely variable placeholders
    if (isPureVariableUrl(request.url)) {
        return;
    }

    // Skip invalid URLs (false positives like HTTP headers, event names, etc.)
    if (!isValidHttpUrl(request.url)) {
        return;
    }

    // Skip frontend framework configs (React Router, Vue Router, Ionic Router, React components, etc.)
    if (isFrontendFrameworkParams(request.params)) {
        return;
    }

    const checksum = generateChecksum(
        `${normalizeTemplateVars(request.url)}|${request.method}|${normalizeTemplateVars(request.params)}|${normalizeTemplateVars(request.body)}`
    );

    if (!extractedChecksums.has(checksum)) {
        extractedChecksums.add(checksum);
        extractedRequests.push(request);
    }
}

export function getExtractedRequests(): ExtractedRequest[] {
    return [...extractedRequests];
}

export function clearExtractedRequests(): void {
    extractedRequests.length = 0;
    extractedChecksums.clear();
}
