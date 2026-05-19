import type { NodePath } from '@babel/traverse';
import type * as t from '@babel/types';
import type { ParseResult } from '@babel/parser';
import { isURLLike } from '../requestpattern/utils';

// ============================================================================
// Types
// ============================================================================

interface TracebackOptions {
  /** Number of context lines per side (default: 15) */
  contextLines?: number;
  /** If line is longer than this = minified code (default: 500) */
  maxLineLength?: number;
  /** Maximum number of call sites (default: 5) */
  maxCallSites?: number;
  /** AST of the file (optional, not used in line-based approach) */
  ast?: ParseResult<t.File> | null;
  /** Source code (optional, if not provided will be read from hub.file.code) */
  sourceCode?: string;
}

interface CallSiteInfo {
  line: number;
  code: string;
}

export interface TracebackResult {
  /** Grep-style formatted code with line numbers */
  code: string;
  /** Name of the function containing the target */
  functionName: string;
  /** Number of function parameters */
  paramCount: number;
  /** Traced variables */
  tracedVariables: Set<string>;
  /** String literals found */
  literals: string[];
  /** Call sites */
  callSites: CallSiteInfo[];
}

interface FunctionInfo {
  name: string;
  paramCount: number;
  startLine: number;
  endLine: number;
}

// ============================================================================
// LineBasedContextExtractor
// ============================================================================

class LineBasedContextExtractor {
  private readonly sourceLines: string[];
  private readonly fileName: string;
  private readonly options: {
    contextLines: number;
    maxLineLength: number;
    maxCallSites: number;
  };

  constructor(
    private readonly startPath: NodePath,
    sourceCode: string,
    options: TracebackOptions = {}
  ) {
    this.sourceLines = sourceCode.split('\n');
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const hub = startPath.hub as any;
    this.fileName = hub?.file?.opts?.filename || 'unknown';
    this.options = {
      contextLines: options.contextLines ?? 15,
      maxLineLength: options.maxLineLength ?? 500,
      maxCallSites: options.maxCallSites ?? 5,
    };
  }

  extract(): TracebackResult {
    // 1. Get line number from AST (using loc only)
    const targetLine = this.getTargetLine();

    // 2. Collect context by line
    const { code: contextCode, startLine, endLine } = this.collectLineContext(targetLine);

    // 3. Find function info
    const funcInfo = this.extractFunctionInfo();

    // 4. Find call sites via text search
    const callSites = funcInfo.name.length >= 2
      ? this.findCallSitesByText(funcInfo.name, targetLine)
      : [];

    // 5. Collect literals from context
    const literals = this.extractLiterals(contextCode);

    // 6. Collect traced variables
    const tracedVariables = this.extractVariables(contextCode);

    // 7. Format output
    const formattedCode = this.formatOutput(
      contextCode,
      startLine,
      endLine,
      targetLine,
      funcInfo,
      callSites,
      literals
    );

    return {
      code: formattedCode,
      functionName: funcInfo.name,
      paramCount: funcInfo.paramCount,
      tracedVariables,
      literals,
      callSites,
    };
  }

  private getTargetLine(): number {
    return this.startPath.node.loc?.start.line || 1;
  }

  private collectLineContext(targetLine: number): { code: string; startLine: number; endLine: number } {
    const { contextLines, maxLineLength } = this.options;

    // Check if minified (single long line)
    const targetLineContent = this.sourceLines[targetLine - 1] || '';
    if (targetLineContent.length > maxLineLength) {
      // Minified: return the whole line as context
      return {
        code: targetLineContent,
        startLine: targetLine,
        endLine: targetLine,
      };
    }

    // Normal: get N lines before and after
    const startLine = Math.max(1, targetLine - contextLines);
    const endLine = Math.min(this.sourceLines.length, targetLine + contextLines);

    const code = this.sourceLines.slice(startLine - 1, endLine).join('\n');
    return { code, startLine, endLine };
  }

  private extractFunctionInfo(): FunctionInfo {
    const defaultInfo: FunctionInfo = { name: '', paramCount: 0, startLine: 0, endLine: 0 };

    try {
      const funcParent = this.startPath.getFunctionParent();
      if (!funcParent?.node) return defaultInfo;

      let name = '';
      let paramCount = 0;

      const node = funcParent.node;

      // Get param count
      if ('params' in node && Array.isArray(node.params)) {
        paramCount = node.params.length;
      }

      // Get function name
      if ('id' in node && node.id && 'name' in node.id) {
        name = node.id.name;
      } else if ('key' in node && node.key && 'name' in node.key) {
        name = node.key.name;
      } else {
        // Try to get name from variable declaration
        const parent = funcParent.parentPath;
        if (parent?.isVariableDeclarator() && 'id' in parent.node && parent.node.id && 'name' in parent.node.id) {
          name = parent.node.id.name;
        } else if (parent?.isAssignmentExpression()) {
          const left = parent.node.left;
          if ('name' in left) {
            name = left.name;
          } else if ('property' in left && left.property && 'name' in left.property) {
            name = left.property.name;
          }
        }
      }

      const startLine = funcParent.node.loc?.start.line || 0;
      const endLine = funcParent.node.loc?.end.line || 0;

      return { name, paramCount, startLine, endLine };
    } catch {
      return defaultInfo;
    }
  }

  private findCallSitesByText(funcName: string, excludeLine: number): CallSiteInfo[] {
    // Escape special regex characters in function name
    const escapedName = funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const pattern = new RegExp(`\\b${escapedName}\\s*\\(`, 'g');
    const sites: CallSiteInfo[] = [];

    for (let i = 0; i < this.sourceLines.length; i++) {
      const lineNum = i + 1;
      const line = this.sourceLines[i];

      // Skip if this is the target line or empty
      if (lineNum === excludeLine || !line.trim()) continue;

      if (pattern.test(line)) {
        // Reset regex lastIndex
        pattern.lastIndex = 0;

        // Get context around call site
        const contextCode = this.getContextAroundLine(lineNum, 2);

        sites.push({
          line: lineNum,
          code: contextCode,
        });

        if (sites.length >= this.options.maxCallSites) break;
      }
    }

    return sites;
  }

  private getContextAroundLine(lineNum: number, contextSize: number): string {
    const start = Math.max(0, lineNum - 1 - contextSize);
    const end = Math.min(this.sourceLines.length, lineNum + contextSize);
    return this.sourceLines.slice(start, end).join('\n');
  }

  private extractLiterals(code: string): string[] {
    const literals: string[] = [];
    const seen = new Set<string>();

    // Match string literals (single and double quotes)
    const stringPattern = /(['"`])(?:(?!\1)[^\\]|\\.)*?\1/g;
    let match;

    while ((match = stringPattern.exec(code)) !== null) {
      const raw = match[0];
      // Remove quotes
      const value = raw.slice(1, -1);

      // Filter out short/useless strings
      if (value.length < 2) continue;
      if (seen.has(value)) continue;

      // Check if looks like URL/API
      if (isURLLike(value)) {
        seen.add(value);
        literals.push(value);
      }
    }

    return literals;
  }

  private extractVariables(code: string): Set<string> {
    const variables = new Set<string>();

    // Match variable declarations
    const varPattern = /\b(const|let|var)\s+(\w+)\s*=/g;
    let match;

    while ((match = varPattern.exec(code)) !== null) {
      variables.add(match[2]);
    }

    return variables;
  }

  private formatOutput(
    contextCode: string,
    startLine: number,
    _endLine: number,
    targetLine: number,
    funcInfo: FunctionInfo,
    callSites: CallSiteInfo[],
    literals: string[]
  ): string {
    const lines: string[] = [];

    // Header
    if (funcInfo.name) {
      lines.push(`TRACEBACK: ${funcInfo.name}(${funcInfo.paramCount} params)`);
    } else {
      lines.push(`TRACEBACK: <anonymous>`);
    }
    lines.push('═'.repeat(60));
    lines.push('');

    // Main context with line numbers
    lines.push('[CONTEXT]');
    lines.push('─'.repeat(60));
    const contextLines = contextCode.split('\n');
    for (let i = 0; i < contextLines.length; i++) {
      const lineNum = startLine + i;
      const separator = lineNum === targetLine ? ':' : '-';
      const paddedNum = String(lineNum).padStart(4);
      lines.push(`${this.fileName}${separator}${paddedNum}${separator}  ${contextLines[i]}`);
    }
    lines.push('');

    // Call sites
    if (callSites.length > 0) {
      lines.push(`[CALL SITES] (${callSites.length} found)`);
      lines.push('─'.repeat(60));
      for (const site of callSites) {
        lines.push(`${this.fileName}:${site.line}:`);
        const siteLines = site.code.split('\n');
        for (const siteLine of siteLines) {
          lines.push(`  ${siteLine}`);
        }
        lines.push('--');
      }
      lines.push('');
    }

    // Literals
    if (literals.length > 0) {
      lines.push('[LITERALS FOUND]');
      lines.push('─'.repeat(60));
      for (const lit of literals) {
        lines.push(`• "${lit}"`);
      }
    }

    return lines.join('\n');
  }
}

// ============================================================================
// Export
// ============================================================================

export { LineBasedContextExtractor as VariableTracer };

export const tracebackVariables = (
  path: NodePath,
  _variablesToTrack?: string[], // Deprecated, kept for compatibility
  options?: TracebackOptions
): TracebackResult => {
  // Get source code from options or from path
  let sourceCode = options?.sourceCode || '';
  if (!sourceCode) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const hub = path.hub as any;
    sourceCode = hub?.file?.code || '';
  }

  if (!sourceCode) {
    // Fallback: return minimal result
    return {
      code: '',
      functionName: '',
      paramCount: 0,
      tracedVariables: new Set(),
      literals: [],
      callSites: [],
    };
  }

  const extractor = new LineBasedContextExtractor(path, sourceCode, options);
  return extractor.extract();
};
