export interface ExtractedRequest {
  type: 'extractedRequest';
  url: string;
  method: string;
  params: string;
  body: string;
  headers: string[];
  cookies: string[];
}

/**
 * Map of variable names to their resolved values.
 * Values are stored as arrays to support multiple values (e.g., from conditionals).
 */
export type TrackedVariableMap = Record<string, string[]>;

/**
 * Context for resolving values within a function
 */
export interface ResolutionContext {
  /** Current function we're in: "CommentsService.getComments" */
  currentFunction?: string;
  /** Index of call site to use for parameter resolution */
  callSiteIndex?: number;
  /** Index of parent function's call site (for nested resolution) */
  parentCallSiteIndex?: number;
}
