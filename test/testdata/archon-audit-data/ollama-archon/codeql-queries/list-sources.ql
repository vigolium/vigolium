/**
 * @name Ollama - Source Enumeration (Entry Points)
 * @description Enumerate all recognized remote flow sources, local user inputs,
 *              and environment variable sources in the Ollama codebase.
 *              Used for Sub-step 4.1 structural extraction.
 * @kind problem
 * @problem.severity recommendation
 * @id go/ollama/source-enumeration
 * @tags source-enumeration structural
 */

import go
import semmle.go.security.FlowSources

from RemoteFlowSource src
select src, "Remote flow source at " + src.getFile().getRelativePath() + ":" + src.getStartLine().toString() + " [" + src.toString() + "]"
