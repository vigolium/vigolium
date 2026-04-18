/**
 * @name Ollama - Sink Enumeration
 * @description Enumerate all recognized security-relevant sinks: file operations,
 *              exec calls, template execution, and HTTP request sinks.
 *              Used for Sub-step 4.1 structural extraction.
 * @kind problem
 * @problem.severity recommendation
 * @id go/ollama/sink-enumeration
 * @tags sink-enumeration structural
 */

import go

from DataFlow::CallNode call, string kind
where
  // File-access sinks
  (
    call.getTarget().hasQualifiedName("os", ["Create", "OpenFile", "Open", "WriteFile", "MkdirAll"]) and
    kind = "file-access"
  )
  or
  // Command execution sinks
  (
    call.getTarget().hasQualifiedName("os/exec", ["Command", "CommandContext"]) and
    kind = "command-execution"
  )
  or
  // io.ReadAll - memory allocation via unbounded read
  (
    call.getTarget().hasQualifiedName("io", "ReadAll") and
    kind = "memory-allocation-readall"
  )
  or
  // JSON unmarshal sinks
  (
    call.getTarget().hasQualifiedName("encoding/json", ["Unmarshal", "NewDecoder"]) and
    kind = "deserialization"
  )
  or
  // filepath.Join - path construction (potential path traversal)
  (
    call.getTarget().hasQualifiedName("path/filepath", "Join") and
    kind = "path-construction"
  )
  or
  // binary.Read - length-prefix reads from untrusted streams
  (
    call.getTarget().hasQualifiedName("encoding/binary", "Read") and
    kind = "binary-read-length-prefix"
  )
select call, kind + " sink at " + call.getFile().getRelativePath() + ":" + call.getStartLine().toString()
