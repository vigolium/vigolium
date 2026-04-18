/**
 * @name GGUF array count uint64-to-int overflow
 * @description readGGUFArray casts a uint64 array count to int without
 *              overflow protection. Values > math.MaxInt wrap negative,
 *              causing panic in make(). Matches CWE-190 / CVE-2025-1975 pattern.
 * @kind problem
 * @problem.severity error
 * @id ollama/gguf-array-count-overflow
 * @tags security correctness
 */

import go

from CallExpr call, ConversionExpr conv, DataFlow::Node source, DataFlow::Node sink
where
  // Find readGGUF[uint64] calls
  call.getTarget().getName() = "readGGUF" and
  call.getTarget().getATypeArgument().toString() = "uint64" and
  // The result flows into int() conversion
  source.asExpr() = call and
  sink.asExpr() = conv and
  conv.getType().getUnderlyingType().(NumericType).getName() = "int" and
  DataFlow::localFlow(source, sink)
select conv,
  "GGUF uint64 array count cast to int without overflow check at " +
  conv.getLocation().toString() +
  ". Values > math.MaxInt wrap negative, causing panic in make()."
