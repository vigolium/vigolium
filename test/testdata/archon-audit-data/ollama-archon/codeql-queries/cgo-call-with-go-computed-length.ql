/**
 * @name Ollama - cgo call with Go-computed length from user input
 * @description Detects C function calls via cgo where unsafe.Pointer or C-type
 *              size casts reference Go slices from user input without bounds checking.
 *              Known positives: llama/llama.go image→mtmd, modelPath→CString.
 *              CVE class: CVE-2025-15514 (mtmd null deref), Sonar-OOB-2025 (mllama OOB write).
 *              DFD: DFD-6 (multimodal image → cgo → C heap).
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @id go/ollama/cgo-call-with-go-computed-length
 * @tags security cgo
 *       external/cwe/cwe-119
 *       external/cwe/cwe-125
 *       external/cwe/cwe-787
 */

import go

from DataFlow::CallNode call, DataFlow::CallNode sizeExpr
where
  // calls in the "C" pseudo-package (cgo)
  call.getTarget().getPackage().getName() = "C" and
  // one of the arguments is a len() or cap() call
  exists(int i |
    sizeExpr = call.getArgument(i) and
    (
      sizeExpr.getCalleeName() = "len" or
      sizeExpr.getCalleeName() = "cap"
    )
  )
select call,
  "cgo call to C." + call.getCalleeName() +
  "() at " + call.getFile().getRelativePath() + ":" + call.getStartLine().toString() +
  " passes Go-computed len()/cap() — verify C function validates bounds independently."
