/**
 * @name TOCTOU: EvalSymlinks called twice on same path (fileDigestMap)
 * @description Finds call sites of filepath.EvalSymlinks in parser/parser.go
 *              to confirm the double-resolution pattern in fileDigestMap / digestForFile.
 * @kind problem
 * @id ollama/toctou-evalsymlinks
 */

import go

from CallExpr call, Function fn
where
  fn.hasQualifiedName("path/filepath", "EvalSymlinks") and
  call.getTarget() = fn and
  call.getFile().getRelativePath().matches("%parser/parser.go%")
select call,
  "EvalSymlinks call in " + call.getFile().getRelativePath() + ":" + call.getLocation().getStartLine().toString()
