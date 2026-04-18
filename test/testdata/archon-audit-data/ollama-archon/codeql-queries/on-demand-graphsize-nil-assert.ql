/**
 * @name GraphSize nil type assertion on KV map lookup
 * @description Finds type assertions on map index expressions (potential nil-assert panic)
 *              in fs/ggml/ggml.go GraphSize function.
 * @kind problem
 * @id ollama/graphsize-nil-assert
 */

import go

from TypeAssertExpr ta, IndexExpr idx
where
  ta.getExpr() = idx and
  ta.getFile().getRelativePath().matches("%fs/ggml/ggml.go%")
select ta,
  "Type assertion on map index at " + ta.getFile().getRelativePath() + ":" + ta.getLocation().getStartLine().toString()
