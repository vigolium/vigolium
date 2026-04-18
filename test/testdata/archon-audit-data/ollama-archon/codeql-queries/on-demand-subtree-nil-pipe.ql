/**
 * @name Subtree produces tree passed to tools.NewParser without nil-pipe validation
 * @description Finds calls to Subtree in template/template.go and calls to
 *              tools.NewParser in server/ to confirm the handoff path.
 * @kind problem
 * @id ollama/subtree-nil-pipe
 */

import go

from CallExpr call
where
  (
    call.getTarget().getName() = "Subtree" or
    call.getTarget().getName() = "NewParser"
  ) and
  (
    call.getFile().getRelativePath().matches("%template/template.go%") or
    call.getFile().getRelativePath().matches("%server/routes.go%") or
    call.getFile().getRelativePath().matches("%tools/%")
  )
select call,
  call.getTarget().getName() + " called at " + call.getFile().getRelativePath() + ":" + call.getLocation().getStartLine().toString()
