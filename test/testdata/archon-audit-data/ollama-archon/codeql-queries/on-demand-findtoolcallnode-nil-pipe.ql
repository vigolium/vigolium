/**
 * @name findToolCallNode dereferences n.Pipe without nil check
 * @description Finds field accesses on Pipe inside findToolCallNode in tools/template.go
 *              to confirm the nil-pipe dereference risk.
 * @kind problem
 * @id ollama/findtoolcallnode-nil-pipe
 */

import go

from SelectorExpr sel
where
  sel.getSelector().getName() = "Cmds" and
  sel.getBase().(SelectorExpr).getSelector().getName() = "Pipe" and
  sel.getFile().getRelativePath().matches("%tools/template.go%")
select sel,
  "n.Pipe.Cmds dereference (no nil check) at tools/template.go:" + sel.getLocation().getStartLine().toString()
