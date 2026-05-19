package tool

// RegisterBuiltins populates a Registry with every tool olium ships by default.
// approve is used only for the bash tool's rm -rf guard; other tools run
// without gating per the M2 permission policy.
func RegisterBuiltins(r *Registry, approve ApprovalFn) {
	r.Register(NewBash(approve))
	r.Register(NewReadFile())
	r.Register(NewWriteFile())
	r.Register(NewEditFile())
	r.Register(NewLs())
	r.Register(NewGrep())
	r.Register(NewGlob())
	r.Register(NewWebFetch())
	r.Register(NewBrowserProbe())
}
