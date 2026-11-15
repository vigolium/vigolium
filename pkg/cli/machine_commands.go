package cli

// MachineContractCommands returns every runnable command path (without the
// root name; "" is the root) and the kind of -j output it declares: read,
// mutation, scan, stream or interactive.
//
// It is a view of commandTraits (command_traits.go), which TestMachineContractCobraTree keeps
// equal to the runnable command tree. Exported for the runtime smoke matrix
// (test/e2e/machine_contract_e2e_test.go), which must cover every leaf and
// cannot reach the cobra tree from outside the package.
func MachineContractCommands() map[string]string {
	out := make(map[string]string, len(machineKinds))
	for path, kind := range machineKinds {
		out[path] = string(kind)
	}
	return out
}

// ShapedCommands returns every command whose -j document can be narrowed with
// --fields, and its shape: "rows" or "object". The e2e contract matrix runs
// each with an unknown --fields name and expects a usage error (exit 2).
func ShapedCommands() map[string]string {
	out := map[string]string{}
	for path, t := range commandTraits {
		if t.Shape.Kind == shapeRows || t.Shape.Kind == shapeObject {
			out[path] = string(t.Shape.Kind)
		}
	}
	return out
}
