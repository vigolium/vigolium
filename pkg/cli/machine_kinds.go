package cli

// machineKinds declares, for every runnable command, the kind of -j output it
// owes (see machine.go). Keyed by cobra path without the root name; "" is the
// root itself.
//
// One table rather than a declaration in each command file: the contract test
// (machine_contract_test.go) walks the finished tree against it, so an added
// command that nobody classified fails there, and the whole surface can be
// reviewed in one place. A declared kind is the TARGET shape; the commands that
// do not produce it yet are listed in that test's knownNonConforming ratchet.
var machineKinds = map[string]machineKind{
	// Help-only groups and cobra's own commands: their output is help text.
	"":         kindInteractive,
	"help":     kindInteractive,
	"kit":      kindInteractive,
	"kit oast": kindInteractive,
	"oast":     kindInteractive,
	// Pure groups: help for a human, a usage error under -j
	// (enforceGroupSubcommands).
	"auth":       kindInteractive,
	"completion": kindInteractive,
	"config":     kindInteractive,
	"db":         kindInteractive,
	"project":    kindInteractive,
	"server ca":  kindInteractive,
	"storage":    kindInteractive,

	"completion bash":       kindInteractive,
	"completion fish":       kindInteractive,
	"completion powershell": kindInteractive,
	"completion zsh":        kindInteractive,

	// TUI, long-running service, passthrough shims, hidden dev generator.
	"agent olium":      kindInteractive,
	"olium":            kindInteractive,
	"server":           kindInteractive,
	"arjun":            kindInteractive,
	"dig":              kindInteractive,
	"host":             kindInteractive,
	"ffuf":             kindInteractive,
	"gau":              kindInteractive,
	"katana":           kindInteractive,
	"nuclei":           kindInteractive,
	"skills gen-flags": kindInteractive,

	// Scans: the single scan document.
	"scan":            kindScan,
	"scan diff":       kindRead,
	"scan status":     kindRead,
	"scan ls":         kindRead,
	"scan stop":       kindMutation,
	"agent cancel":    kindMutation,
	"status":          kindRead,
	"config get":      kindRead,
	"config unset":    kindMutation,
	"scope add":       kindMutation,
	"scope rm":        kindMutation,
	"scope check":     kindRead,
	"auth show":       kindRead,
	"auth rm":         kindMutation,
	"project current": kindRead,
	"project rename":  kindMutation,
	"module show":     kindRead,
	"finding show":    kindRead,
	"server status":   kindRead,
	"server stop":     kindMutation,
	"scan wait":       kindScan, // the finished scan's scan document; --events streams instead
	"run":             kindScan,
	"scan-url":        kindScan,
	"scan-request":    kindScan,
	"agent autopilot": kindScan,
	"agent swarm":     kindScan,
	"agent audit":     kindScan,
	"audit":           kindScan,

	// Agent.
	"agent":         kindRead, // --list-agents / --list-templates / --list-modes
	"agent query":   kindRead,
	"agent session": kindRead,
	"agent triage":  kindMutation,

	// Auth.
	"auth check": kindRead,
	"auth lint":  kindRead,
	"auth list":  kindRead,
	"auth load":  kindMutation,
	"auth totp":  kindRead,

	// Config.
	"config clean":    kindMutation,
	"config env":      kindRead,
	"config ls":       kindRead,
	"config set":      kindMutation,
	"config validate": kindRead,

	// Database.
	"db clean":   kindMutation,
	"db compact": kindMutation,
	"db export":  kindStream,
	"db list":    kindRead,
	"db migrate": kindMutation,
	"db reset":   kindMutation,
	"db seed":    kindMutation,
	"db stats":   kindRead,

	"doctor": kindRead,
	"export": kindStream,

	// Extensions.
	"extensions":         kindRead,
	"extensions docs":    kindRead,
	"extensions eval":    kindRead,
	"extensions example": kindRead,
	"extensions lint":    kindRead,
	"extensions ls":      kindRead,
	"extensions preset":  kindMutation,
	"extensions run":     kindRead,
	"extensions test":    kindRead,
	"extensions types":   kindRead,

	// Findings and traffic.
	"finding":         kindRead,
	"finding load":    kindMutation,
	"finding mark":    kindMutation,
	"finding verify":  kindMutation,
	"traffic":         kindRead,
	"endpoints":       kindRead,
	"params":          kindRead,
	"traffic body":    kindRead,
	"traffic headers": kindRead,
	"fuzz":            kindStream,
	"replay":          kindStream,

	// Input.
	"import": kindMutation,
	"ingest": kindMutation,
	"init":   kindMutation,
	"js":     kindRead,

	// Out-of-band callbacks logged by the operator's endpoint.
	"oast ingest": kindMutation,
	"oast poll":   kindMutation,

	// Kit.
	"kit harvest":     kindRead,
	"kit js-beautify": kindRead,
	"kit jwt-crack":   kindRead,
	"kit oast new":    kindRead,
	"kit oast poll":   kindRead,
	"kit param-mine":  kindRead,
	"kit payload":     kindRead,
	"kit secret-scan": kindRead,
	"kit tmp-clean":   kindMutation,
	"kit wordlist":    kindRead,

	// Logs.
	"log":    kindRead, // bare `log` lists; `log <uuid>` prints a transcript
	"log ls": kindRead,

	// Modules.
	"module":         kindRead,
	"module ls":      kindRead,
	"module enable":  kindMutation,
	"module disable": kindMutation,

	// Projects.
	"project config": kindRead,
	"project create": kindMutation,
	"project delete": kindMutation,
	"project list":   kindRead,
	"project use":    kindMutation,

	// Scope.
	"scope":      kindRead,
	"scope set":  kindMutation,
	"scope view": kindRead,

	// Server MITM CA (the server itself is interactive, above).
	"server ca install":   kindMutation,
	"server ca path":      kindRead,
	"server ca print":     kindRead,
	"server ca uninstall": kindMutation,

	// Skills.
	"skills":         kindRead,
	"skills get":     kindRead,
	"skills install": kindMutation,
	"skills list":    kindRead,

	// Storage.
	"storage download": kindStream,
	"storage ls":       kindRead,
	"storage presign":  kindRead,
	"storage results":  kindMutation,
	"storage rm":       kindMutation,
	"storage upload":   kindMutation,

	// Schemas: the bare JSON Schema owns stdout without -j; -j is an envelope.
	"schema":          kindRead, // bare `schema` lists
	"schema list":     kindRead,
	"schema command":  kindStream,
	"schema event":    kindStream,
	"schema error":    kindStream,
	"schema plan":     kindStream,
	"schema all":      kindStream,
	"schema storage":  kindRead,
	"schema flags":    kindRead,
	"hosts":           kindRead,
	"match-not-found": kindRead,
	"dns":             kindRead,
	"fingerprint":     kindScan,

	"strategy": kindRead,
	"update":   kindMutation,
	"version":  kindRead,
}
