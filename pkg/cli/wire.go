package cli

import "github.com/vigolium/vigolium/pkg/cli/configcmd"

// wire.go registers command groups that have been extracted into their own
// subpackages. Unlike the legacy in-package commands (which self-register via
// init() onto rootCmd), subpackaged groups expose an explicit constructor and
// receive their dependencies here, where the CLI's global flag state lives.
//
// As more groups move out of the flat pkg/cli package they should be wired the
// same way, until rootCmd's children are assembled entirely from explicit
// constructors and the per-file init() registrations are gone.
func init() {
	rootCmd.AddCommand(configcmd.NewCommand(
		configcmd.Deps{
			ConfigFlag:   func() string { return globalConfig },
			Force:        func() bool { return globalForce },
			Reinitialize: initializeVigolium,
		},
		configcmd.Examples{
			Parent: configExamples,
			Ls:     configLsExamples,
			Set:    configSetExamples,
			Clean:  configCleanExamples,
		},
	))
}
