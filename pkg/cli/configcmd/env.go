package configcmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// EnvView is one `config env` row.
type EnvView struct {
	Name         string `json:"name"`
	Set          bool   `json:"set"`
	Value        string `json:"value,omitempty"`
	Redacted     bool   `json:"redacted"`
	Sensitive    bool   `json:"sensitive"`
	OverridesKey string `json:"overrides_key,omitempty"`
	Template     bool   `json:"template,omitempty"`
	Description  string `json:"description"`
}

func newEnvCmd(deps Deps) *cobra.Command {
	var showSecrets, setOnly bool
	cmd := &cobra.Command{
		Use:   "env [filter]",
		Short: "List the VIGOLIUM_* environment variables the binary reads",
		Long: "List every VIGOLIUM_* environment variable this binary reads, whether it is set in this shell, its value " +
			"(credentials redacted unless --show-secrets), the settings key it overrides, and what it does. " +
			"Variables marked template are read through a ${NAME} placeholder in the generated config file.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filter := ""
			if len(args) == 1 {
				filter = strings.ToUpper(strings.TrimSpace(args[0]))
			}
			if showSecrets {
				fmt.Fprintf(os.Stderr, "%s Revealing sensitive environment values in plaintext.\n", terminal.WarningSymbol())
			}
			rows := make([]EnvView, 0, len(config.EnvRegistry))
			for _, e := range config.EnvSettings() {
				if filter != "" && !strings.Contains(e.Name, filter) {
					continue
				}
				if setOnly && !e.Set {
					continue
				}
				v := EnvView{
					Name: e.Name, Set: e.Set, Value: e.Value, Sensitive: e.Sensitive,
					OverridesKey: e.OverridesKey, Template: e.Template, Description: e.Description,
				}
				if e.Sensitive && !showSecrets && e.Value != "" {
					v.Value, v.Redacted = clicommon.SecretPlaceholder, true
				}
				rows = append(rows, v)
			}
			if deps.jsonRequested() {
				return deps.WriteJSON(cmd, "", rows, len(rows), map[string]any{"redacted": !showSecrets})
			}
			for _, r := range rows {
				state := terminal.Gray("unset")
				if r.Set {
					state = terminal.Green("= ") + r.Value
				}
				fmt.Printf("%s %s\n    %s\n", terminal.Cyan(r.Name), state, terminal.Gray(r.Description))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "Reveal sensitive values in plaintext instead of [redacted]")
	cmd.Flags().BoolVar(&setOnly, "set", false, "List only the variables set in this environment")
	return cmd
}
