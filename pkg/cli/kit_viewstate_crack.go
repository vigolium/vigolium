package cli

import (
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/modules/shared/viewstateutil"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	kitViewStateGenerator   string
	kitViewStateKeys        []string
	kitViewStateFailOnCrack bool
)

var kitViewStateCrackCmd = &cobra.Command{
	Use:   "viewstate-crack [viewstate|-]",
	Short: "Check an ASP.NET ViewState's MAC against published machineKeys",
	Long: `Recompute an ASP.NET __VIEWSTATE's MAC, offline, under every published
machineKey validation key in the embedded aspnet.machinekeys.list (plus any
--validation-key), with each legacy validation algorithm (SHA1, which AES and 3DES
validation also use, and HMACSHA256/384/512). A match means anyone can sign a
ViewState the server accepts.

  vigolium kit viewstate-crack --generator CA0B0334 /wEPDwUK...
  echo "$VS" | vigolium kit viewstate-crack -g CA0B0334 -
  vigolium kit viewstate-crack -g CA0B0334 --validation-key D61B3C89... -j --fail-on-crack /wEPDwUK...

--generator is the page's __VIEWSTATEGENERATOR value, the modifier the MAC
covers. Only the legacy (pre-4.5) MAC is checked: a 4.5+ purpose-based MAC,
MD5 validation, a page with a ViewStateUserKey and an encrypted ViewState are
not, so "not cracked" never proves the key is private. The same check runs
passively in the aspnet-viewstate-detect module.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runKitViewStateCrack,
}

func init() {
	f := kitViewStateCrackCmd.Flags()
	f.StringVarP(&kitViewStateGenerator, "generator", "g", "", "The page's __VIEWSTATEGENERATOR value (eight hex digits); required")
	f.StringArrayVar(&kitViewStateKeys, "validation-key", nil, "Additional machineKey validationKey to try, as hex (repeatable)")
	f.BoolVar(&kitViewStateFailOnCrack, "fail-on-crack", false, "Exit 3 when a key reproduces the MAC (for CI/agent gating)")
	kitCmd.AddCommand(kitViewStateCrackCmd)
}

// kitViewStateCrackResult is `kit viewstate-crack -j`'s one item. The key is
// a published one, so a match prints it in full.
type kitViewStateCrackResult struct {
	Cracked bool `json:"cracked"`
	// Serialized is false when the ViewState is not the plain serialized
	// stream (encrypted, or not a ViewState): nothing was checked.
	Serialized    bool   `json:"serialized"`
	Generator     string `json:"generator"`
	Algorithm     string `json:"algorithm,omitempty"`
	ValidationKey string `json:"validation_key,omitempty"`
	KeySource     string `json:"key_source,omitempty"`
	KeysTried     int    `json:"keys_tried"`
	// MACMode names the MAC construction checked: always "legacy".
	MACMode string `json:"mac_mode"`
}

func runKitViewStateCrack(cmd *cobra.Command, args []string) error {
	arg := "-"
	if len(args) == 1 {
		arg = args[0]
	}
	raw := arg
	if arg == "-" {
		data, _, err := kitReadInput("-")
		if err != nil {
			return err
		}
		raw = string(data)
	}
	raw = strings.TrimSpace(raw)
	// A value copied from a request body is URL-encoded ('+', '/', '=').
	if strings.Contains(raw, "%") {
		if unescaped, err := url.QueryUnescape(raw); err == nil {
			raw = unescaped
		}
	}
	decoded, err := viewstateutil.DecodeViewState(raw)
	if err != nil {
		return usageErrorf("input is not a base64 __VIEWSTATE value: %v", err)
	}
	if kitViewStateGenerator == "" {
		return usageErrorf("--generator is required: the page's __VIEWSTATEGENERATOR value")
	}
	modifier, err := viewstateutil.GeneratorModifier(kitViewStateGenerator)
	if err != nil {
		return usageErrorf("%v", err)
	}

	keys, err := kitLoadMachineKeys()
	if err != nil {
		return err
	}
	res := kitViewStateCrackResult{
		Serialized: viewstateutil.IsSerialized(decoded),
		Generator:  strings.ToUpper(kitViewStateGenerator),
		KeysTried:  len(keys),
		MACMode:    "legacy",
	}
	match, ok := viewstateutil.CrackLegacy(decoded, modifier, keys)
	if ok {
		res.Cracked = true
		res.Algorithm = match.Algorithm
		res.ValidationKey = match.Key.Hex()
		res.KeySource = match.Key.Source
	}

	if globalJSON {
		if err := emitObject(cmd, ".", res); err != nil {
			return err
		}
	} else if ok {
		fmt.Printf("%s validationKey %s (%s)\n", terminal.Bold("[cracked]"), res.ValidationKey, res.Algorithm)
		fmt.Fprintf(os.Stderr, "%s source: %s\n", terminal.InfoSymbol(), res.KeySource)
	} else if !res.Serialized {
		fmt.Fprintf(os.Stderr, "%s not checked: the ViewState is not a plain serialized stream (encrypted, or not a ViewState)\n",
			terminal.WarningSymbol())
	} else {
		fmt.Fprintf(os.Stderr, "%s not cracked: %d key(s), legacy MAC only (4.5+ purpose-based MACs are not checked)\n",
			terminal.WarningSymbol(), len(keys))
	}

	if kitViewStateFailOnCrack && ok {
		return asMatchErrorf("--fail-on-crack: a published machineKey reproduces the ViewState MAC")
	}
	return nil
}

// kitLoadMachineKeys is the embedded published-key list plus every --validation-key.
func kitLoadMachineKeys() ([]viewstateutil.MachineKey, error) {
	keys, err := viewstateutil.PublishedKeys()
	if err != nil {
		return nil, err
	}
	// The published list is shared: append --validation-key entries to a copy.
	keys = slices.Clip(keys)
	for _, k := range kitViewStateKeys {
		key, err := viewstateutil.ParseKeyHex(k)
		if err != nil {
			return nil, usageErrorf("--validation-key: %v", err)
		}
		keys = append(keys, viewstateutil.MachineKey{ValidationKey: key, Source: "--validation-key"})
	}
	return keys, nil
}
