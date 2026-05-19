package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/spf13/cobra"
)

const totpPeriod = 30

var (
	totpSecret string
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authentication management utilities",
	Long:  "Manage authentication configurations and helpers used by scans (cookie/header/login flows). Subcommands list, load, and lint auth config files, and a totp helper generates RFC 6238 codes for 2FA flows.",
}

var sessionTotpCmd = &cobra.Command{
	Use:   "totp",
	Short: "Generate a TOTP code from a base32 secret",
	Long: `Generate a time-based one-time password (RFC 6238) from a base32-encoded secret.
Useful for automating 2FA login flows during authenticated scanning.

Output is JSON: {"code": "123456", "expires_in": 18}`,
	RunE: runSessionTotp,
}

func init() {
	rootCmd.AddCommand(authCmd)
	authCmd.AddCommand(sessionTotpCmd)
	sessionTotpCmd.Flags().StringVar(&totpSecret, "secret", "", "Base32-encoded TOTP secret (required)")
	_ = sessionTotpCmd.MarkFlagRequired("secret")
}

func runSessionTotp(_ *cobra.Command, _ []string) error {
	now := time.Now()
	code, err := totp.GenerateCode(totpSecret, now)
	if err != nil {
		return fmt.Errorf("failed to generate TOTP code: %w", err)
	}

	expiresIn := totpPeriod - int(now.Unix()%int64(totpPeriod))

	out, _ := json.Marshal(struct {
		Code      string `json:"code"`
		ExpiresIn int    `json:"expires_in"`
	}{
		Code:      code,
		ExpiresIn: expiresIn,
	})

	fmt.Println(string(out))
	return nil
}
