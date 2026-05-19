package jsext

import (
	"time"

	"github.com/grafana/sobek"
	"github.com/pquerna/otp/totp"
)

const totpPeriod = 30

// totpUtilsFuncDefs returns JSFuncDef entries for TOTP utilities.
func totpUtilsFuncDefs() []JSFuncDef {
	return []JSFuncDef{
		{
			Namespace: NsUtils, Name: "totpCode",
			Category: CatEncoding, Signature: ".totpCode(secret: string)", Returns: "TOTPResult",
			Description: "Generate a TOTP code from a base32-encoded secret (RFC 6238). Returns {code, expires_in}.",
			Example:     exTOTPCode,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					secret := call.Argument(0).String()
					if secret == "" {
						return sobek.Null()
					}

					now := time.Now()
					code, err := totp.GenerateCode(secret, now)
					if err != nil {
						return sobek.Null()
					}

					expiresIn := totpPeriod - int(now.Unix()%int64(totpPeriod))

					result := vm.NewObject()
					_ = result.Set("code", code)
					_ = result.Set("expires_in", expiresIn)
					return result
				}
			},
		},
	}
}
