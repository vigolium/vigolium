package provider

// secret wraps a credential string with formatter-safe stringification so a
// stray `%v` / `%+v` / `%#v` on a Provider value can never leak the raw
// key. Use Reveal() at the exact moment the value needs to land in an
// outgoing HTTP header — anywhere else, prefer the formatter-safe forms.
//
// String() returns the same placeholder used by the rest of the redaction
// stack (`<redacted>`) so an operator can grep across server, audit, and
// olium logs for one literal.
type secret string

const secretStringHidden = "<redacted>"

// String hides the underlying value. Triggered by `%s`, `%v`, and a
// zero-value `%v` via the fmt.Stringer interface.
func (s secret) String() string { return secretStringHidden }

// GoString hides the value under `%#v` too, which the default Go syntax
// would otherwise expand to the raw quoted string.
func (s secret) GoString() string { return secretStringHidden }

// Reveal returns the raw value. Callers should use this *only* when
// emitting the credential into an outbound network request — never in a
// log, error message, or persisted record.
func (s secret) Reveal() string { return string(s) }

// IsZero reports whether the secret is the empty string. Useful for the
// "no key configured" branch in provider constructors.
func (s secret) IsZero() bool { return s == "" }
