package utils

import (
	"errors" // For IllegalStateException
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// --- Static char arrays for random string generation ---
var (
	alphaChars          = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	lowercaseChars      = []rune("abcdefghijklmnopqrstuvwxyz")
	lowercaseDigitChars = []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	alphanumericChars   = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
	digits1To9Chars     = []rune("123456789")
)

// RandomGenerator provides random string, byte, and integer generation.
type RandomGenerator struct {
	randomSource *rand.Rand
}

// NewRandomGenerator creates a new RandomGenerator with a time-based seed.
func NewRandomGenerator() *RandomGenerator {
	return &RandomGenerator{
		randomSource: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// NewRandomGeneratorWithSource creates a new RandomGenerator with a specific rand.Source.
func NewRandomGeneratorWithSource(source rand.Source) *RandomGenerator {
	return &RandomGenerator{
		randomSource: rand.New(source),
	}
}

// NewRandomGeneratorWithFixedSeed is a convenience function for tests
// to get a RandomGenerator with a predictable seed.
func NewRandomGeneratorWithFixedSeed(seed int64) *RandomGenerator {
	return NewRandomGeneratorWithSource(rand.NewSource(seed))
}

// IsRandomGenerator is a marker method.
func (ou *RandomGenerator) IsRandomGenerator() {}

// This specific method 'GeneratePrefixedAlphanumeric' matches one of the requested preserved names.
func (ou *RandomGenerator) GeneratePrefixedAlphanumeric(length int) string {
	// n7 var2 = this.b(); -> builder1 := ou.B_n7()
	// n7 var3 = this.b(); -> builder2 := ou.B_n7()
	// return var2.e().a(1) + var3.b().a(Math.max(var1 - 1, 4));
	// var2.e() sets charset to o5jChars (lowercase)
	// var3.b() sets charset to o5cChars (lowercase + digits)

	builder1 := ou.GetStringBuilder()
	firstChar := builder1.WithLowercaseChars().Build(1) // E_useLowercase corresponds to n7.e()

	builder2 := ou.GetStringBuilder()
	remainingLength := length - 1
	if remainingLength < 4 {
		if length <= 0 { // handle case where length is 0 or 1, avoid negative in Max
			remainingLength = 0 // if length is 1, remaining should be 0. if length is 0, also 0.
			if length == 1 {    // if original length is 1, only firstChar is needed
				return firstChar
			}
			// if original length is 0, result is empty string
			if length == 0 {
				return ""
			}
		} else {
			remainingLength = 4 // Math.max(var1-1, 4)
		}
	}

	restOfChars := builder2.WithLowercaseDigitChars().
		Build(remainingLength)
		// B_useLowercaseDigits corresponds to n7.b()

	return firstChar + restOfChars
}

// GetRandomNumericString - this method was requested to be kept but is not in original ou/o5.
// Implementing a basic version using N1Builder.
func (ou *RandomGenerator) GetRandomNumericString(min, max int) string {
	if min > max {
		// Or handle error appropriately
		return ""
	}
	n1b := ou.GetIntBuilder()
	if min > 0 { // n1.a(min) requires min >=0
		n1b.WithMin(min)
	}
	n1b.WithMax(max)
	num := n1b.Build()
	return fmt.Sprintf("%d", num)
}

func (ou *RandomGenerator) GetStringBuilder() *StringBuilder {
	return newStringBuilder(ou)
}

func (ou *RandomGenerator) GetBytesBuilder() *BytesBuilder {
	return newBytesBuilder(ou)
}

func (ou *RandomGenerator) GetIntBuilder() *IntBuilder {
	return newIntBuilder(ou)
}

func (ou *RandomGenerator) GetInt64Builder() *Int64Builder {
	return newInt64Builder(ou)
}

type StringBuilder struct {
	parentOu *RandomGenerator
	used     bool
	charSet  []rune
}

func newStringBuilder(parent *RandomGenerator) *StringBuilder {
	return &StringBuilder{parentOu: parent, used: false, charSet: nil}
}

func (n7b *StringBuilder) Build(length int) string {
	if n7b.used {
		panic(errors.New("IllegalStateException: Cannot re-use N7Builder"))
	}
	if n7b.charSet == nil {
		panic(errors.New("IllegalStateException: No character set provided for N7Builder"))
	}
	if length <= 0 {
		panic(errors.New("IllegalStateException: Length must be greater than zero for N7Builder"))
	}
	n7b.used = true

	var sb strings.Builder
	sb.Grow(length)
	charSetLen := len(n7b.charSet)

	for i := 0; i < length; i++ {
		sb.WriteRune(n7b.charSet[n7b.parentOu.randomSource.Intn(charSetLen)])
	}
	return sb.String()
}

// WithAlphaChars sets charset to lowercase and uppercase letters.
func (n7b *StringBuilder) WithAlphaChars() *StringBuilder {
	return n7b.WithCharSet(alphaChars)
}

// WithLowercaseChars sets charset to lowercase letters.
func (n7b *StringBuilder) WithLowercaseChars() *StringBuilder {
	return n7b.WithCharSet(lowercaseChars)
}

// WithLowercaseDigitChars sets charset to lowercase letters and digits.
func (n7b *StringBuilder) WithLowercaseDigitChars() *StringBuilder {
	return n7b.WithCharSet(lowercaseDigitChars)
}

// WithAlphanumericChars sets charset to all alphanumeric characters.
func (n7b *StringBuilder) WithAlphanumericChars() *StringBuilder {
	return n7b.WithCharSet(alphanumericChars)
}

// WithDigits1To9Chars sets charset to digits 1-9.
func (n7b *StringBuilder) WithDigits1To9Chars() *StringBuilder {
	return n7b.WithCharSet(digits1To9Chars)
}

func (n7b *StringBuilder) WithCharSet(chars []rune) *StringBuilder {
	if n7b.charSet != nil {
		panic(errors.New("IllegalStateException: Characters specified already for N7Builder"))
	}
	n7b.charSet = chars
	return n7b
}

type BytesBuilder struct {
	parentOu *RandomGenerator
	used     bool
}

func newBytesBuilder(parent *RandomGenerator) *BytesBuilder {
	return &BytesBuilder{parentOu: parent, used: false}
}

func (c1b *BytesBuilder) Build(length int) []byte {
	if c1b.used {
		panic(errors.New("IllegalStateException: Cannot re-use C1Builder"))
	}
	c1b.used = true
	// If length is negative, make will panic.
	if length < 0 {
		panic(errors.New("IllegalStateException: Length cannot be negative for C1Builder"))
	}

	bytes := make([]byte, length)
	_, err := c1b.parentOu.randomSource.Read(bytes) // Fills the slice with random bytes
	if err != nil {
		// This should ideally not happen with rand.Rand from math/rand
		panic(fmt.Errorf("error reading random bytes for C1Builder: %w", err))
	}
	return bytes
}

type IntBuilder struct {
	parentOu *RandomGenerator
	used     bool
	min      *int // Using pointers to distinguish between not set and set to 0
	max      *int
}

func newIntBuilder(parent *RandomGenerator) *IntBuilder {
	return &IntBuilder{parentOu: parent, used: false, min: nil, max: nil}
}

func (n1b *IntBuilder) Build() int {
	if n1b.used {
		panic(errors.New("IllegalStateException: Cannot re-use N1Builder"))
	}
	n1b.used = true

	if n1b.max != nil && n1b.min != nil &&
		*n1b.min >= *n1b.max { //
		panic(
			errors.New("IllegalStateException: Maximum must be greater than minimum for N1Builder"),
		)
	}

	minValue := 0
	if n1b.min != nil {
		minValue = *n1b.min
	}

	maxValue := int(^uint(0) >> 1) // MaxInt
	if n1b.max != nil {
		maxValue = *n1b.max
	}

	if minValue == 0 &&
		maxValue == int(^uint(0)>>1) { // Corresponds to (this.d == null && this.a == null)
		return n1b.parentOu.randomSource.Int()
	}

	// Effective range for Intn: [0, n), offset by minValue.

	n := maxValue - minValue
	if n <= 0 { // This case can happen if max == min, or max < min (already checked above for min >= max)
		// If max == min, return min. rand.Intn(0) panics so handle it explicitly.
		if n == 0 {
			return minValue
		}
		panic(
			errors.New(
				"IllegalStateException: Invalid range for N1Builder (max must be > min for random generation if both are set)",
			),
		)
	}

	return n1b.parentOu.randomSource.Intn(n) + minValue
}

func (n1b *IntBuilder) WithMax(val int) *IntBuilder {
	if n1b.max != nil {
		panic(errors.New("IllegalStateException: Maximum specified already for N1Builder"))
	}
	n1b.max = &val
	return n1b
}

func (n1b *IntBuilder) WithMin(val int) *IntBuilder {
	if n1b.min != nil {
		panic(errors.New("IllegalStateException: Minimum specified already for N1Builder"))
	}
	if val < 0 || val == int(^uint(0)>>1) {
		panic(
			errors.New(
				"IllegalStateException: minInclusive must be in the range 0 <= x < Integer.MAX_VALUE for N1Builder",
			),
		)
	}
	n1b.min = &val
	return n1b
}

type Int64Builder struct {
	parentOu *RandomGenerator
	used     bool
	min      *int64
	max      *int64
}

func newInt64Builder(parent *RandomGenerator) *Int64Builder {
	return &Int64Builder{parentOu: parent, used: false, min: nil, max: nil}
}

func (q9b *Int64Builder) Build() int64 {
	if q9b.used {
		panic(errors.New("IllegalStateException: Cannot re-use Q9Builder"))
	}
	q9b.used = true

	if q9b.max != nil && q9b.min != nil &&
		*q9b.min >= *q9b.max { //
		panic(
			errors.New("IllegalStateException: Maximum must be greater than minimum for Q9Builder"),
		)
	}

	minValue := int64(0)
	if q9b.min != nil {
		minValue = *q9b.min
	}

	maxValue := int64(^uint64(0) >> 1) // MaxInt64
	if q9b.max != nil {
		maxValue = *q9b.max
	}

	if q9b.min == nil && q9b.max == nil { // Corresponds to (this.c == null && this.b == null)
		return q9b.parentOu.randomSource.Int63() // Int63 gives non-negative long
	}

	// Logic from q9.a() and private a(long bound)
	// var2 (bound) = this.b != null ? this.b : Long.MAX_VALUE;
	// if (this.c != null) { var2 -= this.c; }
	// var4 (result) = ... a(var2) ...
	// if (this.c != null) { var4 += this.c; }

	bound := maxValue - minValue
	if bound <= 0 { // Can happen if max == min
		if bound == 0 {
			return minValue
		}
		panic(
			errors.New(
				"IllegalStateException: Invalid range for Q9Builder (max must be > min if both are set)",
			),
		)
	}

	return q9b.a_randomLongWithBound(bound) + minValue
}

// a_randomLongWithBound generates a random int64 in [0, bound).
// var1 is 'bound' (exclusive upper bound for random number, starting from 0).
func (q9b *Int64Builder) a_randomLongWithBound(bound int64) int64 {
	if bound <= 0 {
		panic(
			errors.New(
				"IllegalArgumentException: bound must be positive for Q9Builder random long generation",
			),
		)
	}
	return q9b.parentOu.randomSource.Int63n(bound)
}

// Note: Setters for min/max on Q9Builder (WithMax, A_min_long) would be analogous to N1Builder if needed.
// WithMax sets the maximum value (exclusive).
func (q9b *Int64Builder) WithMax(val int64) *Int64Builder {
	if q9b.max != nil {
		panic(errors.New("IllegalStateException: Maximum specified already for Q9Builder"))
	}
	q9b.max = &val
	return q9b
}

// WithMin sets the minimum value (inclusive).
func (q9b *Int64Builder) WithMin(val int64) *Int64Builder {
	if q9b.min != nil {
		panic(errors.New("IllegalStateException: Minimum specified already for Q9Builder"))
	}
	q9b.min = &val
	return q9b
}
