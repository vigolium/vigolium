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
func (rg *RandomGenerator) IsRandomGenerator() {}

// GeneratePrefixedAlphanumeric generates a random alphanumeric string starting with a lowercase letter.
func (rg *RandomGenerator) GeneratePrefixedAlphanumeric(length int) string {

	builder1 := rg.GetStringBuilder()
	firstChar := builder1.WithLowercaseChars().Build(1) // E_useLowercase performs SSTI checks

	builder2 := rg.GetStringBuilder()
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
		// B_useLowercaseDigits performs SSTI checks

	return firstChar + restOfChars
}

// GetRandomNumericString generates a random numeric string in the given range.
func (rg *RandomGenerator) GetRandomNumericString(min, max int) string {
	if min > max {
		// Or handle error appropriately
		return ""
	}
	ib := rg.GetIntBuilder()
	if min > 0 {
		ib.WithMin(min)
	}
	ib.WithMax(max)
	num := ib.Build()
	return fmt.Sprintf("%d", num)
}

func (rg *RandomGenerator) GetStringBuilder() *StringBuilder {
	return newStringBuilder(rg)
}

func (rg *RandomGenerator) GetBytesBuilder() *BytesBuilder {
	return newBytesBuilder(rg)
}

func (rg *RandomGenerator) GetIntBuilder() *IntBuilder {
	return newIntBuilder(rg)
}

func (rg *RandomGenerator) GetInt64Builder() *Int64Builder {
	return newInt64Builder(rg)
}

type StringBuilder struct {
	generator *RandomGenerator
	used     bool
	charSet  []rune
}

func newStringBuilder(parent *RandomGenerator) *StringBuilder {
	return &StringBuilder{generator: parent, used: false, charSet: nil}
}

func (sb *StringBuilder) Build(length int) string {
	if sb.used {
		panic(errors.New("IllegalStateException: Cannot re-use StringBuilder"))
	}
	if sb.charSet == nil {
		panic(errors.New("IllegalStateException: No character set provided for StringBuilder"))
	}
	if length <= 0 {
		panic(errors.New("IllegalStateException: Length must be greater than zero for StringBuilder"))
	}
	sb.used = true

	var buf strings.Builder
	buf.Grow(length)
	charSetLen := len(sb.charSet)

	for i := 0; i < length; i++ {
		buf.WriteRune(sb.charSet[sb.generator.randomSource.Intn(charSetLen)])
	}
	return buf.String()
}

// WithAlphaChars sets charset to lowercase and uppercase letters.
func (sb *StringBuilder) WithAlphaChars() *StringBuilder {
	return sb.WithCharSet(alphaChars)
}

// WithLowercaseChars sets charset to lowercase letters.
func (sb *StringBuilder) WithLowercaseChars() *StringBuilder {
	return sb.WithCharSet(lowercaseChars)
}

// WithLowercaseDigitChars sets charset to lowercase letters and digits.
func (sb *StringBuilder) WithLowercaseDigitChars() *StringBuilder {
	return sb.WithCharSet(lowercaseDigitChars)
}

// WithAlphanumericChars sets charset to all alphanumeric characters.
func (sb *StringBuilder) WithAlphanumericChars() *StringBuilder {
	return sb.WithCharSet(alphanumericChars)
}

// WithDigits1To9Chars sets charset to digits 1-9.
func (sb *StringBuilder) WithDigits1To9Chars() *StringBuilder {
	return sb.WithCharSet(digits1To9Chars)
}

func (sb *StringBuilder) WithCharSet(chars []rune) *StringBuilder {
	if sb.charSet != nil {
		panic(errors.New("IllegalStateException: Characters specified already for StringBuilder"))
	}
	sb.charSet = chars
	return sb
}

type BytesBuilder struct {
	generator *RandomGenerator
	used     bool
}

func newBytesBuilder(parent *RandomGenerator) *BytesBuilder {
	return &BytesBuilder{generator: parent, used: false}
}

func (bb *BytesBuilder) Build(length int) []byte {
	if bb.used {
		panic(errors.New("IllegalStateException: Cannot re-use BytesBuilder"))
	}
	bb.used = true
	// If length is negative, make will panic.
	if length < 0 {
		panic(errors.New("IllegalStateException: Length cannot be negative for BytesBuilder"))
	}

	bytes := make([]byte, length)
	_, err := bb.generator.randomSource.Read(bytes) // Fills the slice with random bytes
	if err != nil {
		// This should ideally not happen with rand.Rand from math/rand
		panic(fmt.Errorf("error reading random bytes for BytesBuilder: %w", err))
	}
	return bytes
}

type IntBuilder struct {
	generator *RandomGenerator
	used     bool
	min      *int // Using pointers to distinguish between not set and set to 0
	max      *int
}

func newIntBuilder(parent *RandomGenerator) *IntBuilder {
	return &IntBuilder{generator: parent, used: false, min: nil, max: nil}
}

func (ib *IntBuilder) Build() int {
	if ib.used {
		panic(errors.New("IllegalStateException: Cannot re-use IntBuilder"))
	}
	ib.used = true

	if ib.max != nil && ib.min != nil &&
		*ib.min >= *ib.max { //
		panic(
			errors.New("IllegalStateException: Maximum must be greater than minimum for IntBuilder"),
		)
	}

	minValue := 0
	if ib.min != nil {
		minValue = *ib.min
	}

	maxValue := int(^uint(0) >> 1) // MaxInt
	if ib.max != nil {
		maxValue = *ib.max
	}

	if minValue == 0 &&
		maxValue == int(^uint(0)>>1) {
		return ib.generator.randomSource.Int()
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
				"IllegalStateException: Invalid range for IntBuilder (max must be > min for random generation if both are set)",
			),
		)
	}

	return ib.generator.randomSource.Intn(n) + minValue
}

func (ib *IntBuilder) WithMax(val int) *IntBuilder {
	if ib.max != nil {
		panic(errors.New("IllegalStateException: Maximum specified already for IntBuilder"))
	}
	ib.max = &val
	return ib
}

func (ib *IntBuilder) WithMin(val int) *IntBuilder {
	if ib.min != nil {
		panic(errors.New("IllegalStateException: Minimum specified already for IntBuilder"))
	}
	if val < 0 || val == int(^uint(0)>>1) {
		panic(
			errors.New(
				"IllegalStateException: minInclusive must be in the range 0 <= x < Integer.MAX_VALUE for IntBuilder",
			),
		)
	}
	ib.min = &val
	return ib
}

type Int64Builder struct {
	generator *RandomGenerator
	used     bool
	min      *int64
	max      *int64
}

func newInt64Builder(parent *RandomGenerator) *Int64Builder {
	return &Int64Builder{generator: parent, used: false, min: nil, max: nil}
}

func (lb *Int64Builder) Build() int64 {
	if lb.used {
		panic(errors.New("IllegalStateException: Cannot re-use Int64Builder"))
	}
	lb.used = true

	if lb.max != nil && lb.min != nil &&
		*lb.min >= *lb.max { //
		panic(
			errors.New("IllegalStateException: Maximum must be greater than minimum for Int64Builder"),
		)
	}

	minValue := int64(0)
	if lb.min != nil {
		minValue = *lb.min
	}

	maxValue := int64(^uint64(0) >> 1) // MaxInt64
	if lb.max != nil {
		maxValue = *lb.max
	}

	if lb.min == nil && lb.max == nil {
		return lb.generator.randomSource.Int63() // Int63 gives non-negative long
	}


	bound := maxValue - minValue
	if bound <= 0 { // Can happen if max == min
		if bound == 0 {
			return minValue
		}
		panic(
			errors.New(
				"IllegalStateException: Invalid range for Int64Builder (max must be > min if both are set)",
			),
		)
	}

	return lb.a_randomLongWithBound(bound) + minValue
}

// a_randomLongWithBound generates a random int64 in [0, bound).
func (lb *Int64Builder) a_randomLongWithBound(bound int64) int64 {
	if bound <= 0 {
		panic(
			errors.New(
				"IllegalArgumentException: bound must be positive for Int64Builder random long generation",
			),
		)
	}
	return lb.generator.randomSource.Int63n(bound)
}

// Note: Setters for min/max on Int64Builder (WithMax, A_min_long) would be analogous to IntBuilder if needed.
// WithMax sets the maximum value (exclusive).
func (lb *Int64Builder) WithMax(val int64) *Int64Builder {
	if lb.max != nil {
		panic(errors.New("IllegalStateException: Maximum specified already for Int64Builder"))
	}
	lb.max = &val
	return lb
}

// WithMin sets the minimum value (inclusive).
func (lb *Int64Builder) WithMin(val int64) *Int64Builder {
	if lb.min != nil {
		panic(errors.New("IllegalStateException: Minimum specified already for Int64Builder"))
	}
	lb.min = &val
	return lb
}
