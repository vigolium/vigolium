package utils

import (
	"errors" // For IllegalStateException
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// --- Static char arrays from o5.java ---
var (
	alphaChars          = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	lowercaseChars      = []rune("abcdefghijklmnopqrstuvwxyz")
	lowercaseDigitChars = []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	alphanumericChars   = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
	digits1To9Chars     = []rune("123456789")
)

// --- NetPortswiggerOu (combines ou.java and o5.java logic) ---

// RandomGenerator is the Go equivalent of net.portswigger.ou.java
type RandomGenerator struct {
	randomSource *rand.Rand // Corresponds to 'private final T g;' in o5.java, where T is Random
	// No static fields like 'k' from ou.java are needed for instance logic.
}

// NewRandomGenerator creates a new instance of NetPortswiggerOu.
// Corresponds to 'public ou()' which calls 'super(new Random())'.
func NewRandomGenerator() *RandomGenerator {
	return &RandomGenerator{
		randomSource: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// NewNetPortswiggerOuWithSource creates a new instance of NetPortswiggerOu with a specific rand.Source.
// Useful for testing with a fixed seed.
func NewNetPortswiggerOuWithSource(source rand.Source) *RandomGenerator {
	return &RandomGenerator{
		randomSource: rand.New(source),
	}
}

// NewNetPortswiggerOuWithFixedSeedForTest is a convenience function for tests
// to get an instance of NetPortswiggerOu with a predictable seed.
func NewNetPortswiggerOuWithFixedSeedForTest(seed int64) *RandomGenerator {
	return NewNetPortswiggerOuWithSource(rand.NewSource(seed))
}

// IsRandomGenerator is a marker method.
func (ou *RandomGenerator) IsRandomGenerator() {}

// GeneratePrefixedAlphanumeric (String generation) - Corresponds to 'public String a(int var1)' in o5.java
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

// GetStringBuilder creates an N7Builder. Corresponds to 'public n7 b()' in o5.java.
func (ou *RandomGenerator) GetStringBuilder() *StringBuilder {
	return newStringBuilder(ou)
}

// GetBytesBuilder creates a C1Builder. Corresponds to 'public c1 f()' in o5.java.
func (ou *RandomGenerator) GetBytesBuilder() *BytesBuilder {
	return newBytesBuilder(ou)
}

// GetIntBuilder creates an N1Builder. Corresponds to 'public n1 h()' in o5.java.
func (ou *RandomGenerator) GetIntBuilder() *IntBuilder {
	return newIntBuilder(ou)
}

// GetInt64Builder creates a Q9Builder. Corresponds to 'public q9 i()' in o5.java.
func (ou *RandomGenerator) GetInt64Builder() *Int64Builder {
	return newInt64Builder(ou)
}

// --- StringBuilder (from n7.java) ---
type StringBuilder struct {
	parentOu *RandomGenerator
	used     bool
	charSet  []rune
}

func newStringBuilder(parent *RandomGenerator) *StringBuilder {
	return &StringBuilder{parentOu: parent, used: false, charSet: nil}
}

// Build creates the random string. Corresponds to 'public String a(int var1)' in n7.java
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

// WithAlphaChars sets charset to lowercase and uppercase. Corresponds to 'public n7 c()' in n7.java.
func (n7b *StringBuilder) WithAlphaChars() *StringBuilder {
	return n7b.WithCharSet(alphaChars) // o5eChars is 'e' in o5.java
}

// WithLowercaseChars sets charset to lowercase. Corresponds to 'public n7 e()' in n7.java.
func (n7b *StringBuilder) WithLowercaseChars() *StringBuilder {
	return n7b.WithCharSet(lowercaseChars) // o5jChars is 'j' in o5.java
}

// WithLowercaseDigitChars sets charset to lowercase and digits. Corresponds to 'public n7 b()' in n7.java.
func (n7b *StringBuilder) WithLowercaseDigitChars() *StringBuilder {
	return n7b.WithCharSet(lowercaseDigitChars) // o5cChars is 'c' in o5.java
}

// WithAlphanumericChars sets charset to all alphanumeric. Corresponds to 'public n7 a()' in n7.java.
func (n7b *StringBuilder) WithAlphanumericChars() *StringBuilder {
	return n7b.WithCharSet(alphanumericChars) // o5aChars is 'a' in o5.java
}

// WithDigits1To9Chars sets charset to digits 1-9. Corresponds to 'public n7 d()' in n7.java.
func (n7b *StringBuilder) WithDigits1To9Chars() *StringBuilder {
	return n7b.WithCharSet(digits1To9Chars) // o5iChars is 'i' in o5.java
}

// WithCharSet sets the character set. Corresponds to 'public n7 a(char[] var1)' in n7.java.
func (n7b *StringBuilder) WithCharSet(chars []rune) *StringBuilder {
	if n7b.charSet != nil {
		panic(errors.New("IllegalStateException: Characters specified already for N7Builder"))
	}
	// In Java, this also checked this.c (used flag) implicitly by not allowing re-specification.
	// For strictness, we could add: if n7b.used { panic(...) }
	n7b.charSet = chars
	return n7b
}

// --- BytesBuilder (from c1.java) ---
type BytesBuilder struct {
	parentOu *RandomGenerator
	used     bool
}

func newBytesBuilder(parent *RandomGenerator) *BytesBuilder {
	return &BytesBuilder{parentOu: parent, used: false}
}

// Build creates random bytes. Corresponds to 'public byte[] a(int var1)' in c1.java
func (c1b *BytesBuilder) Build(length int) []byte {
	if c1b.used {
		panic(errors.New("IllegalStateException: Cannot re-use C1Builder"))
	}
	c1b.used = true
	// Note: Java c1.a(int) does not check if length > 0, but Random.nextBytes() on a zero-length array is a no-op.
	// For Go, rand.Read on zero-length slice is also a no-op.
	// If length is negative, Go's make([]byte, length) will panic. Java's new byte[length] would NegativeArraySizeException.
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

// --- IntBuilder (from n1.java) ---
type IntBuilder struct {
	parentOu *RandomGenerator
	used     bool
	min      *int // Using pointers to distinguish between not set and set to 0
	max      *int
}

func newIntBuilder(parent *RandomGenerator) *IntBuilder {
	return &IntBuilder{parentOu: parent, used: false, min: nil, max: nil}
}

// Build creates a random int. Corresponds to 'public int a()' in n1.java.
func (n1b *IntBuilder) Build() int {
	if n1b.used {
		panic(errors.New("IllegalStateException: Cannot re-use N1Builder"))
	}
	n1b.used = true

	if n1b.max != nil && n1b.min != nil &&
		*n1b.min >= *n1b.max { // Java: this.a <= this.d (max <= min)
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

	// Effective range for Intn: [0, n). So n = (maxValue - minValue).
	// Result is then offset by minValue.
	// Java: var2 (bound for nextInt) = this.a != null ? this.a : Integer.MAX_VALUE;
	//       if (this.d != null) { var2 -= this.d; }
	//       int var3 = ...nextInt(var2);
	//       if (this.d != null) { var3 += this.d; }

	// If only min is set, range is [min, MaxInt)
	// If only max is set, range is [0, max)
	// If both, range is [min, max)

	n := maxValue - minValue
	if n <= 0 { // This case can happen if max == min, or max < min (already checked above for min >= max)
		// If max == min, result should be min (or max).
		// Java's nextInt(0) or nextInt(negative) would throw.
		// If min == max, we should return min. The range 'n' for Intn would be 0.
		// rand.Intn(0) panics. If n is 0 (min==max), return min.
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

// WithMax sets the maximum value (exclusive). Corresponds to 'public n1 b(int var1)' in n1.java.
func (n1b *IntBuilder) WithMax(val int) *IntBuilder {
	if n1b.max != nil {
		panic(errors.New("IllegalStateException: Maximum specified already for N1Builder"))
	}
	n1b.max = &val
	return n1b
}

// WithMin sets the minimum value (inclusive). Corresponds to 'public n1 a(int var1)' in n1.java.
func (n1b *IntBuilder) WithMin(val int) *IntBuilder {
	if n1b.min != nil {
		panic(errors.New("IllegalStateException: Minimum specified already for N1Builder"))
	}
	if val < 0 || val == int(^uint(0)>>1) { // Java: var1 >= 0 && var1 != Integer.MAX_VALUE
		panic(
			errors.New(
				"IllegalStateException: minInclusive must be in the range 0 <= x < Integer.MAX_VALUE for N1Builder",
			),
		)
	}
	n1b.min = &val
	return n1b
}

// --- Int64Builder (from q9.java) ---
type Int64Builder struct {
	parentOu *RandomGenerator
	used     bool
	min      *int64
	max      *int64
}

func newInt64Builder(parent *RandomGenerator) *Int64Builder {
	return &Int64Builder{parentOu: parent, used: false, min: nil, max: nil}
}

// Build creates a random long. Corresponds to 'public long a()' in q9.java.
func (q9b *Int64Builder) Build() int64 {
	if q9b.used {
		panic(errors.New("IllegalStateException: Cannot re-use Q9Builder"))
	}
	q9b.used = true

	if q9b.max != nil && q9b.min != nil &&
		*q9b.min >= *q9b.max { // Java: this.b <= this.c (max <= min)
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

// a_randomLongWithBound is the Go equivalent of 'private long a(long var1)' in q9.java.
// var1 is 'bound' (exclusive upper bound for random number, starting from 0).
func (q9b *Int64Builder) a_randomLongWithBound(bound int64) int64 {
	if bound <= 0 {
		panic(
			errors.New(
				"IllegalArgumentException: bound must be positive for Q9Builder random long generation",
			),
		)
	}
	// Java: long var4 = o5.a(this.a).nextLong(); (this.a is the o5 instance, o5.a(o5) gets the Random instance)
	// Go: q9b.parentOu.randomSource.Int63() or .Int63n for specific bound handling

	// Java's logic for nextLong(bound):
	// long var6 = var1 - 1L; // bound - 1
	// if ((var1 & var6) == 0L) { // if bound is power of 2
	//    var4 &= var6; // bits = random & (bound-1)
	// } else {
	//    long var8 = var4 >>> 1;
	//    while (var8 + var6 - (var4 = var8 % var1) < 0L) {
	//       var8 = o5.a(this.a).nextLong() >>> 1;
	//    }
	// }
	// return var4;

	// Go's rand.Int63n(n) returns a random number in [0, n). This is much simpler.
	return q9b.parentOu.randomSource.Int63n(bound)
}

// Note: Setters for min/max on Q9Builder (WithMax, A_min_long) would be analogous to N1Builder if needed.
// The Java q9.java doesn't show public setters for min/max, implying they might be set via a different mechanism
// or the builder is used with defaults / specific internal configurations not visible in the snippet.
// For now, Q9Builder only has A_build().
// Based on n1.java structure, it is likely q9 would have similar min/max setters:
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
	// Java q9 doesn't show min checks like n1 for >=0. Assuming any long is fine for min.
	q9b.min = &val
	return q9b
}
