package smart_behavior_detection

import "github.com/vigolium/vigolium/pkg/modules/shared/diffscan"

// All probes match Java implementation in SmartBehaviorDetectionModule.java exactly.

// buildBackslashProbe creates probe for backslash delimiter detection.
// Java: new Probe("Backslash", 3, diffConfig, "\\\\\\", "\\")
func buildBackslashProbe() *diffscan.Probe {
	p := diffscan.NewProbe("Backslash", 3, "\\\\\\", "\\")
	p.Base = "\\"
	p.InjectType = diffscan.InjectType_Append
	p.SetRandomAnchor(false)
	p.SetEscapeStrings("\\\\\\\\", "\\\\")
	return p
}

// buildApostropheProbe creates probe for single quote delimiter detection.
// Java: new Probe("String - apostrophe", 3, diffConfig, "'")
func buildApostropheProbe() *diffscan.Probe {
	p := diffscan.NewProbe("String - apostrophe", 3, "'")
	p.Base = "'"
	p.InjectType = diffscan.InjectType_Append
	p.SetRandomAnchor(false)
	p.AddEscapePair("\\'", "''")
	return p
}

// buildDoubleQuoteProbe creates probe for double quote delimiter detection.
// Java: new Probe("String - doublequoted", 3, diffConfig, "\"")
func buildDoubleQuoteProbe() *diffscan.Probe {
	p := diffscan.NewProbe("String - doublequoted", 3, "\"")
	p.Base = "\""
	p.InjectType = diffscan.InjectType_Append
	p.SetRandomAnchor(false)
	p.SetEscapeStrings("\\\"")
	return p
}

// buildBacktickProbe creates probe for backtick delimiter detection.
// Java: new Probe("String - backtick", 2, diffConfig, "`")
func buildBacktickProbe() *diffscan.Probe {
	p := diffscan.NewProbe("String - backtick", 2, "`")
	p.Base = "`"
	p.InjectType = diffscan.InjectType_Append
	p.SetRandomAnchor(false)
	p.SetEscapeStrings("\\`")
	return p
}

// buildDivideBy0Probe creates probe for numeric context detection (divide by zero).
// Java: new Probe("Divide by 0", 4, diffConfig, "/0")
func buildDivideBy0Probe() *diffscan.Probe {
	p := diffscan.NewProbe("Divide by 0", 4, "/0")
	p.SetEscapeStrings("/1", "-0")
	p.InjectType = diffscan.InjectType_Append
	p.SetRandomAnchor(false)
	return p
}

// buildConcatenationProbe creates probe for concatenation testing (first approach).
// Java: new Probe("Soft-concatenation: " + delimiter + concat, 5, diffConfig, concat + delimiter + delimiter)
// break: concat+d+d, escape: d+concat+d
func buildConcatenationProbe(delimiter, concat string) *diffscan.Probe {
	p := diffscan.NewProbe(
		"Soft-concatenation: "+delimiter+concat,
		5,
		concat+delimiter+delimiter,
	)
	p.SetEscapeStrings(delimiter + concat + delimiter)
	p.InjectType = diffscan.InjectType_Append
	p.SetRandomAnchor(false)
	p.Base = delimiter
	return p
}

// buildConcatenationProbe2 creates probe for concatenation testing (second approach, fallback).
// Java: new Probe("Soft-concatenation 2: " + delimiter + concat, 5, diffConfig, delimiter + concat + delimiter)
// break: d+concat+d, escape: concat+d+d
func buildConcatenationProbe2(delimiter, concat string) *diffscan.Probe {
	p := diffscan.NewProbe(
		"Soft-concatenation 2: "+delimiter+concat,
		5,
		delimiter+concat+delimiter,
	)
	p.SetEscapeStrings(concat + delimiter + delimiter)
	p.InjectType = diffscan.InjectType_Append
	p.SetRandomAnchor(false)
	p.Base = delimiter
	return p
}

// buildOrderByProbe creates probe for ORDER BY injection detection.
// Java: new Probe("Order-by function injection", 5, diffConfig, ",abz(1)")
func buildOrderByProbe() *diffscan.Probe {
	p := diffscan.NewProbe("Order-by function injection", 5, ",abz(1)")
	p.SetEscapeStrings(",abs(1)")
	p.InjectType = diffscan.InjectType_Append
	p.SetRandomAnchor(false)
	return p
}
