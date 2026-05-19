package smart_behavior_detection

import "github.com/vigolium/vigolium/pkg/modules/shared/diffscan"

// buildBackslashProbe creates probe for backslash delimiter detection.
func buildBackslashProbe() *diffscan.Probe {
	p := diffscan.NewProbe("Backslash", 3, "\\\\\\", "\\")
	p.Base = "\\"
	p.InjectType = diffscan.InjectType_Append
	p.SetRandomAnchor(false)
	p.SetEscapeStrings("\\\\\\\\", "\\\\")
	return p
}

// buildApostropheProbe creates probe for single quote delimiter detection.
func buildApostropheProbe() *diffscan.Probe {
	p := diffscan.NewProbe("String - apostrophe", 3, "'")
	p.Base = "'"
	p.InjectType = diffscan.InjectType_Append
	p.SetRandomAnchor(false)
	p.AddEscapePair("\\'", "''")
	return p
}

// buildDoubleQuoteProbe creates probe for double quote delimiter detection.
func buildDoubleQuoteProbe() *diffscan.Probe {
	p := diffscan.NewProbe("String - doublequoted", 3, "\"")
	p.Base = "\""
	p.InjectType = diffscan.InjectType_Append
	p.SetRandomAnchor(false)
	p.SetEscapeStrings("\\\"")
	return p
}

// buildBacktickProbe creates probe for backtick delimiter detection.
func buildBacktickProbe() *diffscan.Probe {
	p := diffscan.NewProbe("String - backtick", 2, "`")
	p.Base = "`"
	p.InjectType = diffscan.InjectType_Append
	p.SetRandomAnchor(false)
	p.SetEscapeStrings("\\`")
	return p
}

// buildDivideBy0Probe creates probe for numeric context detection (divide by zero).
func buildDivideBy0Probe() *diffscan.Probe {
	p := diffscan.NewProbe("Divide by 0", 4, "/0")
	p.SetEscapeStrings("/1", "-0")
	p.InjectType = diffscan.InjectType_Append
	p.SetRandomAnchor(false)
	return p
}

// buildConcatenationProbe creates probe for concatenation testing (first approach).
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
func buildOrderByProbe() *diffscan.Probe {
	p := diffscan.NewProbe("Order-by function injection", 5, ",abz(1)")
	p.SetEscapeStrings(",abs(1)")
	p.InjectType = diffscan.InjectType_Append
	p.SetRandomAnchor(false)
	return p
}
