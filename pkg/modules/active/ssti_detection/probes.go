package ssti_detection

import "github.com/vigolium/vigolium/pkg/modules/shared/diffscan"

// SSTI Detection Probes
// Based on "Successful Errors" research by vladko312 (SSTImap)
// https://github.com/vladko312/SSTImap
//
// Boolean Error-Based Blind Detection Logic:
// - Break payload = ERROR payload (causes syntax error OR evaluates to false for divide-by-zero)
// - Escape payload = OK payload (valid syntax, evaluates to true)
// If responses DIFFER → template engine interprets input → VULNERABLE
//
// Key Language Quirks Used:
// - Python: 'a'.join('bc') produces 'bac' NOT 'abc'
// - PHP: '2' + '3' == 5 (string + string = number via type coercion)
// - JavaScript: typeof(1) + 2 == "number2" (type string + number = string concat)
// - Ruby: (2 + 3).to_s == '5' (integer arithmetic, then string conversion)
// - Java: 1000000000+2000000000 overflows to negative number

// =============================================================================
// GENERIC PROBES - Universal math syntax error detection
// Works across any template engine that evaluates expressions
// =============================================================================

// buildGenericSyntaxProbe1 detects template engines via math syntax errors.
// Break: 3*)2(/4 → Syntax error (invalid math expression)
// Escape: (3*4/2) → Valid math expression = 6
func buildGenericSyntaxProbe1() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Generic syntax 1", 4, "3*)2(/4")
	p.SetEscapeStrings("(3*4/2)")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// buildGenericSyntaxProbe2 detects template engines via complex math syntax errors.
// Break: 7)(*)8)(2/(*4 → Syntax error (malformed expression)
// Escape: ((7*8)/(2*4)) → Valid math expression = 7
func buildGenericSyntaxProbe2() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Generic syntax 2", 4, "7)(*)8)(2/(*4")
	p.SetEscapeStrings("((7*8)/(2*4))")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// =============================================================================
// PYTHON LANGUAGE PROBES
// Python quirk: 'a'.join('bc') produces 'bac' (inserts 'a' between b and c)
// =============================================================================

// buildPythonJoinProbe detects Python via string join behavior.
// 'a'.join('bc') == 'abc' → FALSE because join produces 'bac'
// Break: 1/False → ZeroDivisionError
// Escape: 1/True → 1
func buildPythonJoinProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Python join", 6, "1/('a'.join('bc')=='abc')")
	p.SetEscapeStrings("1/('a'.join('bc')=='bac')")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// buildPythonBoolProbe detects Python via bool() behavior.
// bool('any non-empty string') == True in Python
// Break: bool('True') == False → False → 1/0 → ZeroDivisionError
// Escape: bool('False') == True → True (any non-empty string is truthy) → 1/1 → OK
func buildPythonBoolProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Python bool", 6, "1/(bool('True')==False)")
	p.SetEscapeStrings("1/(bool('False')==True)")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// =============================================================================
// PHP LANGUAGE PROBES
// PHP quirk: '2' + '3' == 5 (string concatenation with + does arithmetic)
// =============================================================================

// buildPHPTypeCoercionProbe detects PHP via type coercion in arithmetic.
// '2' + '5' == 3 → False (2+5=7, not 3)
// '2' + '3' == 5 → True (2+3=5)
// Break: 1/False → Division by zero
// Escape: 1/True → 1
func buildPHPTypeCoercionProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - PHP type coercion", 6, "1/('2'+'5'==3)")
	p.SetEscapeStrings("1/('2'+'3'==5)")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// buildPHPStrlenProbe detects PHP via strlen() function.
// strlen('1') == 2 → False (length is 1)
// strlen('2') == 1 → True
func buildPHPStrlenProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - PHP strlen", 6, "1/(strlen('1')==2)")
	p.SetEscapeStrings("1/(strlen('2')==1)")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// =============================================================================
// JAVASCRIPT LANGUAGE PROBES
// JS quirk: typeof(1) + 2 == "number2" (string + number = string concat)
// =============================================================================

// buildJSTypeofProbe detects JavaScript via typeof concatenation.
// typeof(1) + 2 == "number2" → True (typeof returns "number", + 2 appends "2")
// typeof(2) + 1 == "number2" → False (appends "1" giving "number1")
// Use array access error: [""][1] throws, [""][0] returns ""
func buildJSTypeofProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - JavaScript typeof", 6,
		`[""][0+!(typeof(2)+1=="number2")]["length"]`)
	p.SetEscapeStrings(`[""][0+!(typeof(1)+2=="number2")]["length"]`)
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// buildJSParseIntProbe detects JavaScript via parseInt behavior.
// parseInt("5x") == 5 → True (parses until non-digit)
// parseInt("x5") == 5 → False (NaN, starts with non-digit)
func buildJSParseIntProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - JavaScript parseInt", 6,
		`[""][0+!(parseInt("x5")==5)]["length"]`)
	p.SetEscapeStrings(`[""][0+!(parseInt("5x")==5)]["length"]`)
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// =============================================================================
// RUBY LANGUAGE PROBES
// Ruby quirk: (2 + 3).to_s == '5' (arithmetic then string conversion)
// =============================================================================

// buildRubyToSProbe detects Ruby via .to_s comparison.
// (2 + 5).to_s == '3' → False (7 != 3)
// (2 + 3).to_s == '5' → True
func buildRubyToSProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Ruby to_s", 6, "1/(((2+5).to_s=='3')&&1||0)")
	p.SetEscapeStrings("1/(((2+3).to_s=='5')&&1||0)")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// buildRubyLengthProbe detects Ruby via string length.
// '1'.length == 2 → False (length is 1)
// '2'.length == 1 → True
func buildRubyLengthProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Ruby length", 6, "1/(('1'.length==2)&&1||0)")
	p.SetEscapeStrings("1/(('2'.length==1)&&1||0)")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// =============================================================================
// JAVA LANGUAGE PROBES
// Java quirk: Integer overflow (1e9+2e9 overflows to negative)
// =============================================================================

// buildJavaOverflowProbe detects Java via integer overflow behavior.
// 1000000000+2000000000 = 3000000000 but int max is 2147483647
// So it overflows to -1294967296, NOT 1000000000
// Break: comparison to 1000000000 is False → divide by 0
// Escape: 1000000000+1000000000 = 2000000000 (no overflow) → True → divide by 1
func buildJavaOverflowProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Java overflow", 7,
		`"".getClass().forName('java.lang.Integer').valueOf('1')/((1000000000+2000000000==1000000000)?1:0)+""`)
	p.SetEscapeStrings(
		`"".getClass().forName('java.lang.Integer').valueOf('1')/((1000000000+1000000000==2000000000)?1:0)+""`)
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// buildJavaNegOverflowProbe verifies Java via negative overflow.
// 2000000000+2000000000 = -294967296 (overflow to negative)
func buildJavaNegOverflowProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Java neg overflow", 7,
		`"".getClass().forName('java.lang.Integer').valueOf('1')/((2000000000+2000000000==-224667999)?1:0)+""`)
	p.SetEscapeStrings(
		`"".getClass().forName('java.lang.Integer').valueOf('1')/((2000000000+2000000000==-294967296)?1:0)+""`)
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// =============================================================================
// PYTHON TEMPLATE ENGINES
// =============================================================================

// --- Jinja2/Django ---

// buildJinja2ExpressionProbe detects Jinja2/Django via type error.
// Break: {{7*'7'}} → Type error in strict mode (int * string)
// Escape: {{7*7}} → 49
func buildJinja2ExpressionProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Jinja2 expression", 5, "{{7*'7'}}")
	p.SetEscapeStrings("{{7*7}}")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// buildJinja2DivideProbe detects Jinja2/Django via divide by zero.
// Break: {{7/0}} → ZeroDivisionError
// Escape: {{7/1}} → 7
func buildJinja2DivideProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Jinja2 divide", 5, "{{7/0}}")
	p.SetEscapeStrings("{{7/1}}")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// buildJinja2JoinProbe detects Jinja2 using Python's join quirk.
func buildJinja2JoinProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Jinja2 join", 6, "{{1/('a'.join('bc')=='abc')}}")
	p.SetEscapeStrings("{{1/('a'.join('bc')=='bac')}}")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// --- Mako ---

// buildMakoProbe detects Mako via divide by zero.
// Mako uses ${} syntax
func buildMakoProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Mako", 5, "${7/0}")
	p.SetEscapeStrings("${7/1}")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// buildMakoJoinProbe detects Mako using Python's join quirk.
func buildMakoJoinProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Mako join", 6, "${1/('a'.join('bc')=='abc')}")
	p.SetEscapeStrings("${1/('a'.join('bc')=='bac')}")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// --- Tornado ---

// buildTornadoProbe detects Tornado via divide by zero.
// Tornado uses {{}} syntax
func buildTornadoProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Tornado", 5, "{{1/('a'.join('bc')=='abc')}}")
	p.SetEscapeStrings("{{1/('a'.join('bc')=='bac')}}")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// --- Cheetah ---

// buildCheetahProbe detects Cheetah using Python's join quirk.
// Cheetah uses ${} or $variable syntax
func buildCheetahProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Cheetah", 5, "${1/('a'.join('bc')=='abc')}")
	p.SetEscapeStrings("${1/('a'.join('bc')=='bac')}")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// =============================================================================
// PHP TEMPLATE ENGINES
// =============================================================================

// --- Twig ---

// buildTwigExpressionProbe detects Twig via type error.
// Break: {{7/'7'}} → Type error (division with string)
// Escape: {{7/7}} → 1
func buildTwigExpressionProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Twig expression", 5, "{{7/'7'}}")
	p.SetEscapeStrings("{{7/7}}")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// buildTwigStatementProbe detects Twig via invalid statement.
// Break: {%invalid%} → Twig_Error_Syntax
// Escape: {%if 1%}1{%endif%} → Valid
func buildTwigStatementProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Twig statement", 5, "{%invalid%}")
	p.SetEscapeStrings("{%if 1%}1{%endif%}")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// --- Smarty ---

// buildSmartyProbe detects Smarty (PHP) using type coercion.
// Uses { } delimiters
func buildSmartyProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Smarty", 5, "{1/('2'+'5'==3)}")
	p.SetEscapeStrings("{1/('2'+'3'==5)}")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// --- Blade ---

// buildBladeProbe detects Blade (PHP/Laravel) using type coercion.
// Uses {{ }} delimiters
func buildBladeProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Blade", 5, "{{1/('2'+'5'==3)}}")
	p.SetEscapeStrings("{{1/('2'+'3'==5)}}")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// --- Latte ---

// buildLatteProbe detects Latte (PHP) using type coercion.
// Uses {= } delimiters
func buildLatteProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Latte", 5, "{=1/('2'+'5'==3)}")
	p.SetEscapeStrings("{=1/('2'+'3'==5)}")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// =============================================================================
// JAVA TEMPLATE ENGINES
// =============================================================================

// --- Freemarker ---

// buildFreemarkerProbe detects Freemarker via divide by zero.
// Uses ${} syntax
func buildFreemarkerProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Freemarker", 5, "${7/0}")
	p.SetEscapeStrings("${7/1}")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// buildFreemarkerDirectiveProbe detects Freemarker via invalid directive.
// Break: <#invalid> → ParseException
// Escape: <#if true>1</#if> → Valid
func buildFreemarkerDirectiveProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Freemarker directive", 5, "<#invalid>")
	p.SetEscapeStrings("<#if true>1</#if>")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// buildFreemarkerBoolProbe detects Freemarker via boolean comparison.
// Uses ?string and ?eval built-ins
// (1.0 == 0.1) → false → "0" → ?eval → 0 → divide error
// (1.0 == 1.0) → true → "1" → ?eval → 1 → OK
func buildFreemarkerBoolProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Freemarker bool", 6,
		"${1/((1.0==0.1)?string('1','0')?eval)}")
	p.SetEscapeStrings("${1/((1.0==1.0)?string('1','0')?eval)}")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// --- Velocity ---

// buildVelocityProbe detects Velocity via divide by zero.
// Uses #set() directive
func buildVelocityProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Velocity", 5, "#set($x=7/0)")
	p.SetEscapeStrings("#set($x=7/1)")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// buildVelocityBoolProbe detects Velocity via conditional file include.
// Break: #if(true) includes non-existent file → Error
// Escape: #if(false) → no include → OK
func buildVelocityBoolProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Velocity bool", 5,
		`#if(true)#include("Y:/A:/false")#end`)
	p.SetEscapeStrings(`#if(false)#include("Y:/A:/true")#end`)
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// buildVelocityEqualsProbe detects Velocity via equals comparison.
// Uses .equals() method
func buildVelocityEqualsProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Velocity equals", 5,
		`#set($o=1.0)#if($o.equals(1.0))#include("Y:/A:/xxx")#end`)
	p.SetEscapeStrings(`#set($o=1.0)#if($o.equals(0.1))#include("Y:/A:/xxx")#end`)
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// --- SpEL (Spring Expression Language) ---

// buildSpELOverflowProbe detects SpEL via integer overflow.
func buildSpELOverflowProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - SpEL overflow", 7,
		`"".getClass().forName('java.lang.Integer').valueOf('1')/((1000000000+2000000000==1000000000)?1:0)+""`)
	p.SetEscapeStrings(
		`"".getClass().forName('java.lang.Integer').valueOf('1')/((1000000000+1000000000==2000000000)?1:0)+""`)
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// buildSpELNegOverflowProbe verifies SpEL via negative overflow.
func buildSpELNegOverflowProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - SpEL neg overflow", 7,
		`"".getClass().forName('java.lang.Integer').valueOf('1')/((2000000000+2000000000==-224667999)?1:0)+""`)
	p.SetEscapeStrings(
		`"".getClass().forName('java.lang.Integer').valueOf('1')/((2000000000+2000000000==-294967296)?1:0)+""`)
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// --- OGNL (Object Graph Navigation Library) ---

// buildOGNLOverflowProbe detects OGNL via integer overflow.
// OGNL uses @class@method syntax
func buildOGNLOverflowProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - OGNL overflow", 7,
		`(@java.lang.Integer@valueOf('1')/((1000000000+2000000000==1000000000)?1:0)+'')`)
	p.SetEscapeStrings(
		`(@java.lang.Integer@valueOf('1')/((1000000000+1000000000==2000000000)?1:0)+'')`)
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// buildOGNLNegOverflowProbe verifies OGNL via negative overflow.
func buildOGNLNegOverflowProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - OGNL neg overflow", 7,
		`(@java.lang.Integer@valueOf('1')/((2000000000+2000000000==-224667999)?1:0)+'')`)
	p.SetEscapeStrings(
		`(@java.lang.Integer@valueOf('1')/((2000000000+2000000000==-294967296)?1:0)+'')`)
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// --- Pebble ---

// buildPebbleProbe detects Pebble via divide by zero.
// Uses {{}} syntax like Jinja2
func buildPebbleProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Pebble", 5, "{{7/0}}")
	p.SetEscapeStrings("{{7/1}}")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// =============================================================================
// JAVASCRIPT TEMPLATE ENGINES
// =============================================================================

// --- EJS ---

// buildEJSProbe detects EJS (NodeJS) using typeof quirk.
// Uses <%= %> delimiters
func buildEJSProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - EJS", 5,
		`<%=[""][0+!(typeof(2)+1=="number2")]["length"]%>`)
	p.SetEscapeStrings(
		`<%=[""][0+!(typeof(1)+2=="number2")]["length"]%>`)
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// --- Nunjucks ---

// buildNunjucksProbe detects Nunjucks (NodeJS) via constructor.
// Uses range.constructor to execute code
func buildNunjucksProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Nunjucks", 5,
		`{{range.constructor('return [""][0+!(typeof(2)+1=="number2")]["length"]')()}}`)
	p.SetEscapeStrings(
		`{{range.constructor('return [""][0+!(typeof(1)+2=="number2")]["length"]')()}}`)
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// --- Pug ---

// buildPugProbe detects Pug (NodeJS) using typeof quirk.
// Uses #{ } delimiters
func buildPugProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Pug", 5,
		`#{[""][0+!(typeof(2)+1=="number2")]["length"]}`)
	p.SetEscapeStrings(
		`#{[""][0+!(typeof(1)+2=="number2")]["length"]}`)
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// --- doT.js ---

// buildDotJSProbe detects doT.js (NodeJS) using typeof quirk.
// Uses {{= }} delimiters
func buildDotJSProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - doT.js", 5,
		`{{=[""][0+!(typeof(2)+1=="number2")]["length"]}}`)
	p.SetEscapeStrings(
		`{{=[""][0+!(typeof(1)+2=="number2")]["length"]}}`)
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// --- Marko ---

// buildMarkoProbe detects Marko (NodeJS) using typeof quirk.
// Uses ${} delimiters
func buildMarkoProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Marko", 5,
		`${[""][0+!(typeof(2)+1=="number2")]["length"]}`)
	p.SetEscapeStrings(
		`${[""][0+!(typeof(1)+2=="number2")]["length"]}`)
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// =============================================================================
// RUBY TEMPLATE ENGINES
// =============================================================================

// --- ERB ---

// buildERBProbe detects ERB via divide by zero.
// Uses <%= %> delimiters
func buildERBProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - ERB", 5, "<%=7/0%>")
	p.SetEscapeStrings("<%=7/1%>")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// buildERBToSProbe detects ERB using Ruby's to_s quirk.
func buildERBToSProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - ERB to_s", 6, "<%=1/(((2+5).to_s=='3')&&1||0)%>")
	p.SetEscapeStrings("<%=1/(((2+3).to_s=='5')&&1||0)%>")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// --- Slim ---

// buildSlimProbe detects Slim using Ruby's to_s quirk.
// Uses #{} for expression interpolation
func buildSlimProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Slim", 5, "#{1/(((2+5).to_s=='3')&&1||0)}")
	p.SetEscapeStrings("#{1/(((2+3).to_s=='5')&&1||0)}")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}

// --- Haml ---

// buildHamlProbe detects Haml using Ruby's to_s quirk.
// Uses #{} delimiters (same as Slim)
func buildHamlProbe() *diffscan.Probe {
	p := diffscan.NewProbe("SSTI - Haml", 5, "#{1/(((2+5).to_s=='3')&&1||0)}")
	p.SetEscapeStrings("#{1/(((2+3).to_s=='5')&&1||0)}")
	p.InjectType = diffscan.InjectType_Replace
	p.SetRandomAnchor(true)
	return p
}
