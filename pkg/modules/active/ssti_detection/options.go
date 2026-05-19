package ssti_detection

import "github.com/vigolium/vigolium/pkg/modules/shared/diffscan"

// Options configures the SSTI Detection module.
type Options struct {
	// Generic detection using syntax errors
	EnableGenericDetection bool

	// Language-specific probes (use language quirks for detection)
	EnablePythonDetection     bool // Python join quirk: 'a'.join('bc') == 'bac'
	EnablePHPDetection        bool // PHP type coercion: '2' + '3' == 5
	EnableJavaScriptDetection bool // JS typeof: typeof(1) + 2 == "number2"
	EnableRubyDetection       bool // Ruby to_s: (2+3).to_s == '5'
	EnableJavaDetection       bool // Java overflow: 1e9+2e9 overflows

	// Python template engines
	EnableJinja2Detection  bool // Jinja2/Django (Python) - {{ }} delimiters
	EnableMakoDetection    bool // Mako (Python) - ${ } delimiters
	EnableTornadoDetection bool // Tornado (Python) - {{ }} delimiters
	EnableCheetahDetection bool // Cheetah (Python) - ${ } delimiters

	// PHP template engines
	EnableTwigDetection   bool // Twig (PHP) - {{ }} and {% %} delimiters
	EnableSmartyDetection bool // Smarty (PHP) - { } delimiters
	EnableBladeDetection  bool // Blade (PHP/Laravel) - {{ }} delimiters
	EnableLatteDetection  bool // Latte (PHP) - {= } delimiters

	// Java template engines
	EnableFreemarkerDetection bool // Freemarker (Java) - ${ } and <# > delimiters
	EnableVelocityDetection   bool // Velocity (Java) - #set() #if() delimiters
	EnableSpELDetection       bool // Spring EL (Java) - ${ } or #{ } delimiters
	EnableOGNLDetection       bool // OGNL (Java/Struts) - @class@method syntax
	EnablePebbleDetection     bool // Pebble (Java) - {{ }} delimiters

	// JavaScript/Node.js template engines
	EnableEJSDetection      bool // EJS (NodeJS) - <%= %> delimiters
	EnableNunjucksDetection bool // Nunjucks (NodeJS) - {{ }} delimiters
	EnablePugDetection      bool // Pug (NodeJS) - #{ } delimiters
	EnableDotJSDetection    bool // doT.js (NodeJS) - {{= }} delimiters
	EnableMarkoDetection    bool // Marko (NodeJS) - ${ } delimiters

	// Ruby template engines
	EnableERBDetection  bool // ERB (Ruby) - <%= %> delimiters
	EnableSlimDetection bool // Slim (Ruby) - #{ } delimiters
	EnableHamlDetection bool // Haml (Ruby) - #{ } delimiters

	// DiffScanOptions configures the differential analysis engine
	DiffScanOptions *diffscan.Option
}

// DefaultOptions returns the default configuration with all detections enabled.
func DefaultOptions() *Options {
	return &Options{
		// Generic
		EnableGenericDetection: true,

		// Language-specific
		EnablePythonDetection:     true,
		EnablePHPDetection:        true,
		EnableJavaScriptDetection: true,
		EnableRubyDetection:       true,
		EnableJavaDetection:       true,

		// Python template engines
		EnableJinja2Detection:  true,
		EnableMakoDetection:    true,
		EnableTornadoDetection: true,
		EnableCheetahDetection: true,

		// PHP template engines
		EnableTwigDetection:   true,
		EnableSmartyDetection: true,
		EnableBladeDetection:  true,
		EnableLatteDetection:  true,

		// Java template engines
		EnableFreemarkerDetection: true,
		EnableVelocityDetection:   true,
		EnableSpELDetection:       true,
		EnableOGNLDetection:       true,
		EnablePebbleDetection:     true,

		// JavaScript template engines
		EnableEJSDetection:      true,
		EnableNunjucksDetection: true,
		EnablePugDetection:      true,
		EnableDotJSDetection:    true,
		EnableMarkoDetection:    true,

		// Ruby template engines
		EnableERBDetection:  true,
		EnableSlimDetection: true,
		EnableHamlDetection: true,

		DiffScanOptions: &diffscan.Option{
			Confirmations:             3,
			QuantitativeConfirmations: 50,
			QuantileFactor:            5,
			QuantitativeDiffKeys:      []string{},
		},
	}
}
