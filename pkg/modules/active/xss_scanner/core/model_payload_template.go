package core

// PayloadGenerationTemplate is the Go equivalent of the Java class glw.
// It's used as a data holder for string components, often for payload generation.
type PayloadGenerationTemplate struct {
	techniqueClassifier       AttackTechniqueClassifier // Corresponds to 'public final cgv j;'
	randomString5a            string                    // Corresponds to 'final String f;'
	randomString5b            string                    // Corresponds to 'final String a;'
	randomString8             string                    // Corresponds to 'final String c;'
	randomString10            string                    // Corresponds to 'final String l;'
	randomNumericSuffix1      string                    // Corresponds to 'final String i;'
	randomNumericSuffix2      string                    // Corresponds to 'final String d;'
	randomNumericSuffix3      string                    // Corresponds to 'final String b;'
	randomInvalidTagName5     string                    // Corresponds to 'final String g;'
	primaryFormattedPayload   string                    // Corresponds to 'public final String k;'
	secondaryFormattedPayload string                    // Corresponds to 'public final String e;'
	probeBuilder              *ScanProbeBuilder         // Corresponds to 'final hgm h;' (reference to Hgm instance)
}

// NewPayloadGenerationTemplate creates a new instance of Glw.
// Original Java constructor: glw(hgm var1, cgv var2, String var3, String var4, String var5, String var6, String var7, String var8, String var9, String var10, String var11)
func NewPayloadGenerationTemplate(
	probeBuilder *ScanProbeBuilder, // var1
	techniqueClassifier AttackTechniqueClassifier, // var2
	rStr5a string, // var3
	rStr5b string, // var4
	rStr8 string, // var5
	rStr10 string, // var6
	rNumSuffix1 string, // var7
	rNumSuffix2 string, // var8
	rNumSuffix3 string, // var9
	rInvalidTag5 string, // var10
	baseFormatString string, // var11 - used for K and E initialization
) *PayloadGenerationTemplate {
	template := &PayloadGenerationTemplate{}

	template.probeBuilder = probeBuilder
	// String[] var10000 = hgm.b();
	// This static call result is used in a conditional return,
	// but the assignment to var12 means it's captured for that.

	template.techniqueClassifier = techniqueClassifier
	template.randomString5a = rStr5a
	template.randomString5b = rStr5b
	template.randomString8 = rStr8
	template.randomString10 = rStr10
	template.randomNumericSuffix1 = rNumSuffix1
	template.randomNumericSuffix2 = rNumSuffix2
	template.randomNumericSuffix3 = rNumSuffix3
	template.randomInvalidTagName5 = rInvalidTag5

	// if (var11 != null) {
	//    this.k = hgm.a(var11, hgm.a(var1, null));
	//    this.e = hgm.a(var11, hgm.a(var1, null));
	//    if (var12 == null) { // var12 is var10000 which is hgm.b()
	//       return; // This early return is tricky in Go constructors.
	//                // We'll complete initialization and rely on the caller to handle if hgmStaticBResult is nil.
	//                // Or, since NewGlw returns *Glw, a nil return could signify this, but it's not idiomatic.
	//                // For now, porting the conditional assignment.
	//    }
	// }
	// this.k = null;
	// this.e = null;

	if baseFormatString != "" { // Java null check for String
		// hgm.a(var1, null) -> instance call on hgmVal, passing null as string
		// This requires hgmVal to have a method that can be called like this,
		// which we'll model via a static helper HgmStaticHelperCallInstanceAGlw.
		intermediateTemplateData := PreparePayloadTemplateDataForBuilder(
			probeBuilder,
			"",
		) // Passing empty string for Java null

		// hgm.a(var11, intermediateGlw) -> static formatting call
		template.primaryFormattedPayload = FormatPayloadFromTemplate(
			baseFormatString,
			intermediateTemplateData,
		)
		template.secondaryFormattedPayload = FormatPayloadFromTemplate(
			baseFormatString,
			intermediateTemplateData,
		)

	} else {
		// Java assigns null, Go zero value for string is ""
		template.primaryFormattedPayload = ""
		template.secondaryFormattedPayload = ""
	}

	return template
}
