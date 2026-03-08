package core

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// HTMLEntityVariantCompositeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: b3r
type HTMLEntityVariantCompositeStrategy struct {
	variantGeneratingStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// generateHTMLEntityVariations is the Go equivalent of the private Java method a(String var1)
// It uses a map to simulate Set<String> behavior regarding uniqueness.
// Order is not guaranteed when converting map keys to slice, similar to Java HashSet to ArrayList conversion.
func (receiver *HTMLEntityVariantCompositeStrategy) generateHTMLEntityVariations(
	baseString string,
) map[string]struct{} {
	// HashSet var2 = new HashSet();
	variationsSet := make(map[string]struct{})

	// var2.add(var1.replace("\"", "&quot;"));
	variationsSet[strings.ReplaceAll(baseString, "\"", "&quot;")] = struct{}{}
	// var2.add(var1.replace("\"", "&#x22;"));
	variationsSet[strings.ReplaceAll(baseString, "\"", "&#x22;")] = struct{}{}
	// var2.add(var1.replace("\"", "&#34;"));
	variationsSet[strings.ReplaceAll(baseString, "\"", "&#34;")] = struct{}{}
	// var2.add(var1.replace("'", "&apos;"));
	variationsSet[strings.ReplaceAll(baseString, "'", "&apos;")] = struct{}{}
	// var2.add(var1.replace("'", "&#x27;"));
	variationsSet[strings.ReplaceAll(baseString, "'", "&#x27;")] = struct{}{}
	// var2.add(var1.replace("'", "&#39;"));
	variationsSet[strings.ReplaceAll(baseString, "'", "&#39;")] = struct{}{}

	// var2.remove(var1);
	delete(variationsSet, baseString)

	return variationsSet
}

// NewHTMLEntityVariantCompositeStrategy creates a new instance of B3r.
// Original Java constructor: public b3r(String var1, boolean var2, blw var3)
func NewHTMLEntityVariantCompositeStrategy(
	baseString string,
	useEntityVariants bool,
	strategyFactory StrategyGeneratorFromString,
) *HTMLEntityVariantCompositeStrategy {
	receiver := &HTMLEntityVariantCompositeStrategy{}

	// int var10000 = gfw.b();

	// ArrayList payloadBases = new ArrayList();
	payloadBases := make([]string, 0)

	// int var4 = var10000;

	// var5.add(var1);
	payloadBases = append(payloadBases, baseString)

	// if (var2) {
	//    var5.addAll(this.a(var1)); // Calls private method a
	// }
	if useEntityVariants {
		for variant := range receiver.generateHTMLEntityVariations(baseString) {
			payloadBases = append(payloadBases, variant)
		}
	}

	// ContextualXSSTechnique[] var6 = new ContextualXSSTechnique[var5.size()];
	generatedStrategies := make([]ContextualAttackPayloadGenerator, len(payloadBases))

	// int index = 0;
	// while (index < var5.size()) {
	//    var6[index] = var3.a((String)var5.get(index)); // Calls blw.a
	//    index++;
	//    if (var4 == 0) { // This condition var4 == 0 seems odd
	//       break;        // It's likely related to the static gfw.b() value. If gfw.b() can return 0.
	//    }
	// }
	index := 0
	for index < len(payloadBases) {
		generatedStrategies[index] = strategyFactory.CreateStrategy(
			payloadBases[index],
		) // Call A on Blw interface
		index++
		// The original Java var4 (here var4LoopCondition) is not modified inside the loop.
	}

	// this.a = new gfw(var6);
	receiver.variantGeneratingStrategy = NewFirstSuccessMetaStrategy(
		generatedStrategies...) // Ensure NewGfw stub can handle variadic ContextualXSSTechnique

	return receiver
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *HTMLEntityVariantCompositeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return this.a.a(var1, var2, var3, var4, var5, var6);
	return receiver.variantGeneratingStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
