package core

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)

// --- HgmImpl struct and Interface Implementation ---

// ScanProbeBuilder is the Go equivalent of the Java class hgm.
// It implements the ScanProbeBuilder interface.
type ScanProbeBuilder struct {
	scanFlags                   int                       // Corresponds to 'private final int c;'
	attackStepRunner            AttackStepRunner          // Corresponds to 'private final i2j e;'
	randomProvider              *utils.RandomGenerator    // Corresponds to 'private final ou a;'
	randomStringGenerator       RandomTextProvider        // Corresponds to 'private final fen f;'
	injectionPoint              httpmsg.InsertionPoint     // Corresponds to 'private final bno d;'
	tacticType                  ReflectionTacticType      // Corresponds to 'private final ll i;' (enum type)
	techniqueClassifier         AttackTechniqueClassifier // Corresponds to 'private final cgv g;'
	useSecondaryCanaryComponent bool                      // Corresponds to 'private final boolean h;'
}

// IsScanProbeBuilder marker method for Hgm interface.
func (h *ScanProbeBuilder) IsScanProbeBuilder() {}

// --- Constructors ---

// NewScanProbeBuilder is the primary public constructor.
// Corresponds to 'public hgm(ou var1, fen var2, i2j var3, bno var4, cgv var5, ll var6, boolean var7)'
func NewScanProbeBuilder(
	randomProvider *utils.RandomGenerator,
	randomStringGenerator RandomTextProvider,
	attackStepRunner AttackStepRunner,
	injectionPoint httpmsg.InsertionPoint,
	techniqueClassifier AttackTechniqueClassifier,
	tactic ReflectionTacticType,
	useSecondaryCanary bool,
) *ScanProbeBuilder {
	// this(var1, var2, var3, var4, var5, 0, var6, var7);
	return newScanProbeBuilderInternal(
		randomProvider,
		randomStringGenerator,
		attackStepRunner,
		injectionPoint,
		techniqueClassifier,
		0,
		tactic,
		useSecondaryCanary,
	)
}

// newScanProbeBuilderInternal is the private constructor equivalent.
// Corresponds to 'private hgm(ou var1, fen var2, i2j var3, bno var4, cgv var5, int var6, ll var7, boolean var8)'
func newScanProbeBuilderInternal(
	randomProvider *utils.RandomGenerator,
	randomStringGenerator RandomTextProvider,
	attackStepRunner AttackStepRunner,
	injectionPoint httpmsg.InsertionPoint,
	techniqueClassifier AttackTechniqueClassifier,
	initialScanFlags int,
	tactic ReflectionTacticType,
	useSecondaryCanary bool,
) *ScanProbeBuilder {
	return &ScanProbeBuilder{
		scanFlags:                   initialScanFlags,
		attackStepRunner:            attackStepRunner,
		randomProvider:              randomProvider,
		randomStringGenerator:       randomStringGenerator,
		injectionPoint:              injectionPoint,
		tacticType:                  tactic,
		techniqueClassifier:         techniqueClassifier,
		useSecondaryCanaryComponent: useSecondaryCanary,
	}
}

// --- Hgm Interface Methods ---

// BuildFinding corresponds to 'public bgf a(byte var1, String var2, hnx var3)'
func (builder *ScanProbeBuilder) BuildFinding(
	contextCode byte,
	payloadTemplate string,
	profile *ScanExecutionProfile,
) PotentialXSSFinding {
	// glw var4 = this.a(var2); // Calls private instance method aInternalGlw
	templateData := builder.preparePayloadTemplateData(payloadTemplate)

	// String var5 = a(var2, var4); // Calls static method HgmStaticAFormat
	finalPayload := FormatPayloadFromTemplate(payloadTemplate, templateData)
	zap.L().Debug("BuildFinding.finalPayload", zap.String("payload", finalPayload))

	profileWithTemplateData := profile.withPayloadTemplateData(templateData)
	finalProfile := profileWithTemplateData.withBaseCanaryComponent(finalPayload)

	return builder.attackStepRunner.RunAttackStep(
		builder.injectionPoint,
		builder.scanFlags,
		finalPayload,
		builder.tacticType,
		contextCode,
		builder.techniqueClassifier,
		builder.useSecondaryCanaryComponent,
		finalProfile,
	)
}

// WithAdditionalScanFlags corresponds to 'public hgm a(int var1)'
func (builder *ScanProbeBuilder) WithAdditionalScanFlags(flags int) *ScanProbeBuilder {
	// return new hgm(this.a, this.f, this.e, this.d, this.g, this.c | var1, this.i, this.h);
	return newScanProbeBuilderInternal(
		builder.randomProvider,
		builder.randomStringGenerator,
		builder.attackStepRunner,
		builder.injectionPoint,
		builder.techniqueClassifier,
		builder.scanFlags|flags,
		builder.tacticType,
		builder.useSecondaryCanaryComponent,
	)
}

// WithoutSecondaryCanary corresponds to 'public hgm c()'
func (builder *ScanProbeBuilder) WithoutSecondaryCanary() *ScanProbeBuilder {
	// return new hgm(this.a, this.f, this.e, this.d, this.g, this.c, this.i, false);
	return newScanProbeBuilderInternal(
		builder.randomProvider,
		builder.randomStringGenerator,
		builder.attackStepRunner,
		builder.injectionPoint,
		builder.techniqueClassifier,
		builder.scanFlags,
		builder.tacticType,
		false,
	)
}

// --- Private Instance Methods ---

// preparePayloadTemplateData corresponds to 'private glw a(String var1)'
func (builder *ScanProbeBuilder) preparePayloadTemplateData(
	baseFormatString string,
) *PayloadGenerationTemplate {
	randomNumericSuffix1 := "0"
	randomNumericSuffix2 := "0"
	randomNumericSuffix3 := "0"

	if builder.randomProvider != nil {
		randomNumericSuffix1 = builder.randomProvider.GetRandomNumericString(100, 1000)
		randomNumericSuffix2 = builder.randomProvider.GetRandomNumericString(10000, 100000)
		randomNumericSuffix3 = builder.randomProvider.GetRandomNumericString(10000000, 100000000)
	}

	return NewPayloadGenerationTemplate(
		builder,                     // this
		builder.techniqueClassifier, // this.g
		builder.randomProvider.GeneratePrefixedAlphanumeric(5),
		builder.randomProvider.GeneratePrefixedAlphanumeric(5),
		builder.randomProvider.GeneratePrefixedAlphanumeric(8),
		builder.randomProvider.GeneratePrefixedAlphanumeric(10),
		randomNumericSuffix1,
		randomNumericSuffix2,
		randomNumericSuffix3,
		builder.randomStringGenerator.GenerateText(5),
		baseFormatString,
	)
}

// --- Static Helper Methods (exported for use by other packages like glw.go) ---

// FormatPayloadFromTemplate corresponds to 'static String a(String var0, glw var1)'
func FormatPayloadFromTemplate(template string, templateData *PayloadGenerationTemplate) string {
	// Nếu bạn dùng package log chuẩn, hãy dùng Printf.
	// Nếu dùng thư viện như logrus, Infof là đúng.
	// Ví dụ với package log chuẩn:
	// log.Printf("formatStr: %s", formatStr)

	if templateData == nil {
		return template
	}
	// log.Printf("glwVal: %+v", glwVal)

	// 1. Escape tất cả các ký tự '%' trong chuỗi format gốc để fmt.Sprintf không hiểu nhầm.
	// Ví dụ: "Rate: 100%" sẽ trở thành "Rate: 100%%"
	tempFormatStr := strings.ReplaceAll(template, "%", "%%")

	// 2. Định nghĩa các placeholder và định dạng fmt tương ứng của chúng.
	// Sử dụng cú pháp %[index]verb cho Go, ví dụ: %[1]s, %[2]s.
	replacements := map[string]string{
		"#{poc}":                       "%[1]s",
		"#{random_string_5}":           "%[2]s",
		"#{random_string_5b}":          "%[3]s",
		"#{random_string_8}":           "%[4]s",
		"#{random_string_10}":          "%[5]s",
		"#{random_numeric_string_3}":   "%[6]s",
		"#{random_numeric_string_5}":   "%[7]s",
		"#{random_numeric_string_8}":   "%[8]s",
		"#{random_invalid_tag_name_5}": "%[9]s",
	}

	// 3. Thực hiện thay thế các placeholder bằng các định dạng fmt.
	for placeholder, fmtVerb := range replacements {
		tempFormatStr = strings.ReplaceAll(tempFormatStr, placeholder, fmtVerb)
	}

	// 4. Chuẩn bị các giá trị cho việc định dạng.
	var techniqueClassifier string
	if templateData.techniqueClassifier != nil {
		techniqueClassifier = templateData.techniqueClassifier.String() // Giả sử glwVal.J có phương thức ToString()
	}

	// 5. Gọi fmt.Sprintf với chuỗi định dạng đã được xử lý và các đối số.
	// Thứ tự các đối số ở đây phải khớp với chỉ mục trong %[index]s.
	formatted := fmt.Sprintf(tempFormatStr,
		techniqueClassifier,                // Đối số 1 cho %[1]s
		templateData.randomString5a,        // Đối số 2 cho %[2]s
		templateData.randomString5b,        // Đối số 3 cho %[3]s
		templateData.randomString8,         // Đối số 4 cho %[4]s
		templateData.randomString10,        // Đối số 5 cho %[5]s
		templateData.randomNumericSuffix1,  // Đối số 6 cho %[6]s
		templateData.randomNumericSuffix2,  // Đối số 7 cho %[7]s
		templateData.randomNumericSuffix3,  // Đối số 8 cho %[8]s
		templateData.randomInvalidTagName5, // Đối số 9 cho %[9]s
	)

	return formatted
}

// PreparePayloadTemplateDataForBuilder corresponds to 'static glw a(hgm var0, String var1)'
func PreparePayloadTemplateDataForBuilder(
	builder *ScanProbeBuilder,
	baseFormatString string,
) *PayloadGenerationTemplate {
	if builder != nil {
		return builder.preparePayloadTemplateData(baseFormatString)
	}
	return nil
}
