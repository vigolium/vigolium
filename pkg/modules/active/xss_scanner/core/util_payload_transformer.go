package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// BytePayloadModifier định nghĩa interface cho việc biến đổi payload.
// Tên cũ: C5s
type BytePayloadModifier interface {
	Modify(payload []byte) []byte
}

// PayloadModificationContext lưu trữ dữ liệu ngữ cảnh cho việc biến đổi.
// Tên cũ: D2, tương đương với lớp d2 trong Java.
type PayloadModificationContext struct {
	// byte[] d trong Java; lưu trữ dữ liệu chính
	primaryData []byte
	// byte[] a trong Java; lưu trữ tiền tố (prefix)
	prefixData []byte // Được export vì được truy cập gián tiếp
	// byte[] c trong Java; kết hợp của prefix, mainData, và breakoutPayload
	dataWithBreakoutSequence []byte
	// byte[] e trong Java; payload dùng để thoát khỏi ngữ cảnh (breakout)
	breakoutSequenceBytes []byte
}

// NewPayloadModificationContextWithPrefix tạo một TransformContext mới với tiền tố và dữ liệu chính.
// Tên cũ: NewD2WithPrefix
func NewPayloadModificationContextWithPrefix(
	prefix []byte,
	mainData []byte,
	randomProvider *utils.RandomGenerator,
) *PayloadModificationContext {
	context := &PayloadModificationContext{}
	context.primaryData = mainData
	context.prefixData = prefix

	randomComponent := ""
	if randomProvider != nil {
		randomComponent = randomProvider.GeneratePrefixedAlphanumeric(5) // Lấy phần ngẫu nhiên từ netOu
	}
	breakoutSequenceString := randomComponent + "'/\"<" + randomComponent // Escaped the double quote
	context.breakoutSequenceBytes = utils.StringToBytes(breakoutSequenceString)

	// Combine prefix, mainData, and breakout payload
	context.dataWithBreakoutSequence = utils.CombineByteSlices(
		prefix,
		mainData,
		context.breakoutSequenceBytes,
	)

	return context
}

// NewPayloadModificationContext tạo một TransformContext mới với tiền tố rỗng.
// Tên cũ: NewD2
func NewPayloadModificationContext(
	mainData []byte,
	randomProvider *utils.RandomGenerator,
) *PayloadModificationContext {
	// this(new byte[0], var1, var2); trong Java
	return NewPayloadModificationContextWithPrefix([]byte{}, mainData, randomProvider)
}

// GetPrefixedPrimaryData trả về dữ liệu chính đã được gắn tiền tố.
// Tương đương với public byte[] b() trong Java class d2.
// Tên cũ: B
func (tc *PayloadModificationContext) GetPrefixedPrimaryData() []byte {
	// Combine prefix and primary data
	return utils.CombineByteSlices(tc.prefixData, tc.primaryData)
}

// HasPrefix kiểm tra xem context có tiền tố hay không.
// Tương đương với boolean a() trong Java class d2.
// Tên cũ: A_Bool
func (tc *PayloadModificationContext) HasPrefix() bool {
	return len(tc.prefixData) > 0
}

// PrefixingPayloadModifier implement PayloadTransformer, áp dụng biến đổi dựa trên TransformContext.
// Tên cũ: El6, tương đương với lớp el6 trong Java.
type PrefixingPayloadModifier struct {
	// final d2 a; trong Java
	context *PayloadModificationContext // Ngữ cảnh chứa tiền tố và dữ liệu chính
}

// NewPrefixingPayloadModifier tạo một instance mới của ContextualPayloadTransformer.
// Tên cũ: NewEl6
func NewPrefixingPayloadModifier(
	context *PayloadModificationContext,
) *PrefixingPayloadModifier {
	return &PrefixingPayloadModifier{
		context: context,
	}
}

// A implement PayloadTransformer, kết hợp dữ liệu từ context với payload đầu vào.
// Tương đương với public byte[] a(byte[] var1) trong Java class el6.
func (ct *PrefixingPayloadModifier) Modify(payload []byte) []byte {
	if ct.context == nil {
		// Nếu context là nil, trả về payload gốc hoặc xử lý lỗi phù hợp
		return payload
	}

	// Sao chép payload đầu vào để đảm bảo không thay đổi slice gốc,
	// tương tự Arrays.copyOf trong Java.
	inputPayloadCopy := make([]byte, len(payload))
	copy(inputPayloadCopy, payload)

	// Lấy dữ liệu đã được prefix từ context
	contextPrefixedData := ct.context.GetPrefixedPrimaryData()
	// Kết hợp dữ liệu đã prefix với payload đã sao chép
	return utils.CombineByteSlices(contextPrefixedData, inputPayloadCopy)
}

// NoOpPayloadModifier implement PayloadTransformer, trả về payload đầu vào không thay đổi.
// Tên cũ: E, tương đương với lớp e trong Java.
type NoOpPayloadModifier struct{}

func NewNoOpPayloadModifier() BytePayloadModifier {
	return &NoOpPayloadModifier{}
}

// A implement PayloadTransformer, trả về payload đầu vào không thay đổi.
// Tương đương với public byte[] a(byte[] var1) trong Java class e.
func (pt *NoOpPayloadModifier) Modify(payload []byte) []byte {
	// Trả về payload đầu vào mà không thay đổi
	return payload
}
