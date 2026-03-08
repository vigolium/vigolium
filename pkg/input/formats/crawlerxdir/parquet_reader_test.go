package crawlerxdir

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xitongsys/parquet-go-source/local"
	"github.com/xitongsys/parquet-go/writer"
)

// createDummyParquetFile tạo một tệp Parquet giả với số lượng bản ghi cho trước.
// Nó sử dụng cấu trúc ParquetRecord được định nghĩa trong gói crawlerxdir.
func createDummyParquetFile(t *testing.T, filePath string, numRecords int) {
	t.Helper()

	fw, err := local.NewLocalFileWriter(filePath)
	require.NoError(t, err, "Lỗi khi tạo local file writer: %s", filePath)
	defer func() { _ = fw.Close() }()

	// Giả định ParquetRecord được định nghĩa trong gói và có các trường cần thiết.
	// Ví dụ: URL, Source, Timestamp, Method, Depth.
	// Nếu cấu trúc thực tế khác, cần điều chỉnh phần này.
	pw, err := writer.NewParquetWriter(
		fw,
		new(ParquetRecord),
		4,
	) // Sử dụng ParquetRecord từ package
	require.NoError(t, err, "Lỗi khi tạo parquet writer cho: %s", filePath)

	for i := 0; i < numRecords; i++ {
		// Tạo một bản ghi mẫu. Các trường này phải khớp với định nghĩa ParquetRecord thực tế.
		record := ParquetRecord{
			Url: fmt.Sprintf("http://example.com/page_%s_%d", filepath.Base(filePath), i),
			// Source:    "testSource", // Tạm thời loại bỏ
			// Timestamp: time.Now().UnixNano(), // Tạm thời loại bỏ
			// Method:    "GET", // Tạm thời loại bỏ
			// Depth:     int32(i % 3), // Tạm thời loại bỏ
			// Thêm các trường khác nếu ParquetRecord có
		}
		err = pw.Write(record)
		require.NoError(t, err, "Lỗi khi ghi bản ghi vào tệp parquet: %s", filePath)
	}

	err = pw.WriteStop()
	require.NoError(t, err, "Lỗi khi dừng parquet writer cho: %s", filePath)
}

// createTestDirWithParquetFiles tạo một thư mục tạm với số lượng tệp Parquet cho trước.
func createTestDirWithParquetFiles(
	t *testing.T,
	numFiles int,
	recordsPerFile int,
	prefix string,
) (string, int) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "parquet_test_"+prefix+"_")
	require.NoError(t, err, "Lỗi khi tạo thư mục tạm")

	totalRecords := 0
	for i := 0; i < numFiles; i++ {
		fileName := fmt.Sprintf("%s_file_%d.parquet", prefix, i)
		filePath := filepath.Join(tmpDir, fileName)
		createDummyParquetFile(t, filePath, recordsPerFile)
		totalRecords += recordsPerFile
	}
	return tmpDir, totalRecords
}

// setupTestDir tạo một thư mục tạm với cấu hình file cụ thể.
func setupTestDir(t *testing.T, fileSetups map[string]int) string {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "parquet_test_setup_")
	require.NoError(t, err, "Lỗi khi tạo thư mục tạm cho setup")

	for name, numRecords := range fileSetups {
		filePath := filepath.Join(tmpDir, name)
		if strings.HasSuffix(strings.ToLower(name), ".parquet") {
			createDummyParquetFile(t, filePath, numRecords)
		} else {
			// Tạo file rỗng không phải parquet
			f, createErr := os.Create(filePath)
			require.NoError(t, createErr, "Lỗi khi tạo file không phải parquet: %s", filePath)
			_ = f.Close()
		}
	}
	return tmpDir
}

// createParquetFile là hàm tiện ích để tạo file Parquet với các record cho trước
// Hàm này tạo file Parquet với các record được cung cấp.
func createParquetFile(t *testing.T, filePath string, records []ParquetRecord) {
	t.Helper()

	// Đảm bảo thư mục chứa file tồn tại
	err := os.MkdirAll(filepath.Dir(filePath), 0755)
	require.NoError(t, err, "Không thể tạo thư mục cho file parquet thử nghiệm")

	fw, err := local.NewLocalFileWriter(filePath)
	require.NoError(t, err, "Không thể tạo local file writer")
	defer func() { _ = fw.Close() }()

	// Sử dụng NP=1 để ghi một cách tuần tự trong các bài test, có thể điều chỉnh nếu cần
	// ParquetRecord được truyền vào writer để xác định schema
	pw, err := writer.NewParquetWriter(fw, new(ParquetRecord), 1)
	require.NoError(t, err, "Không thể tạo parquet writer")

	for _, rec := range records {
		// pw.Write mong đợi một struct, không phải con trỏ, khi NewParquetWriter được khởi tạo với new(ParquetRecord)
		err = pw.Write(rec)
		require.NoError(t, err, "Không thể ghi record vào file parquet")
	}

	err = pw.WriteStop()
	require.NoError(t, err, "Không thể dừng parquet writer")
}

func TestNewParquetReader_MaxOpenFiles_TooLarge(t *testing.T) {
	numFiles := 2
	recordsPerFile := 5
	maxOpen := 5 // Lớn hơn số file hiện có
	testDir, _ := createTestDirWithParquetFiles(t, numFiles, recordsPerFile, "max_large")
	defer func() { _ = os.RemoveAll(testDir) }()

	pr, err := NewParquetReader(testDir, maxOpen)
	require.NoError(t, err)
	require.NotNil(t, pr)
	defer pr.Close()

	assert.Equal(t, numFiles, len(pr.activeReaders), "Số active readers nên bằng số lượng file")
	assert.Equal(
		t,
		numFiles,
		pr.maxOpenFiles,
		"maxOpenFiles nên được điều chỉnh bằng số lượng file",
	)
}

func TestNewParquetReader_MaxOpenFiles_Zero(t *testing.T) {
	numFiles := DefaultMaxOpenFiles + 2 // Đảm bảo nhiều file hơn DefaultMaxOpenFiles
	recordsPerFile := 1
	maxOpen := 0 // maxOpen = 0
	testDir, _ := createTestDirWithParquetFiles(t, numFiles, recordsPerFile, "max_zero")
	defer func() { _ = os.RemoveAll(testDir) }()

	pr, err := NewParquetReader(testDir, maxOpen)
	require.NoError(t, err)
	require.NotNil(t, pr)
	defer pr.Close()

	expectedMaxOpenResult := DefaultMaxOpenFiles
	if numFiles < DefaultMaxOpenFiles { // Trường hợp file ít hơn default
		expectedMaxOpenResult = numFiles
	}

	assert.Equal(
		t,
		expectedMaxOpenResult,
		len(pr.activeReaders),
		"Số active readers không khớp với DefaultMaxOpenFiles (hoặc số file)",
	)
	assert.Equal(
		t,
		expectedMaxOpenResult,
		pr.maxOpenFiles,
		"maxOpenFiles không khớp với DefaultMaxOpenFiles (hoặc số file)",
	)
}

func TestNewParquetReader_MaxOpenFiles_Negative(t *testing.T) {
	numFiles := DefaultMaxOpenFiles + 2
	recordsPerFile := 1
	maxOpen := -5 // maxOpen âm
	testDir, _ := createTestDirWithParquetFiles(t, numFiles, recordsPerFile, "max_neg")
	defer func() { _ = os.RemoveAll(testDir) }()

	pr, err := NewParquetReader(testDir, maxOpen)
	require.NoError(t, err)
	require.NotNil(t, pr)
	defer pr.Close()

	expectedMaxOpenResult := DefaultMaxOpenFiles
	if numFiles < DefaultMaxOpenFiles {
		expectedMaxOpenResult = numFiles
	}
	assert.Equal(t, expectedMaxOpenResult, len(pr.activeReaders))
	assert.Equal(t, expectedMaxOpenResult, pr.maxOpenFiles)
}

func TestNewParquetReader_NoParquetFilesInDir(t *testing.T) {
	tmpDir := setupTestDir(t, map[string]int{"not_a_parquet.txt": 0, "another_file.doc": 0})
	defer func() { _ = os.RemoveAll(tmpDir) }()

	pr, err := NewParquetReader(tmpDir, 5)
	assert.Error(t, err, "Nên có lỗi khi không có file .parquet nào trong thư mục")
	if err != nil {
		assert.Contains(t, err.Error(), "no .parquet files found", "Thông báo lỗi không chính xác")
	}
	assert.Nil(t, pr, "ParquetReader nên là nil khi có lỗi")
}

func TestNewParquetReader_EmptyDir(t *testing.T) {
	tmpDir, errMkdir := os.MkdirTemp("", "empty_dir_test_")
	require.NoError(t, errMkdir)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	pr, err := NewParquetReader(tmpDir, 5)
	assert.Error(t, err, "Nên có lỗi khi thư mục rỗng")
	if err != nil {
		assert.Contains(t, err.Error(), "no .parquet files found", "Thông báo lỗi không chính xác")
	}
	assert.Nil(t, pr)
}

func TestNewParquetReader_InvalidDir(t *testing.T) {
	nonExistentDir := filepath.Join(
		os.TempDir(),
		"non_existent_dir_for_parquet_test_"+strconv.FormatInt(time.Now().UnixNano(), 10),
	)
	pr, err := NewParquetReader(nonExistentDir, 5)
	assert.Error(t, err, "Nên có lỗi khi thư mục không tồn tại")
	if err != nil {
		// Lỗi có thể là "error listing parquet files: error walking directory..."
		assert.Contains(
			t,
			err.Error(),
			"error listing parquet files",
			"Thông báo lỗi cần chứa 'error listing parquet files'",
		)
	}
	assert.Nil(t, pr)
}

func TestNewParquetReader_CouldNotOpenAnyInitialFiles(t *testing.T) {
	tmpDir, errMkdir := os.MkdirTemp("", "corrupt_parquet_test_")
	require.NoError(t, errMkdir)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Tạo các file rỗng (0 byte) với đuôi .parquet.
	// reader.NewParquetReader sẽ thất bại với các file này.
	for i := 0; i < 3; i++ {
		filePath := filepath.Join(tmpDir, fmt.Sprintf("empty_corrupt_%d.parquet", i))
		f, createErr := os.Create(filePath)
		require.NoError(t, createErr)
		_ = f.Close() // File rỗng, trình đọc parquet sẽ không mở được.
	}

	pr, err := NewParquetReader(tmpDir, 2) // Cố gắng mở 2 file
	assert.Error(t, err, "Nên có lỗi vì không thể mở bất kỳ file parquet nào ban đầu")
	if err != nil {
		assert.Contains(
			t,
			err.Error(),
			"could not open any parquet files for reading",
			"Thông báo lỗi không chính xác",
		)
	}
	assert.Nil(t, pr)
}

// --- Tests for Reading Records ---

func TestParquetReader_ReadRecords_SingleFile(t *testing.T) {
	numFiles := 1
	recordsPerFile := 5
	maxOpen := 1
	testDir, expectedTotalRecords := createTestDirWithParquetFiles(
		t,
		numFiles,
		recordsPerFile,
		"read_single",
	)
	defer func() { _ = os.RemoveAll(testDir) }()

	pr, err := NewParquetReader(testDir, maxOpen)
	require.NoError(t, err)
	require.NotNil(t, pr)
	defer pr.Close()

	var recordsRead []ParquetRecord
	for {
		record, ok, errRead := pr.Next()
		require.NoError(t, errRead, "pr.Next() không nên trả về lỗi")
		if !ok {
			break // Không còn bản ghi nào
		}
		recordsRead = append(recordsRead, record)
	}
	assert.Equal(t, expectedTotalRecords, len(recordsRead), "Số lượng bản ghi đọc được không khớp")
}

func TestParquetReader_ReadRecords_MultipleFiles_LessThanMaxOpen(t *testing.T) {
	numFiles := 2
	recordsPerFile := 3
	maxOpen := 3 // maxOpen lớn hơn hoặc bằng số file
	testDir, expectedTotalRecords := createTestDirWithParquetFiles(
		t,
		numFiles,
		recordsPerFile,
		"read_less_max",
	)
	defer func() { _ = os.RemoveAll(testDir) }()

	pr, err := NewParquetReader(testDir, maxOpen)
	require.NoError(t, err)
	require.NotNil(t, pr)
	defer pr.Close()

	count := 0
	for {
		_, ok, errRead := pr.Next()
		require.NoError(t, errRead)
		if !ok {
			break
		}
		count++
	}
	assert.Equal(t, expectedTotalRecords, count, "Tổng số bản ghi đọc được không khớp")
}

func TestParquetReader_ReadRecords_MultipleFiles_MoreThanMaxOpen(t *testing.T) {
	numFiles := 5 // Nhiều file hơn maxOpen
	recordsPerFile := 4
	maxOpen := 3
	testDir, expectedTotalRecords := createTestDirWithParquetFiles(
		t,
		numFiles,
		recordsPerFile,
		"read_more_max",
	)
	defer func() { _ = os.RemoveAll(testDir) }()

	pr, err := NewParquetReader(testDir, maxOpen)
	require.NoError(t, err)
	require.NotNil(t, pr)
	defer pr.Close()

	// Kiểm tra số active reader ban đầu
	initialActiveReaders := maxOpen
	if numFiles < maxOpen {
		initialActiveReaders = numFiles
	}
	assert.Equal(
		t,
		initialActiveReaders,
		len(pr.activeReaders),
		"Số active reader ban đầu không khớp",
	)

	count := 0
	var wg sync.WaitGroup
	// Dùng channel để thu thập bản ghi từ goroutine đọc, tránh deadlock nếu buffer đầy
	recordChan := make(chan ParquetRecord, expectedTotalRecords)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(recordChan) // Đóng channel khi goroutine đọc xong
		for {
			record, ok, errRead := pr.Next()
			if errRead != nil {
				// Sử dụng t.Errorf vì nó an toàn cho goroutine
				t.Errorf("Lỗi khi gọi Next(): %v", errRead)
				return
			}
			if !ok {
				return // Kết thúc đọc
			}
			recordChan <- record
		}
	}()

	for range recordChan { // Đọc từ channel cho đến khi nó đóng
		count++
	}
	wg.Wait() // Đợi goroutine đọc hoàn thành

	assert.Equal(t, expectedTotalRecords, count, "Tổng số bản ghi đọc được không khớp")
}

func TestParquetReader_ReadRecords_NoRecordsInFiles(t *testing.T) {
	numFiles := 2
	recordsPerFile := 0 // Không có bản ghi nào trong các file
	maxOpen := 2
	testDir, expectedTotalRecords := createTestDirWithParquetFiles(
		t,
		numFiles,
		recordsPerFile,
		"read_no_records",
	)
	assert.Equal(t, 0, expectedTotalRecords, "Dự kiến không có bản ghi nào")
	defer func() { _ = os.RemoveAll(testDir) }()

	// Parquet files with 0 records cannot be opened by the parquet library
	// so NewParquetReader should return an error
	pr, err := NewParquetReader(testDir, maxOpen)
	require.Error(t, err, "Parquet files with 0 records cannot be opened")
	require.Nil(t, pr)
}

func TestParquetReader_ReadRecords_WithSomeEmptyFiles(t *testing.T) {
	tmpDir, errMkdir := os.MkdirTemp("", "parquet_some_empty_")
	require.NoError(t, errMkdir)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// File 1: 5 records
	createDummyParquetFile(t, filepath.Join(tmpDir, "file1.parquet"), 5)
	// File 2: 0 records (rỗng)
	createDummyParquetFile(t, filepath.Join(tmpDir, "file2_empty.parquet"), 0)
	// File 3: 3 records
	createDummyParquetFile(t, filepath.Join(tmpDir, "file3.parquet"), 3)
	// File 4: 0 records (rỗng)
	createDummyParquetFile(t, filepath.Join(tmpDir, "file4_empty.parquet"), 0)

	expectedTotalRecords := 5 + 0 + 3 + 0
	maxOpen := 2 // Để kiểm tra logic thay thế reader

	pr, err := NewParquetReader(tmpDir, maxOpen)
	require.NoError(t, err)
	require.NotNil(t, pr)
	defer pr.Close()

	count := 0
	for {
		_, ok, errRead := pr.Next()
		require.NoError(t, errRead, "Đọc bản ghi không nên gây lỗi")
		if !ok {
			break
		}
		count++
	}
	assert.Equal(
		t,
		expectedTotalRecords,
		count,
		"Tổng số bản ghi đọc được không khớp khi có file rỗng",
	)
}

// --- Tests for Close ---

func TestParquetReader_Close_Idempotent(t *testing.T) {
	testDir, _ := createTestDirWithParquetFiles(t, 1, 1, "close_idem")
	defer func() { _ = os.RemoveAll(testDir) }()

	pr, err := NewParquetReader(testDir, 1)
	require.NoError(t, err)
	require.NotNil(t, pr)

	pr.Close() // Gọi Close lần đầu
	assert.NotPanics(t, func() { pr.Close() }, "Gọi Close() nhiều lần không nên gây panic")

	// Thử đọc sau khi đóng
	_, ok, errAfterClose := pr.Next()
	assert.False(t, ok, "Next() nên trả về false sau khi Close()")
	assert.NoError(t, errAfterClose, "Next() nên trả về lỗi nil sau khi Close() và buffer đã rỗng")
}

// Có thể thêm các test khác nếu cần, ví dụ:
// - Test với file parquet bị hỏng một phần (khó mô phỏng chính xác lỗi đọc giữa chừng).
// - Test performance (ngoài phạm vi unit test điển hình).

// TestParquetReader_SingleFile kiểm tra việc đọc từ một file Parquet duy nhất.
// Nó xác minh số lượng record, nội dung và thứ tự của chúng.
func TestParquetReader_SingleFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "parquet_test_single")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	expectedRecords := []ParquetRecord{
		{
			Url:                "http://example.com/page1",
			ResultType:         "page",
			InputURL:           "http://example.com",
			RequestMethod:      "GET",
			ResponseStatusCode: 200,
			Time:               "2023-01-01T10:00:00Z",
			RequestHeaders:     map[string]string{"X-Test": "val1"},
			ResponseHeaders:    map[string]string{"Content-Type": "text/html"},
		},
		{
			Url:                "http://example.com/page2",
			ResultType:         "page",
			InputURL:           "http://example.com",
			RequestMethod:      "GET",
			ResponseStatusCode: 200,
			Time:               "2023-01-01T10:00:01Z",
			RequestHeaders:     map[string]string{},
			ResponseHeaders:    map[string]string{},
		},
		{
			Url:                "http://example.com/api/data",
			ResultType:         "api",
			InputURL:           "http://example.com",
			RequestMethod:      "POST",
			ResponseStatusCode: 201,
			Time:               "2023-01-01T10:00:02Z",
			ResponseBodyData:   "{\"id\":1}",
			RequestHeaders:     map[string]string{},
			ResponseHeaders:    map[string]string{},
		},
	}
	filePath := filepath.Join(tempDir, "single_file.parquet")
	createParquetFile(t, filePath, expectedRecords)

	reader, err := NewParquetReader(tempDir, DefaultMaxOpenFiles)
	require.NoError(t, err, "NewParquetReader thất bại")
	require.NotNil(t, reader, "NewParquetReader trả về reader là nil")
	defer reader.Close()

	var SUTRecords []ParquetRecord // SUT (System Under Test)
	count := 0
	for {
		record, hasNext, errLoop := reader.Next()
		require.NoError(t, errLoop, "reader.Next() trả về lỗi")
		if !hasNext {
			break
		}
		SUTRecords = append(SUTRecords, record)
		count++
	}

	assert.Equal(t, len(expectedRecords), count, "Số lượng record đọc được không khớp")
	assert.Equal(
		t,
		len(expectedRecords),
		len(SUTRecords),
		"Số lượng record trong slice SUTRecords không khớp",
	)

	// Xác minh nội dung và thứ tự
	for i, expected := range expectedRecords {
		if i < len(SUTRecords) {
			assert.True(
				t,
				reflect.DeepEqual(expected, SUTRecords[i]),
				"Nội dung record %d không khớp. Mong đợi:\n%#v\nNhận được:\n%#v",
				i,
				expected,
				SUTRecords[i],
			)
		}
	}
}

// TestParquetReader_MultipleFiles kiểm tra việc đọc từ nhiều file Parquet.
// Nó xác minh tổng số lượng record và sự hiện diện của tất cả các record mong đợi.
// Thứ tự chính xác giữa các file không được đảm bảo do cơ chế xáo trộn và round-robin.
func TestParquetReader_MultipleFiles(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "parquet_test_multi")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	file1Records := []ParquetRecord{
		{
			Url:                "http://file1.com/page1",
			ResultType:         "page",
			InputURL:           "http://file1.com",
			RequestMethod:      "GET",
			ResponseStatusCode: 200,
			Time:               "2023-02-01T10:00:00Z",
			RequestHeaders:     map[string]string{},
			ResponseHeaders:    map[string]string{},
		},
		{
			Url:                "http://file1.com/page2",
			ResultType:         "page",
			InputURL:           "http://file1.com",
			RequestMethod:      "GET",
			ResponseStatusCode: 404,
			Time:               "2023-02-01T10:00:01Z",
			RequestHeaders:     map[string]string{},
			ResponseHeaders:    map[string]string{},
		},
	}
	file2Records := []ParquetRecord{
		{
			Url:                "http://file2.com/resourceA",
			ResultType:         "resource",
			InputURL:           "http://file2.com",
			RequestMethod:      "GET",
			ResponseStatusCode: 200,
			Time:               "2023-02-01T11:00:00Z",
			RequestHeaders:     map[string]string{"Auth": "Bearer"},
			ResponseHeaders:    map[string]string{},
		},
	}
	file3Records := []ParquetRecord{
		{
			Url:                "http://file3.com/item1",
			ResultType:         "item",
			InputURL:           "http://file3.com",
			RequestMethod:      "PUT",
			ResponseStatusCode: 200,
			Time:               "2023-02-01T12:00:00Z",
			RequestHeaders:     map[string]string{},
			ResponseHeaders:    map[string]string{},
		},
		{
			Url:                "http://file3.com/item2",
			ResultType:         "item",
			InputURL:           "http://file3.com",
			RequestMethod:      "DELETE",
			ResponseStatusCode: 204,
			Time:               "2023-02-01T12:00:01Z",
			RequestHeaders:     map[string]string{},
			ResponseHeaders:    map[string]string{},
		},
		{
			Url:                "http://file3.com/item3",
			ResultType:         "item",
			InputURL:           "http://file3.com",
			RequestMethod:      "GET",
			ResponseStatusCode: 500,
			Time:               "2023-02-01T12:00:02Z",
			RequestHeaders:     map[string]string{},
			ResponseHeaders:    map[string]string{},
		},
	}

	createParquetFile(t, filepath.Join(tempDir, "file1.parquet"), file1Records)
	createParquetFile(
		t,
		filepath.Join(tempDir, "sub", "file2.parquet"),
		file2Records,
	) // File trong thư mục con
	createParquetFile(t, filepath.Join(tempDir, "file3.parquet"), file3Records)

	// Sử dụng maxOpenFiles nhỏ hơn tổng số file để kiểm tra việc quản lý file
	// (Mặc dù ParquetReader hiện tại không tự động mở file mới khi một file cũ đóng lại)
	reader, err := NewParquetReader(tempDir, 2)
	require.NoError(t, err, "NewParquetReader thất bại")
	require.NotNil(t, reader, "NewParquetReader trả về reader là nil")
	defer reader.Close()

	var SUTRecords []ParquetRecord
	for {
		record, hasNext, errLoop := reader.Next()
		require.NoError(t, errLoop, "reader.Next() trả về lỗi")
		if !hasNext {
			break
		}
		SUTRecords = append(SUTRecords, record)
	}

	allExpectedRecords := append(append(file1Records, file2Records...), file3Records...)
	assert.Equal(
		t,
		len(allExpectedRecords),
		len(SUTRecords),
		"Tổng số lượng record đọc được không khớp",
	)

	// Để xác minh nội dung khi thứ tự không được đảm bảo:
	// Sắp xếp cả hai slice dựa trên một khóa duy nhất (ví dụ: URL cho dữ liệu test này)
	sort.SliceStable(allExpectedRecords, func(i, j int) bool {
		return allExpectedRecords[i].Url < allExpectedRecords[j].Url
	})
	sort.SliceStable(SUTRecords, func(i, j int) bool {
		return SUTRecords[i].Url < SUTRecords[j].Url
	})

	// Thêm log chi tiết nếu DeepEqual thất bại
	if !reflect.DeepEqual(allExpectedRecords, SUTRecords) {
		t.Logf("Mismatch detected. Printing sorted expected vs actual records for comparison:")
		maxLen := len(allExpectedRecords)
		if len(SUTRecords) > maxLen {
			maxLen = len(SUTRecords)
		}
		for i := 0; i < maxLen; i++ {
			var expectedStr, actualStr string
			match := true

			if i < len(allExpectedRecords) {
				expectedStr = fmt.Sprintf("%#v", allExpectedRecords[i])
			} else {
				expectedStr = "N/A (no corresponding expected record)"
				match = false
			}

			if i < len(SUTRecords) {
				actualStr = fmt.Sprintf("%#v", SUTRecords[i])
			} else {
				actualStr = "N/A (no corresponding actual record)"
				match = false
			}

			if match && i < len(allExpectedRecords) && i < len(SUTRecords) {
				match = reflect.DeepEqual(allExpectedRecords[i], SUTRecords[i])
			}

			if !match {
				t.Logf(
					"Record %d (after sorting by URL):\nExpected: %s\nActual:   %s\n---",
					i,
					expectedStr,
					actualStr,
				)
			}
		}
	}

	assert.True(
		t,
		reflect.DeepEqual(allExpectedRecords, SUTRecords),
		"Tập hợp các record đọc được không khớp với tập hợp các record mong đợi",
	)
}

// TestParquetReader_NoParquetFiles kiểm tra trường hợp không có file .parquet nào trong thư mục.
// NewParquetReader dự kiến sẽ trả về lỗi.
func TestParquetReader_NoParquetFiles(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "parquet_test_no_files")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Tạo một file không phải parquet để đảm bảo nó bị bỏ qua
	_, err = os.Create(filepath.Join(tempDir, "somefile.txt"))
	require.NoError(t, err)

	reader, err := NewParquetReader(tempDir, DefaultMaxOpenFiles)
	require.Error(t, err, "NewParquetReader nên trả về lỗi khi không tìm thấy file parquet nào")
	assert.Contains(t, err.Error(), "no .parquet files found", "Thông báo lỗi không khớp")
	require.Nil(t, reader, "Reader nên là nil khi có lỗi")
}

// TestParquetReader_OnlyEmptyParquetFiles kiểm tra trường hợp thư mục chỉ chứa các file .parquet rỗng.
// NewParquetReader dự kiến sẽ trả về lỗi vì không mở được file nào có thể đọc được.
func TestParquetReader_OnlyEmptyParquetFiles(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "parquet_test_empty_files")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	emptyRecords := []ParquetRecord{} // 0 records
	createParquetFile(t, filepath.Join(tempDir, "empty1.parquet"), emptyRecords)
	createParquetFile(t, filepath.Join(tempDir, "sub", "empty2.parquet"), emptyRecords)

	reader, err := NewParquetReader(tempDir, DefaultMaxOpenFiles)
	require.Error(
		t,
		err,
		"NewParquetReader nên trả về lỗi nếu tất cả các file đều rỗng/không thể đọc được",
	)
	// openFile sẽ trả về lỗi cho các file rỗng (numRows == 0),
	// vì vậy NewParquetReader sẽ không tìm thấy activeReaders nào.
	assert.Contains(
		t,
		err.Error(),
		"could not open any parquet files for reading",
		"Thông báo lỗi nên chỉ ra không thể mở file nào",
	)
	require.Nil(t, reader, "Reader nên là nil khi có lỗi")
}

// TestParquetReader_FileWithOneRecord kiểm tra việc đọc một file chỉ có một record.
func TestParquetReader_FileWithOneRecord(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "parquet_test_one_rec")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Sử dụng time.Now() để đảm bảo giá trị Time là hợp lệ nếu logic cụ thể dựa vào nó
	expectedRecords := []ParquetRecord{
		{
			Url:                "http://onerec.com/page",
			ResultType:         "page",
			InputURL:           "http://onerec.com",
			RequestMethod:      "GET",
			ResponseStatusCode: 200,
			Time:               time.Now().Format(time.RFC3339),
			RequestHeaders:     map[string]string{},
			ResponseHeaders:    map[string]string{},
		},
	}
	filePath := filepath.Join(tempDir, "one_record_file.parquet")
	createParquetFile(t, filePath, expectedRecords)

	reader, err := NewParquetReader(tempDir, DefaultMaxOpenFiles)
	require.NoError(t, err, "NewParquetReader thất bại")
	require.NotNil(t, reader, "NewParquetReader trả về reader là nil")
	defer reader.Close()

	var SUTRecords []ParquetRecord
	count := 0
	for {
		record, hasNext, errLoop := reader.Next()
		require.NoError(t, errLoop, "reader.Next() trả về lỗi")
		if !hasNext {
			break
		}
		SUTRecords = append(SUTRecords, record)
		count++
	}

	assert.Equal(t, 1, count, "Số lượng record đọc được phải là 1")
	require.Equal(t, 1, len(SUTRecords), "Slice SUTRecords phải chứa 1 record")
	assert.True(
		t,
		reflect.DeepEqual(expectedRecords[0], SUTRecords[0]),
		"Nội dung record không khớp cho file có một record",
	)
}

// TestParquetReader_MixedValidAndEmptyFiles kiểm tra việc đọc từ thư mục chứa cả file hợp lệ và file rỗng.
// Chỉ các record từ file hợp lệ mới được đọc.
func TestParquetReader_MixedValidAndEmptyFiles(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "parquet_test_mixed")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	validRecords := []ParquetRecord{
		{
			Url:                "http://valid.com/data1",
			ResultType:         "data",
			ResponseStatusCode: 200,
			Time:               "t1",
			RequestHeaders:     map[string]string{},
			ResponseHeaders:    map[string]string{},
		},
		{
			Url:                "http://valid.com/data2",
			ResultType:         "data",
			ResponseStatusCode: 200,
			Time:               "t2",
			RequestHeaders:     map[string]string{},
			ResponseHeaders:    map[string]string{},
		},
	}
	emptyRecords := []ParquetRecord{} // File này sẽ bị bỏ qua bởi openFile

	createParquetFile(t, filepath.Join(tempDir, "valid_file.parquet"), validRecords)
	createParquetFile(t, filepath.Join(tempDir, "another_empty.parquet"), emptyRecords)
	createParquetFile(t, filepath.Join(tempDir, "sub", "deep_empty.parquet"), emptyRecords)

	reader, err := NewParquetReader(tempDir, DefaultMaxOpenFiles)
	require.NoError(
		t,
		err,
		"NewParquetReader thất bại, mong đợi thành công với ít nhất một file hợp lệ",
	)
	require.NotNil(t, reader, "Reader không nên là nil")
	defer reader.Close()

	var SUTRecords []ParquetRecord
	for {
		record, hasNext, errLoop := reader.Next()
		require.NoError(t, errLoop, "reader.Next() trả về lỗi")
		if !hasNext {
			break
		}
		SUTRecords = append(SUTRecords, record)
	}

	assert.Equal(
		t,
		len(validRecords),
		len(SUTRecords),
		"Số lượng record đọc được không khớp với số record hợp lệ mong đợi",
	)

	// Sắp xếp để so sánh nội dung không phụ thuộc vào thứ tự đọc
	sort.SliceStable(
		validRecords,
		func(i, j int) bool { return validRecords[i].Url < validRecords[j].Url },
	)
	sort.SliceStable(
		SUTRecords,
		func(i, j int) bool { return SUTRecords[i].Url < SUTRecords[j].Url },
	)

	// Thêm log chi tiết nếu DeepEqual thất bại
	if !reflect.DeepEqual(validRecords, SUTRecords) {
		t.Logf("Mismatch detected. Printing sorted expected vs actual records for comparison:")
		maxLen := len(validRecords)
		if len(SUTRecords) > maxLen {
			maxLen = len(SUTRecords)
		}
		for i := 0; i < maxLen; i++ {
			var expectedStr, actualStr string
			match := true

			if i < len(validRecords) {
				expectedStr = fmt.Sprintf("%#v", validRecords[i])
			} else {
				expectedStr = "N/A (no corresponding expected record)"
				match = false
			}

			if i < len(SUTRecords) {
				actualStr = fmt.Sprintf("%#v", SUTRecords[i])
			} else {
				actualStr = "N/A (no corresponding actual record)"
				match = false
			}

			if match && i < len(validRecords) && i < len(SUTRecords) {
				match = reflect.DeepEqual(validRecords[i], SUTRecords[i])
			}

			if !match {
				t.Logf(
					"Record %d (after sorting by URL):\nExpected: %s\nActual:   %s\n---",
					i,
					expectedStr,
					actualStr,
				)
			}
		}
	}

	assert.True(
		t,
		reflect.DeepEqual(validRecords, SUTRecords),
		"Tập hợp các record đọc được không khớp với tập hợp các record hợp lệ mong đợi",
	)
}

// TestParquetReader_ManyFiles_RandomRecords_ContentValidation kiểm tra việc đọc từ nhiều file (50 files)
// với số lượng record ngẫu nhiên (1-50) trong mỗi file.
// Nó xác minh tổng số lượng record và sự hiện diện của tất cả các record mong đợi.
// Nó cũng kiểm tra logic replenishActiveReaders bằng cách đặt maxOpenFiles nhỏ hơn tổng số file.
func TestParquetReader_ManyFiles_RandomRecords_ContentValidation(t *testing.T) {
	numTotalFiles := 50        // Tổng số mục trong thư mục (bao gồm cả file lỗi/trống)
	numValidParquetFiles := 40 // Số lượng file parquet hợp lệ có dữ liệu
	maxRecordsPerFile := 30    // Giảm một chút để test nhanh hơn
	minRecordsPerFile := 1
	maxOpen := 10

	tempDir, err := os.MkdirTemp("", "parquet_test_many_mixed_")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	allExpectedRecords := make([]ParquetRecord, 0)
	randSource := rand.NewSource(time.Now().UnixNano())
	randomizer := rand.New(randSource)

	filePaths := make([]string, numTotalFiles)
	for i := range filePaths {
		filePaths[i] = fmt.Sprintf("mixed_file_%02d.parquet", i)
	}
	randomizer.Shuffle(
		len(filePaths),
		func(i, j int) { // Xáo trộn tên file để vị trí file lỗi/trống là ngẫu nhiên
			filePaths[i], filePaths[j] = filePaths[j], filePaths[i]
		},
	)

	validFilesCreated := 0
	for i := 0; i < numTotalFiles; i++ {
		filePath := filepath.Join(tempDir, filePaths[i])

		// Quyết định loại file sẽ tạo
		fileTypeDecision := randomizer.Float64()

		if validFilesCreated < numValidParquetFiles &&
			(fileTypeDecision < 0.8 || (numTotalFiles-i) <= (numValidParquetFiles-validFilesCreated)) {
			// Tạo file Parquet hợp lệ với dữ liệu (ưu tiên tạo đủ số file hợp lệ)
			numRecordsInFile := randomizer.Intn(
				maxRecordsPerFile-minRecordsPerFile+1,
			) + minRecordsPerFile
			fileRecords := make([]ParquetRecord, numRecordsInFile)
			for j := 0; j < numRecordsInFile; j++ {
				uniqueURL := fmt.Sprintf(
					"http://example.com/%s/page%03d",
					strings.TrimSuffix(filePaths[i], ".parquet"),
					j,
				)
				fileRecords[j] = ParquetRecord{
					Url:        uniqueURL,
					ResultType: fmt.Sprintf("type%d", j%5),
					InputURL: fmt.Sprintf(
						"http://input.com/%s",
						strings.TrimSuffix(filePaths[i], ".parquet"),
					),
					RequestMethod:      "GET",
					ResponseStatusCode: int32(200 + (i+j)%10),
					Time: time.Now().
						Add(time.Duration(i*100+j) * time.Second).
						Format(time.RFC3339Nano),
					RequestHeaders: map[string]string{
						"X-File-Name":    filePaths[i],
						"X-Record-Index": strconv.Itoa(j),
					},
					ResponseHeaders: map[string]string{"Content-Source": filePaths[i]},
				}
			}
			createParquetFile(t, filePath, fileRecords)
			allExpectedRecords = append(allExpectedRecords, fileRecords...)
			validFilesCreated++
		} else if fileTypeDecision < 0.9 {
			// Tạo file Parquet hợp lệ nhưng trống
			logMsg := fmt.Sprintf("Creating empty valid parquet file: %s", filePath) // Sử dụng fmt.Sprintf để tránh import log của app
			t.Log(logMsg)                                                            // Ghi log của test
			createParquetFile(t, filePath, []ParquetRecord{})
		} else {
			// Tạo file lỗi (file text với đuôi .parquet)
			logMsg := fmt.Sprintf("Creating intentionally broken (text) parquet file: %s", filePath)
			t.Log(logMsg)
			err := os.WriteFile(filePath, []byte("this is not a valid parquet file"), 0644)
			require.NoError(t, err, "Không thể tạo file parquet lỗi")
		}
	}

	t.Logf(
		"Test setup: %d total items created. %d valid Parquet files with data (total %d expected records). Others are empty or intentionally broken.",
		numTotalFiles,
		validFilesCreated,
		len(allExpectedRecords),
	)

	reader, err := NewParquetReader(tempDir, maxOpen)
	require.NoError(t, err, "NewParquetReader thất bại")
	require.NotNil(t, reader, "NewParquetReader trả về reader là nil")
	defer reader.Close()

	var SUTRecords []ParquetRecord
	for {
		record, hasNext, errLoop := reader.Next()
		require.NoError(t, errLoop, "reader.Next() trả về lỗi")
		if !hasNext {
			break
		}
		SUTRecords = append(SUTRecords, record)
	}

	assert.Equal(
		t,
		len(allExpectedRecords),
		len(SUTRecords),
		"Tổng số lượng record đọc được không khớp",
	)

	// Sắp xếp cả hai slice dựa trên URL để so sánh nội dung
	sort.SliceStable(allExpectedRecords, func(i, j int) bool {
		return allExpectedRecords[i].Url < allExpectedRecords[j].Url
	})
	sort.SliceStable(SUTRecords, func(i, j int) bool {
		return SUTRecords[i].Url < SUTRecords[j].Url
	})

	if !reflect.DeepEqual(allExpectedRecords, SUTRecords) {
		t.Logf("Mismatch detected after sorting. Printing differences (up to 10):")
		diffsFound := 0
		for i := 0; i < len(allExpectedRecords); i++ {
			if i >= len(SUTRecords) || !reflect.DeepEqual(allExpectedRecords[i], SUTRecords[i]) {
				expectedRecStr := "N/A"
				if i < len(allExpectedRecords) {
					expectedRecStr = fmt.Sprintf("%#v", allExpectedRecords[i])
				}
				actualRecStr := "N/A"
				if i < len(SUTRecords) {
					actualRecStr = fmt.Sprintf("%#v", SUTRecords[i])
				}
				t.Logf(
					"Record %d (URL: %s):\nExpected: %s\nActual:   %s\n---",
					i,
					allExpectedRecords[i].Url,
					expectedRecStr,
					actualRecStr,
				)
				diffsFound++
				if diffsFound >= 10 {
					t.Logf("More differences exist but not printed...")
					break
				}
			}
		}
	}
	assert.True(
		t,
		reflect.DeepEqual(allExpectedRecords, SUTRecords),
		"Nội dung của các record đọc được (sau khi sắp xếp) không khớp với các record mong đợi",
	)
}
