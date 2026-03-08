package crawlerxdir

import (
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xitongsys/parquet-go-source/local"
	"github.com/xitongsys/parquet-go/reader"
	"go.uber.org/zap"
)

const (
	DefaultMaxOpenFiles = 30
)

// trackedParquetReader wraps a ParquetReader with its file path and read count.
type trackedParquetReader struct {
	reader           *reader.ParquetReader
	filePath         string
	recordsReadCount int64
}

// ParquetReader manages reading records from multiple Parquet files concurrently.
type ParquetReader struct {
	allFilePaths      []string // All .parquet files to be processed (renamed from filePaths)
	nextFilePathIndex int      // Index of the next file to try opening from allFilePaths

	activeReaders      []*trackedParquetReader // Active Parquet file readers
	currentReaderIndex int                     // Index for round-robin reading from activeReaders
	activeReadersLock  sync.RWMutex            // RWMutex for better performance on reads

	maxOpenFiles int // Maximum number of files to keep open concurrently
	closed       bool
	closeMutex   sync.Mutex
}

// NewParquetReader creates a new ParquetReader.
// It recursively finds all .parquet files in the inputDir and opens up to maxOpenFiles.
func NewParquetReader(inputDir string, maxOpenFiles int) (*ParquetReader, error) {
	files, err := listParquetFiles(inputDir)
	if err != nil {
		return nil, fmt.Errorf("error listing parquet files: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no .parquet files found in %s", inputDir)
	}

	// Shuffle the file paths for better distribution
	if len(files) > 1 {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		r.Shuffle(len(files), func(i, j int) {
			files[i], files[j] = files[j], files[i]
		})
		zap.L().Debug("Shuffled parquet files for processing", zap.Int("count", len(files)))
	}

	mop := maxOpenFiles
	if mop <= 0 {
		mop = DefaultMaxOpenFiles
	}
	if mop > len(files) {
		mop = len(files)
	}

	pr := &ParquetReader{
		allFilePaths:      files,
		nextFilePathIndex: 0,
		activeReaders:     make([]*trackedParquetReader, 0, mop),
		maxOpenFiles:      mop,
	}

	// Open initial files up to maxOpenFiles
	for pr.nextFilePathIndex < len(pr.allFilePaths) && len(pr.activeReaders) < mop {
		filePathToOpen := pr.allFilePaths[pr.nextFilePathIndex]
		pr.nextFilePathIndex++ // Consume this path for the initial opening round

		if err := pr.openFile(filePathToOpen); err != nil {
			zap.L().Warn("Failed to open initial file, continuing with next available file if any", zap.String("file", filePathToOpen), zap.Error(err))
			// Continue to try other files from allFilePaths up to mop active readers
		}
		// If openFile was successful, len(pr.activeReaders) increases.
	}

	if len(pr.activeReaders) == 0 {
		if len(pr.allFilePaths) > 0 {
			return nil, fmt.Errorf("could not open any parquet files for reading from %s (attempted to check %d files)", inputDir, pr.nextFilePathIndex)
		}
		// This specific error for "no .parquet files found" is already returned by listParquetFiles logic, handled above.
		// However, if listParquetFiles found files but none could be opened, this provides a fallback message.
		return nil, fmt.Errorf("no .parquet files found in %s or none could be opened", inputDir)
	}

	zap.L().Debug("Successfully opened initial parquet files for reading", zap.Int("opened", len(pr.activeReaders)), zap.Int("total_files", len(pr.allFilePaths)), zap.Int("next_index", pr.nextFilePathIndex))
	return pr, nil
}

// listParquetFiles recursively finds all files ending with ".parquet" in a directory.
func listParquetFiles(rootDir string) ([]string, error) {
	var parquetFiles []string
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".parquet") {
			parquetFiles = append(parquetFiles, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("error walking directory %s: %w", rootDir, err)
	}
	return parquetFiles, nil
}

// openFile opens a single parquet file and adds its tracked reader to activeReaders
// Basic validation for numRows == 0 is kept. Deeper validation moved to Next().
func (pr *ParquetReader) openFile(filePath string) error {
	fr, err := local.NewLocalFileReader(filePath)
	if err != nil {
		return fmt.Errorf("failed to open local file %s: %w", filePath, err)
	}

	// ParquetRecord is the struct type for unmarshalling. 4 is concurrency for reading columns.
	pqReader, err := reader.NewParquetReader(fr, new(ParquetRecord), 4)
	if err != nil {
		_ = fr.Close() // Ensure file handle for fr is closed if NewParquetReader fails
		return fmt.Errorf("failed to create parquet reader for %s: %w", filePath, err)
	}

	numRows := pqReader.GetNumRows()

	// Quick check to see if file has any records based on metadata
	// This helps avoid adding files that are known to be empty to activeReaders.
	if numRows == 0 {
		zap.L().Debug("Skipping parquet file based on metadata (0 rows)", zap.String("file", filePath))
		pqReader.ReadStop() // This should close the underlying PFile (fr)
		// fr.Close() is not strictly needed here again as pqReader.ReadStop() handles it.
		return fmt.Errorf("file %s is empty based on metadata", filePath)
	}

	// Test read and re-opening logic has been removed for simplification.
	// File readability will be determined during actual read attempts in Next().

	trackedReader := &trackedParquetReader{
		reader:           pqReader, // Use the initially created pqReader
		filePath:         filePath,
		recordsReadCount: 0,
	}
	pr.activeReaders = append(pr.activeReaders, trackedReader)
	zap.L().Debug(
		"Opened parquet file for reading, actual readability verified on Next()",
		zap.String("file", filePath),
		zap.Int64("metadata_rows", numRows),
	)
	return nil
}

// Next returns the next record using round-robin across all open files
// Handles files with different row counts and empty/corrupted files gracefully
func (pr *ParquetReader) Next() (ParquetRecord, bool, error) {
	pr.activeReadersLock.Lock()
	defer pr.activeReadersLock.Unlock()

	if pr.closed {
		return ParquetRecord{}, false, nil
	}

	// Continue until we find a record or exhaust all readers
	for len(pr.activeReaders) > 0 {
		// Ensure currentReaderIndex is within bounds
		if pr.currentReaderIndex >= len(pr.activeReaders) {
			pr.currentReaderIndex = 0
		}

		currentTrackedReader := pr.activeReaders[pr.currentReaderIndex]
		readerIndexBeingProcessed := pr.currentReaderIndex // Store index for logging and advancing

		// Initialize records slice with length 1. The parquet library's Read method
		// expects a pointer to a slice and will resize it/populate it.
		records := make([]ParquetRecord, 1)
		err := currentTrackedReader.reader.Read(&records)

		if err != nil {
			if err == io.EOF {
				zap.L().Debug(
					"File exhausted (EOF), normal completion",
					zap.String("file", currentTrackedReader.filePath),
					zap.Int("reader_index", readerIndexBeingProcessed),
					zap.Int64("records_read", currentTrackedReader.recordsReadCount),
				)
			} else {
				zap.L().Warn("Error reading from parquet file, closing reader",
					zap.String("file", currentTrackedReader.filePath), zap.Int("reader_index", readerIndexBeingProcessed), zap.Int64("records_read", currentTrackedReader.recordsReadCount), zap.Error(err))
			}
			pr.closeAndRemoveReader(readerIndexBeingProcessed)
			continue // Try next reader
		}

		// If err is nil, check if any records were actually read.
		// The Read() method of parquet-go reader might return err == nil
		// but also set the length of the records slice to 0 if no actual data was read.
		if len(records) == 0 {
			zap.L().Debug(
				"File returned 0 records despite err == nil, assuming EOF or empty data section, closing reader",
				zap.String("file", currentTrackedReader.filePath),
				zap.Int("reader_index", readerIndexBeingProcessed),
				zap.Int64("records_read", currentTrackedReader.recordsReadCount),
			)
			pr.closeAndRemoveReader(readerIndexBeingProcessed)
			continue // Try next reader
		}

		// If we are here, err == nil AND len(records) > 0. A record was read into records[0].
		currentTrackedReader.recordsReadCount++
		recordToReturn := records[0] // This should now be safe

		if len(
			pr.activeReaders,
		) > 0 { // Check before modulo operation, though loop condition should ensure this
			pr.currentReaderIndex = (readerIndexBeingProcessed + 1) % len(pr.activeReaders)
		}
		return recordToReturn, true, nil
	}

	zap.L().Debug("All parquet files have been processed or removed from active readers")
	return ParquetRecord{}, false, nil
}

// closeAndRemoveReader safely closes and removes a tracked reader from the active readers slice
func (pr *ParquetReader) closeAndRemoveReader(readerIndex int) {
	if readerIndex < 0 || readerIndex >= len(pr.activeReaders) {
		zap.L().Warn(
			"Invalid reader index for removal",
			zap.Int("reader_index", readerIndex),
			zap.Int("active_readers_count", len(pr.activeReaders)),
		)
		return
	}

	trackedReader := pr.activeReaders[readerIndex]

	if trackedReader != nil && trackedReader.reader != nil {
		trackedReader.reader.ReadStop()
		if trackedReader.reader.PFile != nil {
			_ = trackedReader.reader.PFile.Close()
		}
		zap.L().Debug("Closed reader for file", zap.String("file", trackedReader.filePath), zap.Int64("records_read", trackedReader.recordsReadCount))
	}

	pr.activeReaders = append(
		pr.activeReaders[:readerIndex],
		pr.activeReaders[readerIndex+1:]...)

	if len(pr.activeReaders) == 0 {
		pr.currentReaderIndex = 0
	} else {
		if pr.currentReaderIndex > readerIndex {
			pr.currentReaderIndex--
		}
		if pr.currentReaderIndex >= len(pr.activeReaders) {
			pr.currentReaderIndex = 0
		}
	}

	zap.L().Debug(
		"Removed reader for file, active readers before replenish",
		zap.String("file", trackedReader.filePath),
		zap.Int("active_readers", len(pr.activeReaders)),
	)

	// Try to open new files if slots are available and paths remain
	pr.replenishActiveReaders()

	zap.L().Debug(
		"After attempting to replenish",
		zap.String("file", trackedReader.filePath),
		zap.Int("active_readers", len(pr.activeReaders)),
		zap.Int("next_file_index", pr.nextFilePathIndex),
		zap.Int("total_files", len(pr.allFilePaths)),
	)
}

// replenishActiveReaders tries to open new files from allFilePaths until
// the number of activeReaders reaches maxOpenFiles or all paths are processed.
// This method expects activeReadersLock (write lock) to be held by the caller.
func (pr *ParquetReader) replenishActiveReaders() {
	if pr.closed {
		return
	}

	for len(pr.activeReaders) < pr.maxOpenFiles && pr.nextFilePathIndex < len(pr.allFilePaths) {
		filePathToOpen := pr.allFilePaths[pr.nextFilePathIndex]
		pr.nextFilePathIndex++ // Move to the next file for the subsequent attempt

		zap.L().Debug("Replenishing: Attempting to open next available file",
			zap.String("file", filePathToOpen), zap.Int("active", len(pr.activeReaders)), zap.Int("max", pr.maxOpenFiles), zap.Int("next_index", pr.nextFilePathIndex), zap.Int("total_files", len(pr.allFilePaths)))

		if err := pr.openFile(filePathToOpen); err != nil {
			zap.L().Warn("Replenishing: Failed to open subsequent file, will try more if available", zap.String("file", filePathToOpen), zap.Error(err))
			// Loop continues to try the next file path
		} else {
			zap.L().Debug("Replenishing: Successfully opened subsequent file", zap.String("file", filePathToOpen), zap.Int("active_readers", len(pr.activeReaders)))
			// If successful, activeReaders count increases, loop condition re-evaluates
		}
	}
}

// GetActiveReaderCount returns the number of currently active readers (for monitoring)
func (pr *ParquetReader) GetActiveReaderCount() int {
	pr.activeReadersLock.RLock()
	defer pr.activeReadersLock.RUnlock()
	return len(pr.activeReaders)
}

// Close stops the ParquetReader and cleans up resources.
func (pr *ParquetReader) Close() {
	pr.closeMutex.Lock()
	defer pr.closeMutex.Unlock()

	if pr.closed {
		return // Already closed
	}

	pr.activeReadersLock.Lock()
	defer pr.activeReadersLock.Unlock()

	zap.L().Debug(
		"Closing ParquetReader, stopping and closing active readers",
		zap.Int("active_readers", len(pr.activeReaders)),
	)
	for i, tr := range pr.activeReaders {
		if tr != nil && tr.reader != nil {
			tr.reader.ReadStop()
			if tr.reader.PFile != nil {
				_ = tr.reader.PFile.Close()
			}
			zap.L().Debug("Closed reader for file", zap.String("file", tr.filePath), zap.Int("index", i), zap.Int64("records_read", tr.recordsReadCount))
		}
		pr.activeReaders[i] = nil // Help GC
	}
	pr.activeReaders = nil
	pr.closed = true

	zap.L().Debug("ParquetReader closed, all active readers stopped and files closed")
}
