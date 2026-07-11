package discovery

import (
	"net/url"

	"github.com/vigolium/vigolium/pkg/deparos/config"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/module"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"go.uber.org/zap"
)

// Factory creates discovery tasks based on configuration.
// Centralizes task creation logic and ensures correct priority assignment.
// Tasks are pure configuration objects - callbacks are injected at execution time by PayloadCoordinator.
type Factory struct {
	config        *config.Config
	wordlistCache *payload.WordlistCache
}

// NewFactory creates a new task factory.
func NewFactory(cfg *config.Config) *Factory {
	return &Factory{
		config:        cfg,
		wordlistCache: payload.NewWordlistCache(),
	}
}

// getBuiltInProvider returns a provider for the given wordlist, using cached data.
// Loads wordlist once on first access, then reuses cached data for subsequent calls.
func (f *Factory) getBuiltInProvider(listType payload.BuiltInListType, filePath string, caseSensitive bool) (payload.Provider, error) {
	cached, err := f.wordlistCache.Get(listType, filePath, caseSensitive)
	if err != nil {
		return nil, err
	}
	return payload.NewLazyBuiltInProvider(cached, listType, caseSensitive), nil
}

// ============ Internal Builders ============

// createFileTasks creates file tasks for a given wordlist (short or long).
// schemeHost and path are separated to prevent query params from being passed.
func (f *Factory) createFileTasks(schemeHost, path []byte, depth uint16, listType payload.BuiltInListType, wordlistPath string, noExtType, customExtType WordlistTaskType) ([]Task, error) {
	tasks := make([]Task, 0, 2)
	caseSensitive := f.isFileCaseSensitive()

	if f.config.Extensions.TestNoExtension {
		provider, err := f.getBuiltInProvider(listType, wordlistPath, caseSensitive)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, NewWordlistTask(&WordlistTaskConfig{
			TaskType:   noExtType,
			Provider:   provider,
			SchemeHost: schemeHost,
			Path:       path,
			Depth:      depth,
		}))
	}

	// Static custom-extension fuzzing. EffectiveCustomList is empty under
	// ConfirmRequired: in that mode extensions are only swept once confirmed as a
	// valid route, via the observed-extension task paths driven by confirmExtension.
	for _, ext := range f.config.Extensions.EffectiveCustomList() {
		provider, err := f.getBuiltInProvider(listType, wordlistPath, caseSensitive)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, NewWordlistTask(&WordlistTaskConfig{
			TaskType:   customExtType,
			Provider:   provider,
			Extension:  ext,
			SchemeHost: schemeHost,
			Path:       path,
			Depth:      depth,
		}))
	}

	return tasks, nil
}

// isFileCaseSensitive returns true if files should be treated as case-sensitive.
// For auto_detect mode, defaults to false (case-insensitive) until detection completes.
func (f *Factory) isFileCaseSensitive() bool {
	return f.config.Engine.CaseSensitivity == config.CaseSensitive
}

// isDirCaseSensitive returns true if directories should be treated as case-sensitive.
// For auto_detect mode, defaults to false (case-insensitive) until detection completes.
func (f *Factory) isDirCaseSensitive() bool {
	return f.config.Engine.CaseSensitivity == config.CaseSensitive
}

// createDirTask creates a directory task for a given wordlist (short or long).
// schemeHost and path are separated to prevent query params from being passed.
func (f *Factory) createDirTask(schemeHost, path []byte, depth uint16, listType payload.BuiltInListType, wordlistPath string, taskType WordlistTaskType) (Task, error) {
	caseSensitive := f.isDirCaseSensitive()
	provider, err := f.getBuiltInProvider(listType, wordlistPath, caseSensitive)
	if err != nil {
		return nil, err
	}
	return NewWordlistTask(&WordlistTaskConfig{
		TaskType:   taskType,
		Provider:   provider,
		SchemeHost: schemeHost,
		Path:       path,
		Depth:      depth,
	}), nil
}

// buildObservedFileTasks creates Priority 1/2/3 tasks from observed names.
// Each task gets its own LazyObservedProvider pointing to the same source.
func (f *Factory) buildObservedFileTasks(
	baseURL []byte,
	dirPath string,
	depth uint16,
	observedNames *payload.ObservedProvider,
	observedExtensions []string,
	observedFiles *payload.ObservedProvider,
) []Task {
	tasks := make([]Task, 0, 4+len(observedExtensions))

	// Priority 1: Observed names with no extensions
	if f.config.Extensions.TestNoExtension {
		tasks = append(tasks, NewObservedTask(&ObservedTaskConfig{
			TaskType: ObservedFilesNoExt,
			Provider: payload.NewLazyObservedProvider(observedNames),
			BaseURL:  baseURL,
			DirPath:  dirPath,
			Depth:    depth,
		}))
	}

	// Priority 2: Observed names with custom extensions (one task per extension).
	// EffectiveCustomList is empty under ConfirmRequired (extensions flow through
	// confirmExtension → the observed-extension task path below).
	for _, ext := range f.config.Extensions.EffectiveCustomList() {
		tasks = append(tasks, NewObservedTask(&ObservedTaskConfig{
			TaskType:  ObservedFilesCustomExt,
			Provider:  payload.NewLazyObservedProvider(observedNames),
			Extension: ext,
			BaseURL:   baseURL,
			DirPath:   dirPath,
			Depth:     depth,
		}))
	}

	// Priority 2: Observed full filenames (literal) - no extension manipulation
	if f.config.Filenames.UseObservedFiles && observedFiles != nil && observedFiles.Count() > 0 {
		tasks = append(tasks, NewObservedTask(&ObservedTaskConfig{
			TaskType: ObservedFilesLiteral,
			Provider: payload.NewLazyObservedProvider(observedFiles),
			BaseURL:  baseURL,
			DirPath:  dirPath,
			Depth:    depth,
		}))
	}

	// Priority 3: Observed names with observed extensions (one task per extension)
	if f.config.Extensions.TestObserved {
		for _, ext := range observedExtensions {
			tasks = append(tasks, NewObservedTask(&ObservedTaskConfig{
				TaskType:  ObservedFilesObservedExt,
				Provider:  payload.NewLazyObservedProvider(observedNames),
				Extension: ext,
				BaseURL:   baseURL,
				DirPath:   dirPath,
				Depth:     depth,
			}))
		}
	}

	return tasks
}

// ============ Public API ============

// CreateInitialTasks generates the initial set of tasks based on configuration.
// baseURL should be scheme://host/path without query params.
func (f *Factory) CreateInitialTasks(baseURL []byte, depth uint16) ([]Task, error) {
	logger.Debug("Creating initial tasks",
		zap.ByteString("baseURL", baseURL),
		zap.Uint16("depth", depth))

	// Extract schemeHost and path once for all tasks
	schemeHost := []byte(extractSchemeHost(string(baseURL)))
	path := []byte(extractPathFromURL(string(baseURL)))

	tasks := make([]Task, 0, 6)

	// Short file tasks (priority 5-6)
	if f.config.Filenames.Wordlists.HasShortFiles() {
		shortFileTasks, err := f.createFileTasks(schemeHost, path, depth,
			payload.ShortFileList,
			f.config.Filenames.Wordlists.ShortFilePath,
			ShortFilesNoExt,
			ShortFilesCustomExt)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, shortFileTasks...)
	}

	// Short dir task (priority 6)
	if f.config.Filenames.Wordlists.HasShortDirs() {
		task, err := f.createDirTask(schemeHost, path, depth,
			payload.ShortDirList,
			f.config.Filenames.Wordlists.ShortDirPath,
			ShortDirs)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}

	// Long file tasks (priority 8-9)
	if f.config.Filenames.Wordlists.HasLongFiles() {
		longFileTasks, err := f.createFileTasks(schemeHost, path, depth,
			payload.LongFileList,
			f.config.Filenames.Wordlists.LongFilePath,
			LongFilesNoExt,
			LongFilesCustomExt)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, longFileTasks...)
	}

	// Long dir task (priority 9)
	if f.config.Filenames.Wordlists.HasLongDirs() {
		task, err := f.createDirTask(schemeHost, path, depth,
			payload.LongDirList,
			f.config.Filenames.Wordlists.LongDirPath,
			LongDirs)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}

	logger.Info("Initial tasks created",
		zap.Int("total_count", len(tasks)),
		zap.Uint16("depth", depth))

	return tasks, nil
}

// CreateObservedNameTasks creates tasks using names collected from spidering.
func (f *Factory) CreateObservedNameTasks(baseURL []byte, depth uint16, observedNames, observedExtensions *payload.ObservedProvider) []Task {
	if !f.config.Filenames.UseObservedNames {
		logger.Debug("Observed names disabled, skipping observed name tasks")
		return nil
	}

	logger.Info("Creating observed name tasks",
		zap.Bool("test_no_ext", f.config.Extensions.TestNoExtension),
		zap.Bool("test_custom", f.config.Extensions.TestCustom),
		zap.Bool("test_observed", f.config.Extensions.TestObserved))

	// Extract scheme://host and path from baseURL
	schemeHost := extractSchemeHost(string(baseURL))
	dirPath := extractPathFromURL(string(baseURL))

	// For Priority 7, we pass empty extensions here since observedExtensions
	// is handled by CreateDynamicExtensionTasks when new extensions are discovered
	// observedFiles is nil here - it's only used in CreateRecursiveDirectoryTasks
	tasks := f.buildObservedFileTasks([]byte(schemeHost), dirPath, depth, observedNames, nil, nil)

	logger.Info("Observed name tasks created", zap.Int("count", len(tasks)))
	return tasks
}

// CreateObservedDirectoryTasks creates tasks to test observed names AS directories.
// baseURL is scheme://host only, dirPath is the directory path (e.g., "/api/v1/").
func (f *Factory) CreateObservedDirectoryTasks(baseURL []byte, dirPath string, depth uint16, observedNames *payload.ObservedProvider) []Task {
	dirEnabled := f.config.Target.Mode == config.ModeFilesAndDirs || f.config.Target.Mode == config.ModeDirsOnly
	if !dirEnabled || !f.config.Filenames.UseObservedNames {
		logger.Debug("Observed directory tasks disabled",
			zap.String("mode", string(f.config.Target.Mode)),
			zap.Bool("use_observed_names", f.config.Filenames.UseObservedNames))
		return nil
	}

	logger.Info("Creating observed directory task", zap.Uint8("priority", PriorityObservedDirs))

	return []Task{NewObservedTask(&ObservedTaskConfig{
		TaskType: ObservedDirs,
		Provider: payload.NewLazyObservedProvider(observedNames),
		BaseURL:  baseURL,
		DirPath:  dirPath,
		Depth:    depth,
	})}
}

// CreateExtensionVariantTask creates a task to test extension variants for a discovered file.
// schemeHost is the scheme://host portion (e.g., "http://example.com").
// path is the directory path (e.g., "/api/v1/").
func (f *Factory) CreateExtensionVariantTask(discoveredFile, schemeHost, path []byte, depth uint16) Task {
	if !ShouldCreateVariantTask(discoveredFile) {
		logger.Debug("Skipping variant task (file not eligible)",
			zap.ByteString("file", discoveredFile))
		return nil
	}

	filename, ext := ParseFilename(discoveredFile)

	logger.Debug("Creating extension variant task",
		zap.ByteString("file", discoveredFile),
		zap.ByteString("filename", filename),
		zap.ByteString("extension", ext),
		zap.Uint8("priority", PriorityExtensionVariants),
		zap.Int("backup_ext_count", len(f.config.Extensions.BackupExtensions)))

	extProvider := payload.NewExtensionProviderWithVariants(f.config.Extensions.BackupExtensions)

	return NewExtensionVariantTask(&ExtensionVariantTaskConfig{
		SchemeHost:  schemeHost,
		Path:        path,
		Filename:    filename,
		OriginalExt: ext,
		FullName:    discoveredFile,
		ExtProvider: extProvider,
		Depth:       depth,
	})
}

// CreateNumericFuzzTask creates a task to fuzz numeric parameters in a URL.
// fullURL should be a complete URL (scheme://host/path).
func (f *Factory) CreateNumericFuzzTask(fullURL []byte, depth uint16) Task {
	parsed, err := url.Parse(string(fullURL))
	if err != nil {
		logger.Debug("Failed to parse URL for numeric fuzz",
			zap.ByteString("url", fullURL),
			zap.Error(err))
		return nil
	}

	pathOnly := []byte(parsed.Path)
	startOffset, endOffset, value, found := FindNumericParameter(pathOnly)
	if !found {
		logger.Debug("No numeric parameter found in path",
			zap.ByteString("path", pathOnly))
		return nil
	}

	baseURL := []byte(normalizeSchemeHost(parsed))

	logger.Debug("Creating numeric fuzz task",
		zap.ByteString("baseURL", baseURL),
		zap.ByteString("path", pathOnly),
		zap.Int("original_value", value),
		zap.Int("start_offset", startOffset),
		zap.Int("end_offset", endOffset),
		zap.Uint8("priority", PriorityNumericFuzz))

	return NewNumericFuzzTask(&NumericFuzzTaskConfig{
		BaseURL:       baseURL,
		PathTemplate:  pathOnly,
		Suffix:        []byte(""),
		Extension:     nil,
		OriginalValue: value,
		StartOffset:   startOffset,
		EndOffset:     endOffset,
		Depth:         depth,
	})
}

// CreateDynamicExtensionTasks generates tasks when new extension discovered during scan.
// directoryURLs contains full URLs (e.g., "http://example.com/api/v1/") for each directory.
func (f *Factory) CreateDynamicExtensionTasks(
	extension string,
	directoryURLs []string,
	observedNames *payload.ObservedProvider,
	depth uint16,
) []Task {
	logger.Debug("Creating dynamic tasks for observed extension",
		zap.String("extension", extension),
		zap.Int("directory_count", len(directoryURLs)),
		zap.Uint16("depth", depth))

	tasks := make([]Task, 0, len(directoryURLs)+2)

	// Priority 3: Observed names + this extension (for ALL directories)
	// Use LazyObservedProvider to ensure hash matches tasks from CreateRecursiveDirectoryTasks
	if f.config.Filenames.UseObservedNames && f.config.Extensions.TestObserved {
		for _, dirURL := range directoryURLs {
			// Extract scheme://host and path for consistent API
			schemeHost := extractSchemeHost(dirURL)
			dirPath := extractPathFromURL(dirURL)
			tasks = append(tasks, NewObservedTask(&ObservedTaskConfig{
				TaskType:  ObservedFilesObservedExt,
				Provider:  payload.NewLazyObservedProvider(observedNames),
				Extension: extension,
				BaseURL:   []byte(schemeHost),
				DirPath:   dirPath,
				Depth:     depth,
			}))
		}

		logger.Debug("Created Priority 3 tasks (observed names + extension)",
			zap.String("extension", extension),
			zap.Int("task_count", len(directoryURLs)))
	}

	// Extract schemeHost and path from StartURL for wordlist tasks
	startSchemeHost := []byte(extractSchemeHost(f.config.Target.StartURL))
	startPath := []byte(extractPathFromURL(f.config.Target.StartURL))

	// Priority 6: Short wordlist + this extension (base path only)
	if f.config.Filenames.Wordlists.HasShortFiles() && f.config.Extensions.TestObserved {
		shortProvider, err := f.getBuiltInProvider(
			payload.ShortFileList,
			f.config.Filenames.Wordlists.ShortFilePath,
			f.isFileCaseSensitive())
		if err == nil {
			tasks = append(tasks, NewWordlistTask(&WordlistTaskConfig{
				TaskType:   ShortFilesObservedExt,
				Provider:   shortProvider,
				Extension:  extension,
				SchemeHost: startSchemeHost,
				Path:       startPath,
				Depth:      depth,
			}))
		}
	}

	// Priority 11: Long wordlist + this extension (base path only)
	if f.config.Filenames.Wordlists.HasLongFiles() && f.config.Extensions.TestObserved {
		longProvider, err := f.getBuiltInProvider(
			payload.LongFileList,
			f.config.Filenames.Wordlists.LongFilePath,
			f.isFileCaseSensitive())
		if err == nil {
			tasks = append(tasks, NewWordlistTask(&WordlistTaskConfig{
				TaskType:   LongFilesObservedExt,
				Provider:   longProvider,
				Extension:  extension,
				SchemeHost: startSchemeHost,
				Path:       startPath,
				Depth:      depth,
			}))

			logger.Debug("Created Priority 11 task (long list + extension)",
				zap.String("extension", extension))
		}
	}

	logger.Info("Dynamic extension tasks created",
		zap.String("extension", extension),
		zap.Int("task_count", len(tasks)),
		zap.Int("directories_tested", len(directoryURLs)))

	return tasks
}

// CreateObservedPathTasks creates tasks to test observed full paths as directories.
// baseURL is the full start URL (e.g., "http://example.com/api/"); we extract scheme://host.
func (f *Factory) CreateObservedPathTasks(baseURL []byte, depth uint16,
	observedPaths *payload.ObservedProvider) []Task {

	if !f.config.Filenames.UseObservedPaths {
		return nil
	}

	dirEnabled := f.config.Target.Mode == config.ModeFilesAndDirs ||
		f.config.Target.Mode == config.ModeDirsOnly
	if !dirEnabled {
		return nil
	}

	// For ObservedPaths, baseURL should be scheme://host only
	schemeHost := extractSchemeHost(string(baseURL))

	// Use LazyMergedPathProvider for consistency with CreateRecursiveDirectoryTasks
	// This ensures identical hashes for deduplication when same directory is discovered
	provider := payload.NewLazyMergedPathProvider(observedPaths, string(baseURL))

	return []Task{NewObservedTask(&ObservedTaskConfig{
		TaskType: ObservedPaths,
		Provider: provider,
		BaseURL:  []byte(schemeHost),
		Depth:    depth,
	})}
}

// CreateRecursiveDirectoryTasks creates observed name/extension tasks for discovered directory.
func (f *Factory) CreateRecursiveDirectoryTasks(
	dirPath string,
	depth uint16,
	observedNames *payload.ObservedProvider,
	observedExtensions []string,
	observedPaths *payload.ObservedProvider,
	observedFiles *payload.ObservedProvider,
) []Task {
	// Check if there are any observed names (cheap count check)
	if observedNames.Count() == 0 {
		logger.Debug("No observed names available for directory",
			zap.String("directory", dirPath))
		return nil
	}

	logger.Debug("Building observed name tasks for directory",
		zap.String("directory", dirPath),
		zap.Int("name_count", observedNames.Count()),
		zap.Int("extension_count", len(observedExtensions)))

	// Extract scheme://host and path from dirPath for consistent API
	schemeHost := extractSchemeHost(dirPath)
	pathOnly := extractPathFromURL(dirPath)

	// Each task gets its own LazyObservedProvider pointing to same source.
	// This is memory-efficient and ensures tasks see latest observed names.
	tasks := f.buildObservedFileTasks(
		[]byte(schemeHost),
		pathOnly,
		depth,
		observedNames,
		observedExtensions,
		observedFiles,
	)

	// Observed directory tasks (uses same observedNames list)
	if f.config.Target.Mode == config.ModeFilesAndDirs {
		observedDirTasks := f.CreateObservedDirectoryTasks(
			[]byte(schemeHost),
			pathOnly,
			depth,
			observedNames)
		tasks = append(tasks, observedDirTasks...)
	}

	// Add observed path tasks - use lazy provider to defer transformation until execution
	if f.config.Filenames.UseObservedPaths && observedPaths != nil {
		if observedPaths.Count() > 0 {
			// LazyMergedPathProvider now uses MergePathWithBase directly (no callback needed)
			provider := payload.NewLazyMergedPathProvider(observedPaths, dirPath)
			// Extract scheme://host from dirPath for baseURL
			// MergePathWithBase returns full paths, so buildPathURL only needs scheme://host
			tasks = append(tasks, NewObservedTask(&ObservedTaskConfig{
				TaskType: ObservedPaths,
				Provider: provider,
				BaseURL:  []byte(schemeHost),
				Depth:    depth,
			}))
		}
	}

	logger.Info("Recursive directory tasks created",
		zap.String("directory", dirPath),
		zap.Int("task_count", len(tasks)))

	return tasks
}

// CreateSpiderBatchTask creates a batched task from multiple spider-discovered URLs.
// Returns SpiderTask with highest priority (0) that bypasses module filtering.
func (f *Factory) CreateSpiderBatchTask(baseURL []byte, paths [][]byte, isDirectory bool, depth uint16) Task {
	if len(paths) == 0 {
		return nil
	}

	logger.Debug("Creating spider batch task",
		zap.Int("count", len(paths)),
		zap.Bool("isDirectory", isDirectory),
		zap.Uint16("depth", depth))

	provider := payload.NewStaticProvider(paths)

	var taskType SpiderTaskType
	if isDirectory {
		taskType = SpiderDirs
	} else {
		taskType = SpiderFiles
	}

	return NewSpiderTask(&SpiderTaskConfig{
		TaskType: taskType,
		Provider: provider,
		BaseURL:  baseURL,
		Depth:    depth,
	})
}

// CreateModuleTasks creates tasks from module specifications.
// schemeHost is the scheme://host portion (e.g., "http://example.com").
// path is the directory path (e.g., "/api/v1/").
func (f *Factory) CreateModuleTasks(
	schemeHost, path []byte,
	depth uint16,
	taskSpecs []module.TaskSpec,
	observedNames, observedPaths *payload.ObservedProvider,
) ([]Task, error) {
	if len(taskSpecs) == 0 {
		return nil, nil
	}

	var tasks []Task

	for _, spec := range taskSpecs {
		provider, err := f.getProviderForSource(spec, observedNames, observedPaths)
		if err != nil {
			return nil, err
		}
		if provider == nil {
			continue
		}

		tasks = append(tasks, NewModuleTask(&ModuleTaskConfig{
			Priority:   spec.Priority,
			Provider:   provider,
			Extension:  spec.Extension,
			SchemeHost: schemeHost,
			Path:       path,
			Depth:      depth,
		}))
	}

	if len(tasks) > 0 {
		logger.Info("Module tasks created",
			zap.Int("count", len(tasks)),
			zap.ByteString("schemeHost", schemeHost),
			zap.ByteString("path", path))
	}

	return tasks, nil
}

// getProviderForSource returns a payload provider for the given task spec.
func (f *Factory) getProviderForSource(
	spec module.TaskSpec,
	observedNames, observedPaths *payload.ObservedProvider,
) (payload.Provider, error) {
	switch spec.WordlistSource {
	case config.WordlistObservedNames:
		if observedNames == nil {
			return nil, nil
		}
		if observedNames.Count() == 0 {
			return nil, nil
		}
		return payload.NewLazyObservedProvider(observedNames), nil

	case config.WordlistObservedPaths:
		if observedPaths == nil {
			return nil, nil
		}
		if observedPaths.Count() == 0 {
			return nil, nil
		}
		return payload.NewLazyObservedProvider(observedPaths), nil

	case config.WordlistShortFiles:
		if !f.config.Filenames.Wordlists.HasShortFiles() {
			return nil, nil
		}
		return f.getBuiltInProvider(payload.ShortFileList, f.config.Filenames.Wordlists.ShortFilePath, f.isFileCaseSensitive())

	case config.WordlistLongFiles:
		if !f.config.Filenames.Wordlists.HasLongFiles() {
			return nil, nil
		}
		return f.getBuiltInProvider(payload.LongFileList, f.config.Filenames.Wordlists.LongFilePath, f.isFileCaseSensitive())

	case config.WordlistShortDirs:
		if !f.config.Filenames.Wordlists.HasShortDirs() {
			return nil, nil
		}
		return f.getBuiltInProvider(payload.ShortDirList, f.config.Filenames.Wordlists.ShortDirPath, f.isDirCaseSensitive())

	case config.WordlistLongDirs:
		if !f.config.Filenames.Wordlists.HasLongDirs() {
			return nil, nil
		}
		return f.getBuiltInProvider(payload.LongDirList, f.config.Filenames.Wordlists.LongDirPath, f.isDirCaseSensitive())

	case config.WordlistCustom:
		if spec.CustomFile != "" {
			cached, err := f.wordlistCache.GetCustom(spec.CustomFile)
			if err != nil {
				return nil, err
			}
			return payload.NewLazyCustomProvider(cached, "module-custom"), nil
		}
		if len(spec.CustomInline) > 0 {
			return payload.NewLazyCustomProviderFromInline("module-custom", spec.CustomInline), nil
		}
		return nil, nil

	default:
		return nil, nil
	}
}

// CreateJSExtractedRequestTask creates a task to process all JS extracted HTTP requests
// for a specific directory.
func (f *Factory) CreateJSExtractedRequestTask(
	dirURL *url.URL,
	getExtractedRequests func() []jstangle.ExtractedRequest,
	depth uint16,
	getRequestTemplates ...func() []ExtractedRequestTemplate,
) Task {
	if dirURL == nil || getExtractedRequests == nil {
		return nil
	}

	var typedGetter func() []ExtractedRequestTemplate
	if len(getRequestTemplates) > 0 {
		typedGetter = getRequestTemplates[0]
	}
	return NewJSExtractedRequestTask(&JSExtractedRequestTaskConfig{
		DirURL:               dirURL,
		Depth:                depth,
		GetExtractedRequests: getExtractedRequests,
		GetRequestTemplates:  typedGetter,
	})
}

// CreateMalformedPathProbeTask creates a task to probe a directory with the embedded fuzz.txt payloads.
// schemeHost is the scheme://host portion, path is the directory path.
// Returns nil if malformed path probing is disabled or no payloads are loaded.
func (f *Factory) CreateMalformedPathProbeTask(schemeHost, path []byte, depth uint16) Task {
	if !f.config.Filenames.EnableMalformedPathProbe {
		return nil
	}
	if len(f.config.Filenames.MalformedPathProbePayloads) == 0 {
		return nil
	}

	// Ensure trailing slash on path
	pathStr := string(path)
	if pathStr == "" {
		pathStr = "/"
	}
	if pathStr[len(pathStr)-1] != '/' {
		pathStr += "/"
	}

	urlTemplate := string(schemeHost) + pathStr + fuzzMarker
	provider := payload.NewStaticProvider(f.config.Filenames.MalformedPathProbePayloads)

	return NewMalformedPathProbeTask(&MalformedPathProbeTaskConfig{
		URLTemplate: urlTemplate,
		Provider:    provider,
		Depth:       depth,
	})
}

// CreateFuzzTask creates a task that replaces FUZZ in the URL template with words from a wordlist.
// urlTemplate is the full URL with FUZZ marker (e.g., "http://example.com/FUZZ").
func (f *Factory) CreateFuzzTask(urlTemplate string, wordlistPath string, depth uint16) (Task, error) {
	cached, err := f.wordlistCache.GetCustom(wordlistPath)
	if err != nil {
		return nil, err
	}

	provider := payload.NewLazyCustomProvider(cached, "fuzz")

	return NewFuzzTask(&FuzzTaskConfig{
		URLTemplate: urlTemplate,
		Provider:    provider,
		Depth:       depth,
	}), nil
}

// normalizeSchemeHost returns scheme://host with default ports omitted.
// HTTP port 80 and HTTPS port 443 are considered default ports.
func normalizeSchemeHost(parsed *url.URL) string {
	host := parsed.Hostname()
	port := parsed.Port()

	// Omit default ports
	if port == "" ||
		(parsed.Scheme == "http" && port == "80") ||
		(parsed.Scheme == "https" && port == "443") {
		return parsed.Scheme + "://" + host
	}

	return parsed.Scheme + "://" + host + ":" + port
}

// extractSchemeHost extracts scheme://host from a URL string.
// Example: "http://example.com/api/v1/" → "http://example.com"
// Default ports (80 for HTTP, 443 for HTTPS) are omitted.
// If parsing fails, returns the original string.
func extractSchemeHost(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	if parsed.Scheme != "" && parsed.Host != "" {
		return normalizeSchemeHost(parsed)
	}
	return urlStr
}

// extractPathFromURL extracts the path portion from a URL string, delegating to
// the canonical payload.ExtractPathFromURL so the escaped-wire-path handling
// (critical for "/%23/../" bypass templates) lives in exactly one place.
func extractPathFromURL(urlStr string) string {
	return payload.ExtractPathFromURL(urlStr)
}
