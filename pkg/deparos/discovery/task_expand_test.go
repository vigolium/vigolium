package discovery

import (
	"context"
	"net/url"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
	"github.com/vigolium/vigolium/pkg/deparos/fingerprint"
)

// =============================================================================
// SpiderTask.Expand() Tests
// =============================================================================

func TestSpiderTask_Expand(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		payloads []string
		expected []string
	}{
		{
			name:    "preserves trailing slash for directories",
			baseURL: "http://example.com",
			payloads: []string{
				"admin/",
				"api/v1/",
				"docs/",
			},
			expected: []string{
				"http://example.com/admin/",
				"http://example.com/api/v1/",
				"http://example.com/docs/",
			},
		},
		{
			name:    "files without trailing slash",
			baseURL: "http://example.com/",
			payloads: []string{
				"index.html",
				"style.css",
				"app.js",
			},
			expected: []string{
				"http://example.com/index.html",
				"http://example.com/style.css",
				"http://example.com/app.js",
			},
		},
		{
			name:    "mixed files and directories",
			baseURL: "http://example.com",
			payloads: []string{
				"admin/",
				"robots.txt",
				"api/v1/",
				"favicon.ico",
			},
			expected: []string{
				"http://example.com/admin/",
				"http://example.com/robots.txt",
				"http://example.com/api/v1/",
				"http://example.com/favicon.ico",
			},
		},
		{
			name:    "trims leading slash from payload",
			baseURL: "http://example.com",
			payloads: []string{
				"/admin/",
				"/index.html",
			},
			expected: []string{
				"http://example.com/admin/",
				"http://example.com/index.html",
			},
		},
		{
			name:    "baseURL with trailing slash",
			baseURL: "http://example.com/",
			payloads: []string{
				"docs/",
				"file.js",
			},
			expected: []string{
				"http://example.com/docs/",
				"http://example.com/file.js",
			},
		},
		{
			name:    "nested directory paths",
			baseURL: "http://example.com/api",
			payloads: []string{
				"v1/users/",
				"v2/products/123/",
			},
			expected: []string{
				"http://example.com/api/v1/users/",
				"http://example.com/api/v2/products/123/",
			},
		},
		{
			name:    "vulnweb real-world case",
			baseURL: "http://testphp.vulnweb.com/Mod_Rewrite_Shop",
			payloads: []string{
				"Details/color-printer/3/",
				"Details/web-camera-a4tech/2/",
			},
			expected: []string{
				"http://testphp.vulnweb.com/Mod_Rewrite_Shop/Details/color-printer/3/",
				"http://testphp.vulnweb.com/Mod_Rewrite_Shop/Details/web-camera-a4tech/2/",
			},
		},
		{
			name:     "empty payloads",
			baseURL:  "http://example.com/",
			payloads: []string{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloadBytes := toByteSlices(tt.payloads)
			task := NewSpiderTask(&SpiderTaskConfig{
				TaskType: SpiderDirs,
				Provider: payload.NewStaticProvider(payloadBytes),
				BaseURL:  []byte(tt.baseURL),
				Depth:    1,
			})

			urls := collectURLs(t, task)
			assertURLsEqual(t, urls, tt.expected)
		})
	}
}

func TestSpiderTask_Expand_DepthCalculatedFromPath(t *testing.T) {
	// With hybrid scheduling, SpiderTask.Expand calculates depth from path, not task.Depth
	tests := []struct {
		name           string
		paths          [][]byte
		expectedDepths []uint16
	}{
		{
			name:           "single segment",
			paths:          [][]byte{[]byte("test/")},
			expectedDepths: []uint16{1}, // "test" = 1 segment
		},
		{
			name:           "multi segments",
			paths:          [][]byte{[]byte("api/v1/users/")},
			expectedDepths: []uint16{3}, // "api/v1/users" = 3 segments
		},
		{
			name:           "root path",
			paths:          [][]byte{[]byte("/")},
			expectedDepths: []uint16{0}, // root = 0 segments
		},
		{
			name:           "mixed depths",
			paths:          [][]byte{[]byte("a/"), []byte("b/c/d/")},
			expectedDepths: []uint16{1, 3}, // "a" = 1, "b/c/d" = 3
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := NewSpiderTask(&SpiderTaskConfig{
				TaskType: SpiderDirs,
				Provider: payload.NewStaticProvider(tt.paths),
				BaseURL:  []byte("http://example.com"),
				Depth:    99, // This value should NOT be used anymore
			})

			var depths []uint16
			_ = task.Expand(context.Background(), func(url string, depth uint16) {
				depths = append(depths, depth)
			})

			if len(depths) != len(tt.expectedDepths) {
				t.Errorf("expected %d depths, got %d", len(tt.expectedDepths), len(depths))
				return
			}

			for i, expected := range tt.expectedDepths {
				if depths[i] != expected {
					t.Errorf("path %d: expected depth %d, got %d", i, expected, depths[i])
				}
			}
		})
	}
}

func TestSpiderTask_Expand_ContextCancellation(t *testing.T) {
	task := NewSpiderTask(&SpiderTaskConfig{
		TaskType: SpiderDirs,
		Provider: payload.NewStaticProvider([][]byte{[]byte("a"), []byte("b"), []byte("c")}),
		BaseURL:  []byte("http://example.com"),
		Depth:    0,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := task.Expand(ctx, func(url string, depth uint16) {
		t.Error("callback should not be called when context is cancelled")
	})

	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestSpiderTask_Expand_NilProvider(t *testing.T) {
	task := &SpiderTask{
		baseURL:  []byte("http://example.com"),
		provider: nil,
	}

	err := task.Expand(context.Background(), func(url string, depth uint16) {
		t.Error("callback should not be called with nil provider")
	})

	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

// =============================================================================
// WordlistTask.Expand() Tests
// =============================================================================

func TestWordlistTask_Expand(t *testing.T) {
	tests := []struct {
		name      string
		baseURL   string
		payloads  []string
		extension string
		expected  []string
	}{
		{
			name:      "no extension",
			baseURL:   "http://example.com/",
			payloads:  []string{"admin", "config", "backup"},
			extension: "",
			expected: []string{
				"http://example.com/admin",
				"http://example.com/config",
				"http://example.com/backup",
			},
		},
		{
			name:      "single extension",
			baseURL:   "http://example.com/",
			payloads:  []string{"index", "admin"},
			extension: "php",
			expected: []string{
				"http://example.com/index.php",
				"http://example.com/admin.php",
			},
		},
		{
			name:      "trims trailing slash from payloads",
			baseURL:   "http://example.com/",
			payloads:  []string{"admin/", "backup/"},
			extension: "",
			expected: []string{
				"http://example.com/admin",
				"http://example.com/backup",
			},
		},
		{
			name:      "trims leading slash from payloads",
			baseURL:   "http://example.com/",
			payloads:  []string{"/admin", "/backup"},
			extension: "",
			expected: []string{
				"http://example.com/admin",
				"http://example.com/backup",
			},
		},
		{
			name:      "baseURL without trailing slash",
			baseURL:   "http://example.com",
			payloads:  []string{"admin"},
			extension: "php",
			expected: []string{
				"http://example.com/admin.php",
			},
		},
		{
			name:      "baseURL with path",
			baseURL:   "http://example.com/api/v1",
			payloads:  []string{"users", "products"},
			extension: "json",
			expected: []string{
				"http://example.com/api/v1/users.json",
				"http://example.com/api/v1/products.json",
			},
		},
		{
			name:      "empty payloads",
			baseURL:   "http://example.com/",
			payloads:  []string{},
			extension: "php",
			expected:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloadBytes := toByteSlices(tt.payloads)
			// Split baseURL into schemeHost and path
			schemeHost, path := splitURL(tt.baseURL)
			task := NewWordlistTask(&WordlistTaskConfig{
				TaskType:   ShortFilesNoExt,
				Provider:   payload.NewStaticProvider(payloadBytes),
				Extension:  tt.extension,
				SchemeHost: []byte(schemeHost),
				Path:       []byte(path),
				Depth:      0,
			})

			urls := collectURLs(t, task)
			assertURLsEqual(t, urls, tt.expected)
		})
	}
}

func TestWordlistTask_Expand_AllTaskTypes(t *testing.T) {
	taskTypes := []struct {
		taskType    WordlistTaskType
		name        string
		expectedURL string
	}{
		{ShortFilesNoExt, "ShortFilesNoExt", "http://example.com/test"},
		{ShortFilesCustomExt, "ShortFilesCustomExt", "http://example.com/test"},
		{ShortDirs, "ShortDirs", "http://example.com/test/"}, // Directory has trailing slash
		{ShortFilesObservedExt, "ShortFilesObservedExt", "http://example.com/test"},
		{LongFilesNoExt, "LongFilesNoExt", "http://example.com/test"},
		{LongFilesCustomExt, "LongFilesCustomExt", "http://example.com/test"},
		{LongDirs, "LongDirs", "http://example.com/test/"}, // Directory has trailing slash
		{LongFilesObservedExt, "LongFilesObservedExt", "http://example.com/test"},
	}

	for _, tt := range taskTypes {
		t.Run(tt.name, func(t *testing.T) {
			task := NewWordlistTask(&WordlistTaskConfig{
				TaskType:   tt.taskType,
				Provider:   payload.NewStaticProvider([][]byte{[]byte("test")}),
				SchemeHost: []byte("http://example.com"),
				Path:       []byte("/"),
				Depth:      0,
			})

			urls := collectURLs(t, task)
			if len(urls) != 1 || urls[0] != tt.expectedURL {
				t.Errorf("unexpected URLs: got %v, want %v", urls, tt.expectedURL)
			}
		})
	}
}

// =============================================================================
// ObservedTask.Expand() Tests
// =============================================================================

func TestObservedTask_Expand(t *testing.T) {
	t.Run("ObservedFilesNoExt - no extensions", func(t *testing.T) {
		task := NewObservedTask(&ObservedTaskConfig{
			TaskType: ObservedFilesNoExt,
			Provider: payload.NewStaticProvider(toByteSlices([]string{"config", "backup"})),
			BaseURL:  []byte("http://example.com/"),
			Depth:    0,
		})
		urls := collectURLs(t, task)
		assertURLsEqual(t, urls, []string{
			"http://example.com/config",
			"http://example.com/backup",
		})
	})

	t.Run("ObservedFilesCustomExt - with single extension", func(t *testing.T) {
		task := NewObservedTask(&ObservedTaskConfig{
			TaskType:  ObservedFilesCustomExt,
			Provider:  payload.NewStaticProvider(toByteSlices([]string{"index"})),
			Extension: "php",
			BaseURL:   []byte("http://example.com/"),
			Depth:     0,
		})
		urls := collectURLs(t, task)
		assertURLsEqual(t, urls, []string{
			"http://example.com/index.php",
		})
	})

	t.Run("ObservedDirs - adds trailing slash", func(t *testing.T) {
		task := NewObservedTask(&ObservedTaskConfig{
			TaskType: ObservedDirs,
			Provider: payload.NewStaticProvider(toByteSlices([]string{"admin", "backup"})),
			BaseURL:  []byte("http://example.com/"),
			Depth:    0,
		})
		urls := collectURLs(t, task)
		assertURLsEqual(t, urls, []string{
			"http://example.com/admin/",
			"http://example.com/backup/",
		})
	})

	t.Run("ObservedPaths - preserves trailing slash", func(t *testing.T) {
		task := NewObservedTask(&ObservedTaskConfig{
			TaskType: ObservedPaths,
			Provider: payload.NewStaticProvider(toByteSlices([]string{"api/v1/users/", "docs/"})),
			BaseURL:  []byte("http://example.com"),
			Depth:    0,
		})
		urls := collectURLs(t, task)
		assertURLsEqual(t, urls, []string{
			"http://example.com/api/v1/users/",
			"http://example.com/docs/",
		})
	})

	t.Run("ObservedPaths - preserves file paths without slash", func(t *testing.T) {
		task := NewObservedTask(&ObservedTaskConfig{
			TaskType: ObservedPaths,
			Provider: payload.NewStaticProvider(toByteSlices([]string{"api/config.json", "docs/readme.md"})),
			BaseURL:  []byte("http://example.com"),
			Depth:    0,
		})
		urls := collectURLs(t, task)
		assertURLsEqual(t, urls, []string{
			"http://example.com/api/config.json",
			"http://example.com/docs/readme.md",
		})
	})

	t.Run("ObservedFilesObservedExt - with single observed extension", func(t *testing.T) {
		task := NewObservedTask(&ObservedTaskConfig{
			TaskType:  ObservedFilesObservedExt,
			Provider:  payload.NewStaticProvider(toByteSlices([]string{"config", "backup"})),
			Extension: "json",
			BaseURL:   []byte("http://example.com/"),
			Depth:     0,
		})
		urls := collectURLs(t, task)
		assertURLsEqual(t, urls, []string{
			"http://example.com/config.json",
			"http://example.com/backup.json",
		})
	})
}

func TestObservedTask_Expand_AllTaskTypes(t *testing.T) {
	taskTypes := []struct {
		taskType ObservedTaskType
		name     string
	}{
		{ObservedFilesNoExt, "ObservedFilesNoExt"},
		{ObservedFilesCustomExt, "ObservedFilesCustomExt"},
		{ObservedDirs, "ObservedDirs"},
		{ObservedFilesObservedExt, "ObservedFilesObservedExt"},
		{ObservedPaths, "ObservedPaths"},
	}

	for _, tt := range taskTypes {
		t.Run(tt.name, func(t *testing.T) {
			task := NewObservedTask(&ObservedTaskConfig{
				TaskType: tt.taskType,
				Provider: payload.NewStaticProvider([][]byte{[]byte("test")}),
				BaseURL:  []byte("http://example.com/"),
				Depth:    0,
			})

			urls := collectURLs(t, task)
			if len(urls) == 0 {
				t.Error("expected at least one URL")
			}
		})
	}
}

// =============================================================================
// ExtensionVariantTask.Expand() Tests
// =============================================================================

func TestExtensionVariantTask_Expand(t *testing.T) {
	tests := []struct {
		name        string
		baseURL     string
		filename    string
		originalExt string
		variants    []string
		expected    []string
	}{
		{
			name:        "basic with extension",
			baseURL:     "http://example.com/",
			filename:    "index",
			originalExt: "php",
			variants:    []string{"bak", "old", "~1"},
			expected: []string{
				"http://example.com/index.php.bak",
				"http://example.com/index.php.old",
				"http://example.com/index.php.~1",
			},
		},
		{
			name:        "no original extension",
			baseURL:     "http://example.com/",
			filename:    "config",
			originalExt: "",
			variants:    []string{"bak", "old"},
			expected: []string{
				"http://example.com/config.bak",
				"http://example.com/config.old",
			},
		},
		{
			name:        "baseURL without trailing slash",
			baseURL:     "http://example.com",
			filename:    "index",
			originalExt: "php",
			variants:    []string{"bak"},
			expected: []string{
				"http://example.com/index.php.bak",
			},
		},
		{
			name:        "special extension variants",
			baseURL:     "http://example.com/",
			filename:    "web",
			originalExt: "config",
			variants:    []string{"$$$", "~1", "_backup"},
			expected: []string{
				"http://example.com/web.config.$$$",
				"http://example.com/web.config.~1",
				"http://example.com/web.config._backup",
			},
		},
		{
			name:        "with subdirectory in baseURL",
			baseURL:     "http://example.com/admin/",
			filename:    "config",
			originalExt: "json",
			variants:    []string{"bak"},
			expected: []string{
				"http://example.com/admin/config.json.bak",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			variantPayloads := toByteSlices(tt.variants)

			var fullName []byte
			if tt.originalExt != "" {
				fullName = append([]byte(tt.filename), '.')
				fullName = append(fullName, []byte(tt.originalExt)...)
			} else {
				fullName = []byte(tt.filename)
			}

			// Split baseURL into schemeHost and path
			schemeHost, path := splitURL(tt.baseURL)
			task := NewExtensionVariantTask(&ExtensionVariantTaskConfig{
				SchemeHost:  []byte(schemeHost),
				Path:        []byte(path),
				Filename:    []byte(tt.filename),
				OriginalExt: []byte(tt.originalExt),
				FullName:    fullName,
				ExtProvider: payload.NewStaticProvider(variantPayloads),
				Depth:       0,
			})

			urls := collectURLs(t, task)
			assertURLsEqual(t, urls, tt.expected)
		})
	}
}

// =============================================================================
// NumericFuzzTask.Expand() Tests
// =============================================================================

func TestNumericFuzzTask_Expand(t *testing.T) {
	tests := []struct {
		name          string
		baseURL       string
		pathTemplate  string
		originalValue int
		startOffset   int
		endOffset     int
		extension     string
		suffix        string
		expectedCount int // Number of URLs (original ±10, excluding original)
	}{
		{
			// "/user/100" - number "100" starts at position 6, ends at 9
			name:          "basic numeric fuzzing",
			baseURL:       "http://example.com",
			pathTemplate:  "/user/100",
			originalValue: 100,
			startOffset:   6, // position of '1' in "100" within path
			endOffset:     9, // position after '0' in "100" within path
			extension:     "",
			suffix:        "",
			expectedCount: 20, // 90-110 excluding 100
		},
		{
			// "/item/5" - number "5" at position 6
			name:          "numeric near zero",
			baseURL:       "http://example.com",
			pathTemplate:  "/item/5",
			originalValue: 5,
			startOffset:   6,
			endOffset:     7,
			extension:     "",
			suffix:        "",
			expectedCount: 15, // 0-15 excluding 5 (can't go below 0)
		},
		{
			// "/doc/50" - number "50" at position 5
			name:          "with extension",
			baseURL:       "http://example.com",
			pathTemplate:  "/doc/50",
			originalValue: 50,
			startOffset:   5,
			endOffset:     7,
			extension:     "pdf",
			suffix:        "",
			expectedCount: 20, // 40-60 excluding 50
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := NewNumericFuzzTask(&NumericFuzzTaskConfig{
				BaseURL:       []byte(tt.baseURL),
				PathTemplate:  []byte(tt.pathTemplate),
				Suffix:        []byte(tt.suffix),
				Extension:     []byte(tt.extension),
				OriginalValue: tt.originalValue,
				StartOffset:   tt.startOffset,
				EndOffset:     tt.endOffset,
				Depth:         0,
			})

			urls := collectURLs(t, task)

			if len(urls) != tt.expectedCount {
				t.Errorf("expected %d URLs, got %d\nurls: %v", tt.expectedCount, len(urls), urls)
			}
		})
	}
}

func TestNumericFuzzTask_Expand_ValueRange(t *testing.T) {
	task := NewNumericFuzzTask(&NumericFuzzTaskConfig{
		BaseURL:       []byte("http://example.com"),
		PathTemplate:  []byte("/user/100"),
		Suffix:        nil,
		Extension:     nil,
		OriginalValue: 100,
		StartOffset:   6,
		EndOffset:     9,
		Depth:         0,
	})

	var urls []string
	_ = task.Expand(context.Background(), func(url string, depth uint16) {
		urls = append(urls, url)
	})

	// Should have 20 values: 90-99, 101-110
	if len(urls) != 20 {
		t.Errorf("expected 20 URLs, got %d", len(urls))
	}

	// Verify range
	for _, u := range urls {
		// URL should contain a number from 90-110, excluding 100
		if u == "http://example.com/user/100" {
			t.Error("original value 100 should not be in results")
		}
	}
}

// =============================================================================
// ModuleTask.Expand() Tests
// =============================================================================

func TestModuleTask_Expand(t *testing.T) {
	tests := []struct {
		name      string
		baseURL   string
		payloads  []string
		extension string
		expected  []string
	}{
		{
			name:      "no extension",
			baseURL:   "http://example.com/",
			payloads:  []string{"wp-admin", "wp-content", "wp-includes"},
			extension: "",
			expected: []string{
				"http://example.com/wp-admin",
				"http://example.com/wp-content",
				"http://example.com/wp-includes",
			},
		},
		{
			name:      "with extension",
			baseURL:   "http://example.com/",
			payloads:  []string{"config"},
			extension: "php",
			expected: []string{
				"http://example.com/config.php",
			},
		},
		{
			name:      "trims trailing slash from payloads",
			baseURL:   "http://example.com/",
			payloads:  []string{"admin/", "backup/"},
			extension: "",
			expected: []string{
				"http://example.com/admin",
				"http://example.com/backup",
			},
		},
		{
			name:      "trims leading slash from payloads",
			baseURL:   "http://example.com/",
			payloads:  []string{"/admin", "/backup"},
			extension: "",
			expected: []string{
				"http://example.com/admin",
				"http://example.com/backup",
			},
		},
		{
			name:      "baseURL without trailing slash",
			baseURL:   "http://example.com",
			payloads:  []string{"admin"},
			extension: "php",
			expected: []string{
				"http://example.com/admin.php",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloadBytes := toByteSlices(tt.payloads)
			// Split baseURL into schemeHost and path
			schemeHost, path := splitURL(tt.baseURL)
			task := NewModuleTask(&ModuleTaskConfig{
				Priority:   5,
				Provider:   payload.NewStaticProvider(payloadBytes),
				Extension:  tt.extension,
				SchemeHost: []byte(schemeHost),
				Path:       []byte(path),
				Depth:      0,
			})

			urls := collectURLs(t, task)
			assertURLsEqual(t, urls, tt.expected)
		})
	}
}

// =============================================================================
// JSFetchTask.Expand() Tests (Batched URLs)
// =============================================================================

func TestJSFetchTask_Expand_BatchedURLs(t *testing.T) {
	task := NewJSFetchTask(&JSFetchTaskConfig{
		JSURLs: []string{"http://example.com/app.js", "http://example.com/vendor.js"},
	})

	var urls []string
	var depths []uint16
	err := task.Expand(context.Background(), func(url string, depth uint16) {
		urls = append(urls, url)
		depths = append(depths, depth)
	})

	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if len(urls) != 2 {
		t.Errorf("expected 2 callbacks, got %d", len(urls))
	}
	if urls[0] != "http://example.com/app.js" {
		t.Errorf("expected first JS URL, got %s", urls[0])
	}
	if urls[1] != "http://example.com/vendor.js" {
		t.Errorf("expected second JS URL, got %s", urls[1])
	}
	// All JS fetches use depth 0
	for i, d := range depths {
		if d != 0 {
			t.Errorf("expected depth 0 for url %d, got %d", i, d)
		}
	}
}

// =============================================================================
// CaseSenseDetectionTask.Expand() Tests (No-op)
// =============================================================================

func TestCaseSenseDetectionTask_Expand_NoOp(t *testing.T) {
	discoveredURL, _ := url.Parse("http://example.com/Admin")
	task := NewCaseSenseDetectionTask(&CaseSenseDetectionTaskConfig{
		DiscoveredURL: discoveredURL,
		Sample:        &fingerprint.Sample{},
		IsDirectory:   false,
		Callback: func(ctx context.Context, u *url.URL, s *fingerprint.Sample, isDir bool) {
		},
	})

	var callCount int
	err := task.Expand(context.Background(), func(url string, depth uint16) {
		callCount++
	})

	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if callCount != 0 {
		t.Errorf("expected 0 callbacks (no-op), got %d", callCount)
	}
}

// =============================================================================
// Context Cancellation Tests (all task types)
// =============================================================================

func TestAllTasks_Expand_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	provider := payload.NewStaticProvider([][]byte{[]byte("test")})

	tasks := []struct {
		name string
		task Task
	}{
		{
			name: "SpiderTask",
			task: NewSpiderTask(&SpiderTaskConfig{
				Provider: provider,
				BaseURL:  []byte("http://example.com"),
			}),
		},
		{
			name: "WordlistTask",
			task: NewWordlistTask(&WordlistTaskConfig{
				TaskType:   ShortFilesNoExt,
				Provider:   provider,
				SchemeHost: []byte("http://example.com"),
				Path:       []byte("/"),
			}),
		},
		{
			name: "ObservedTask",
			task: NewObservedTask(&ObservedTaskConfig{
				TaskType: ObservedFilesNoExt,
				Provider: provider,
				BaseURL:  []byte("http://example.com"),
			}),
		},
		{
			name: "ExtensionVariantTask",
			task: NewExtensionVariantTask(&ExtensionVariantTaskConfig{
				SchemeHost:  []byte("http://example.com"),
				Path:        []byte("/"),
				Filename:    []byte("index"),
				OriginalExt: []byte("php"),
				ExtProvider: provider,
			}),
		},
		{
			name: "NumericFuzzTask",
			task: NewNumericFuzzTask(&NumericFuzzTaskConfig{
				BaseURL:       []byte("http://example.com"),
				PathTemplate:  []byte("/100"),
				OriginalValue: 100,
				StartOffset:   1,
				EndOffset:     4,
			}),
		},
		{
			name: "ModuleTask",
			task: NewModuleTask(&ModuleTaskConfig{
				Priority:   5,
				Provider:   provider,
				SchemeHost: []byte("http://example.com"),
				Path:       []byte("/"),
			}),
		},
	}

	for _, tt := range tasks {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.task.Expand(ctx, func(url string, depth uint16) {
				t.Error("callback should not be called when context is cancelled")
			})

			if err != context.Canceled {
				t.Errorf("expected context.Canceled, got %v", err)
			}
		})
	}
}

// =============================================================================
// Nil Provider Tests (all task types)
// =============================================================================

func TestAllTasks_Expand_NilProvider(t *testing.T) {
	tasks := []struct {
		name string
		task Task
	}{
		{
			name: "SpiderTask",
			task: &SpiderTask{baseURL: []byte("http://example.com"), provider: nil},
		},
		{
			name: "WordlistTask",
			task: &WordlistTask{schemeHost: []byte("http://example.com"), path: []byte("/"), provider: nil},
		},
		{
			name: "ObservedTask",
			task: &ObservedTask{baseURL: []byte("http://example.com"), provider: nil},
		},
		{
			name: "ExtensionVariantTask",
			task: &ExtensionVariantTask{schemeHost: []byte("http://example.com"), path: []byte("/"), extProvider: nil},
		},
		{
			name: "NumericFuzzTask",
			task: &NumericFuzzTask{pathTemplate: []byte("http://example.com/100"), provider: nil},
		},
		{
			name: "ModuleTask",
			task: &ModuleTask{schemeHost: []byte("http://example.com"), path: []byte("/"), provider: nil},
		},
	}

	for _, tt := range tasks {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.task.Expand(context.Background(), func(url string, depth uint16) {
				t.Error("callback should not be called with nil provider")
			})

			if err != nil {
				t.Errorf("expected nil error, got %v", err)
			}
		})
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func toByteSlices(strs []string) [][]byte {
	result := make([][]byte, len(strs))
	for i, s := range strs {
		result[i] = []byte(s)
	}
	return result
}

func collectURLs(t *testing.T, task Task) []string {
	t.Helper()
	var urls []string
	err := task.Expand(context.Background(), func(url string, depth uint16) {
		urls = append(urls, url)
	})
	if err != nil {
		t.Fatalf("Expand() error: %v", err)
	}
	return urls
}

func assertURLsEqual(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("got %d URLs, want %d\ngot: %v\nwant: %v", len(got), len(want), got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("URL[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// splitURL splits a URL into schemeHost (scheme://host) and path components.
func splitURL(rawURL string) (schemeHost, path string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, ""
	}
	schemeHost = u.Scheme + "://" + u.Host
	path = u.Path
	if path == "" {
		path = "/"
	}
	return schemeHost, path
}
