package source

import "testing"

func TestShouldSkipDir(t *testing.T) {
	// Directories that SHOULD be skipped
	skip := []string{
		"node_modules", "vendor", "bower_components", ".bundle", "Pods",
		".dart_tool", ".pub-cache", ".cargo", ".gradle", ".mvn",
		"dist", "build", "out", ".next", ".nuxt", ".output", "target",
		"__pycache__", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache",
		"coverage", ".nyc_output", ".cache",
		".git", ".svn", ".hg", ".idea", ".vscode", ".settings",
		".github", ".gitlab", ".circleci", ".terraform", ".pulumi",
		"testdata", "__snapshots__", "fixtures",
		"docs", "doc",
	}
	for _, d := range skip {
		if !ShouldSkipDir(d) {
			t.Errorf("expected ShouldSkipDir(%q) = true", d)
		}
	}

	// Directories that should NOT be skipped
	keep := []string{
		"src", "lib", "api", "pkg", "internal", "cmd", "app",
		"controllers", "handlers", "routes", "middleware", "models",
		"services", "utils", "config", "test", "tests", "spec",
	}
	for _, d := range keep {
		if ShouldSkipDir(d) {
			t.Errorf("expected ShouldSkipDir(%q) = false", d)
		}
	}
}

func TestShouldSkipFile(t *testing.T) {
	// Files that SHOULD be skipped
	skip := []string{
		// Media
		"logo.png", "banner.jpg", "icon.svg", "photo.jpeg", "favicon.ico", "bg.webp",
		// Audio/video
		"intro.mp4", "sound.mp3", "clip.wav", "demo.webm",
		// Fonts
		"roboto.woff", "roboto.woff2", "arial.ttf", "icon.eot", "sans.otf",
		// Documents
		"manual.pdf",
		// Compiled
		"module.pyc", "Main.class", "lib.o", "lib.so", "lib.dylib", "app.dll", "app.exe",
		// Archives
		"bundle.zip", "data.tar", "backup.gz",
		// Lock files
		"package-lock.lock", "go.sum", "yarn.lock",
		// Source maps
		"bundle.js.map",
		// Minified
		"app.min.js", "style.min.css",
		// Generated Go
		"service.pb.go", "types_generated.go",
		// Generated TS/JS
		"api.generated.ts", "client.generated.js",
		// TypeScript declarations
		"types.d.ts",
	}
	for _, f := range skip {
		if !ShouldSkipFile(f) {
			t.Errorf("expected ShouldSkipFile(%q) = true", f)
		}
	}

	// Files that should NOT be skipped
	keep := []string{
		"main.go", "server.py", "app.js", "index.ts", "App.tsx", "Page.vue",
		"handler.java", "controller.rb", "route.php", "lib.rs",
		"Makefile", "Dockerfile", "docker-compose.yml",
		"go.mod", "package.json", "requirements.txt",
		".env", ".env.example", "config.yaml",
	}
	for _, f := range keep {
		if ShouldSkipFile(f) {
			t.Errorf("expected ShouldSkipFile(%q) = false", f)
		}
	}
}

func TestShouldSkipFile_CaseInsensitive(t *testing.T) {
	// Extensions should be matched case-insensitively
	cases := []string{"IMAGE.PNG", "Photo.JPG", "Icon.SVG", "App.Min.JS", "Style.MIN.CSS"}
	for _, f := range cases {
		if !ShouldSkipFile(f) {
			t.Errorf("expected ShouldSkipFile(%q) = true (case-insensitive)", f)
		}
	}
}
