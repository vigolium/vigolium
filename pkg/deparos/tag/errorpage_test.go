package tag

import (
	"testing"
)

func TestErrorPageMatcher_Match(t *testing.T) {
	matcher := NewErrorPageMatcher()

	tests := []struct {
		name         string
		responseBody string
		wantMatch    bool
	}{
		{
			name:         "java stack trace",
			responseBody: "Error: at com.example.MyClass.method(MyClass.java:42)",
			wantMatch:    true,
		},
		{
			name:         "java exception",
			responseBody: "java.lang.NullPointerException: Cannot invoke method on null",
			wantMatch:    true,
		},
		{
			name: "python traceback",
			responseBody: `Traceback (most recent call last):
  File "/app/main.py", line 42, in main
    result = process()`,
			wantMatch: true,
		},
		{
			name:         "python file line",
			responseBody: `File "/home/user/app.py", line 123`,
			wantMatch:    true,
		},
		{
			name:         "python valueerror",
			responseBody: "ValueError: invalid literal for int()",
			wantMatch:    true,
		},
		{
			name:         "php fatal error",
			responseBody: "Fatal error: Uncaught Exception in /var/www/html/index.php on line 42",
			wantMatch:    true,
		},
		{
			name:         "php warning",
			responseBody: "PHP Warning: include(/etc/passwd): failed to open stream",
			wantMatch:    true,
		},
		{
			name:         "nodejs stack trace",
			responseBody: "at Object.<anonymous> (/app/index.js:10:15)",
			wantMatch:    true,
		},
		{
			name:         "javascript typeerror",
			responseBody: "TypeError: Cannot read property 'x' of undefined",
			wantMatch:    true,
		},
		{
			name:         "go panic",
			responseBody: "panic: runtime error: invalid memory address",
			wantMatch:    true,
		},
		{
			name:         "go goroutine",
			responseBody: "goroutine 1 [running]:",
			wantMatch:    true,
		},
		{
			name:         "go stack",
			responseBody: "\t/usr/local/go/src/runtime/panic.go:212",
			wantMatch:    true,
		},
		{
			name:         "dotnet exception",
			responseBody: "System.NullReferenceException: Object reference not set",
			wantMatch:    true,
		},
		{
			name:         "ruby error",
			responseBody: "/app/lib/user.rb:42:in `process'",
			wantMatch:    true,
		},
		{
			name:         "sql error mysql",
			responseBody: "You have an error in your SQL syntax near 'SELECT",
			wantMatch:    true,
		},
		{
			name:         "sql error oracle",
			responseBody: "ORA-00942: table or view does not exist",
			wantMatch:    true,
		},
		{
			name:         "debug mode django",
			responseBody: "DEBUG = True in settings",
			wantMatch:    true,
		},
		{
			name:         "internal server error",
			responseBody: "Internal Server Error occurred",
			wantMatch:    true,
		},
		{
			name:         "exception in thread",
			responseBody: "Exception in thread main java.lang.Error",
			wantMatch:    true,
		},
		{
			name:         "stack trace keyword",
			responseBody: "See the stack trace below for details",
			wantMatch:    true,
		},
		{
			name:         "web-inf exposed",
			responseBody: "WEB-INF/web.xml",
			wantMatch:    true,
		},
		{
			name:         "vendor autoload",
			responseBody: "require vendor/autoload.php",
			wantMatch:    true,
		},
		{
			name:         "normal page no error",
			responseBody: "<html><body><h1>Welcome</h1><p>Hello world</p></body></html>",
			wantMatch:    false,
		},
		{
			name:         "json response no error",
			responseBody: `{"status": "ok", "message": "success"}`,
			wantMatch:    false,
		},
		{
			name:         "empty body",
			responseBody: "",
			wantMatch:    false,
		},
		{
			name:         "404 page no stack trace",
			responseBody: "Page not found. Please check the URL.",
			wantMatch:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &MatchInput{
				ResponseBody: []byte(tt.responseBody),
			}
			got := matcher.Match(input)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestErrorPageMatcher_Tag(t *testing.T) {
	matcher := NewErrorPageMatcher()
	if matcher.Tag() != TagErrorPage {
		t.Errorf("Tag() = %v, want %v", matcher.Tag(), TagErrorPage)
	}
}
