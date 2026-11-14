package jsext

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/grafana/sobek"
)

// An empty sandbox_dir means the working directory, not anywhere.
func TestResolveSandboxPath_EmptyMeansCwd(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolveSandboxPath("/etc/passwd", ""); err == nil {
		t.Error("/etc/passwd must be outside the default (cwd) sandbox")
	}
	if _, err := resolveSandboxPath(filepath.Join(wd, "x.txt"), ""); err != nil {
		t.Errorf("a cwd path must be allowed: %v", err)
	}
}

// The JS call bound follows extensions.limits.timeout.
func TestCallJSWithTimeout_UsesConfiguredLimit(t *testing.T) {
	SetCallTimeout(150 * time.Millisecond)
	defer SetCallTimeout(0)
	vm := sobek.New()
	v, err := vm.RunString(`(function(){ for(;;){} })`)
	if err != nil {
		t.Fatal(err)
	}
	fn, ok := sobek.AssertFunction(v)
	if !ok {
		t.Fatal("not a function")
	}
	start := time.Now()
	_, err, poisoned := callJSWithTimeout(vm, fn, sobek.Undefined())
	if err == nil || !poisoned {
		t.Fatalf("err=%v poisoned=%v, want an interrupt", err, poisoned)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("interrupted after %v, want ~150ms", d)
	}
}

// An https URL connects over https on 443, not plain http.
func TestServiceForRequest(t *testing.T) {
	svc := serviceForRequest("https://app.test/x", "app.test")
	if svc == nil || svc.Protocol() != "https" || svc.Port() != 443 {
		t.Errorf("https URL service = %+v", svc)
	}
	if svc := serviceForRequest("", "app.test:443"); svc == nil || svc.Protocol() != "https" {
		t.Errorf("Host :443 should infer https, got %+v", svc)
	}
	if svc := serviceForRequest("", "app.test:8080"); svc == nil || svc.Protocol() == "https" || svc.Port() != 8080 {
		t.Errorf("Host :8080 should be http:8080, got %+v", svc)
	}
}
