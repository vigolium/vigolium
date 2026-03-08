package csti_detection

import (
	"testing"
)

func TestDetectFramework_AngularJS(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "ng-app attribute",
			body: `<html><body ng-app="myApp"><div>Hello</div></body></html>`,
			want: "AngularJS",
		},
		{
			name: "ng-controller attribute",
			body: `<div ng-controller="MainCtrl">{{message}}</div>`,
			want: "AngularJS",
		},
		{
			name: "data-ng-app attribute",
			body: `<html data-ng-app="app"><body></body></html>`,
			want: "AngularJS",
		},
		{
			name: "angular.js script",
			body: `<script src="/js/angular.js"></script>`,
			want: "AngularJS",
		},
		{
			name: "angular.min.js script",
			body: `<script src="https://cdn.example.com/angular.min.js"></script>`,
			want: "AngularJS",
		},
		{
			name: "ng-bind attribute",
			body: `<span ng-bind="user.name"></span>`,
			want: "AngularJS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectFramework(tt.body)
			if got == nil {
				t.Fatalf("expected framework %q, got nil", tt.want)
			}
			if got.Name != tt.want {
				t.Errorf("expected framework %q, got %q", tt.want, got.Name)
			}
		})
	}
}

func TestDetectFramework_VueJS(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "v-bind directive",
			body: `<div v-bind:class="active">Content</div>`,
			want: "Vue.js",
		},
		{
			name: "v-model directive",
			body: `<input v-model="username">`,
			want: "Vue.js",
		},
		{
			name: "v-if directive",
			body: `<p v-if="show">Visible</p>`,
			want: "Vue.js",
		},
		{
			name: "v-for directive",
			body: `<li v-for="item in items">{{ item }}</li>`,
			want: "Vue.js",
		},
		{
			name: "vue.js script",
			body: `<script src="/vendor/vue.js"></script>`,
			want: "Vue.js",
		},
		{
			name: "vue.min.js script",
			body: `<script src="https://cdn.example.com/vue.min.js"></script>`,
			want: "Vue.js",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectFramework(tt.body)
			if got == nil {
				t.Fatalf("expected framework %q, got nil", tt.want)
			}
			if got.Name != tt.want {
				t.Errorf("expected framework %q, got %q", tt.want, got.Name)
			}
		})
	}
}

func TestDetectFramework_NoFramework(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "plain HTML",
			body: `<html><body><p>Hello World</p></body></html>`,
		},
		{
			name: "React app",
			body: `<div id="root"></div><script src="/static/js/main.js"></script>`,
		},
		{
			name: "empty body",
			body: "",
		},
		{
			name: "jQuery only",
			body: `<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectFramework(tt.body)
			if got != nil {
				t.Errorf("expected nil, got framework %q", got.Name)
			}
		})
	}
}

func TestGetFramework_Caching(t *testing.T) {
	// Clear cache for test isolation
	frameworkCache.Range(func(key, _ any) bool {
		frameworkCache.Delete(key)
		return true
	})

	host := "test-cache.example.com"
	body := `<html ng-app="myApp"><body></body></html>`

	// First call — should detect and cache
	fw1 := getFramework(host, body)
	if fw1 == nil || fw1.Name != "AngularJS" {
		t.Fatalf("first call: expected AngularJS, got %v", fw1)
	}

	// Second call with different body — should return cached result
	fw2 := getFramework(host, "<html><body>no framework</body></html>")
	if fw2 == nil || fw2.Name != "AngularJS" {
		t.Fatalf("second call: expected cached AngularJS, got %v", fw2)
	}

	// Different host with no framework
	noFw := getFramework("no-fw.example.com", "<html><body>plain</body></html>")
	if noFw != nil {
		t.Errorf("expected nil for no-framework host, got %v", noFw)
	}

	// Same no-framework host again — cached nil
	noFw2 := getFramework("no-fw.example.com", `<html ng-app="x"></html>`)
	if noFw2 != nil {
		t.Errorf("expected cached nil, got %v", noFw2)
	}
}

func TestIsInsideFrameworkScope(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		payload string
		want    bool
	}{
		{
			name:    "inside ng-app scope",
			body:    `<html><body ng-app="myApp"><div>abc{{1970*2024}}def</div></body></html>`,
			payload: "abc{{1970*2024}}def",
			want:    true,
		},
		{
			name:    "inside data-ng-app scope",
			body:    `<html data-ng-app="app"><div>abc{{1970*2024}}def</div></html>`,
			payload: "abc{{1970*2024}}def",
			want:    true,
		},
		{
			name:    "outside any scope",
			body:    `<html><body><div>abc{{1970*2024}}def</div></body></html>`,
			payload: "abc{{1970*2024}}def",
			want:    false,
		},
		{
			name:    "payload not found",
			body:    `<html ng-app="x"><body></body></html>`,
			payload: "notfound{{1*2}}here",
			want:    false,
		},
		{
			name:    "inside vue id=app scope",
			body:    `<html><div id="app"><p>abc{{1970*2024}}def</p></div></html>`,
			payload: "abc{{1970*2024}}def",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isInsideFrameworkScope(tt.body, tt.payload)
			if got != tt.want {
				t.Errorf("isInsideFrameworkScope() = %v, want %v", got, tt.want)
			}
		})
	}
}
