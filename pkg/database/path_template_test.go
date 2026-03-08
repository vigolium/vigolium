package database

import "testing"

func TestPathToTemplate(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "empty", path: "", want: ""},
		{name: "root", path: "/", want: "/"},
		{name: "static only", path: "/api/users", want: "/api/users"},
		{name: "static with trailing slash", path: "/api/users/", want: "/api/users/"},

		// Numeric IDs
		{name: "numeric ID", path: "/api/users/123", want: "/api/users/*"},
		{name: "large numeric", path: "/api/users/9999999", want: "/api/users/*"},
		{name: "zero", path: "/api/items/0", want: "/api/items/*"},

		// UUIDs
		{name: "UUID lowercase", path: "/api/orders/550e8400-e29b-41d4-a716-446655440000", want: "/api/orders/*"},
		{name: "UUID uppercase", path: "/api/orders/550E8400-E29B-41D4-A716-446655440000", want: "/api/orders/*"},
		{name: "v2 with UUID", path: "/api/v2/orders/550e8400-e29b-41d4-a716-446655440000", want: "/api/v2/orders/*"},

		// Hex strings
		{name: "hex exactly 8 chars", path: "/api/items/abcdef12", want: "/api/items/*"},
		{name: "hex 12 chars", path: "/api/items/abc123def456", want: "/api/items/*"},
		{name: "hex 7 chars kept", path: "/api/items/abcdef1", want: "/api/items/abcdef1"},
		{name: "hex uppercase 8 chars", path: "/api/items/ABCDEF12", want: "/api/items/*"},

		// Token-like (≥ 20 chars)
		{name: "token 20 chars", path: "/api/auth/abcdefghijklmnopqrst", want: "/api/auth/*"},
		{name: "token 25 chars", path: "/api/auth/eyJhbGciOiJIUzI1NiJ9", want: "/api/auth/*"},
		{name: "token 19 chars kept", path: "/api/auth/abcdefghijklmnopqrs", want: "/api/auth/abcdefghijklmnopqrs"},

		// Version segments kept
		{name: "version v1", path: "/api/v1/users", want: "/api/v1/users"},
		{name: "version v2 with numeric", path: "/api/v2/orders/123", want: "/api/v2/orders/*"},
		{name: "version v10", path: "/api/v10/users", want: "/api/v10/users"},

		// Multiple dynamic segments
		{name: "multiple numeric", path: "/api/users/123/orders/456", want: "/api/users/*/orders/*"},
		{name: "mixed static and dynamic", path: "/api/v1/users/123/profile", want: "/api/v1/users/*/profile"},
		{name: "nested resources", path: "/orgs/42/repos/99/issues/7", want: "/orgs/*/repos/*/issues/*"},

		// No leading slash
		{name: "no leading slash", path: "api/users/123", want: "api/users/*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PathToTemplate(tt.path)
			if got != tt.want {
				t.Errorf("PathToTemplate(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
