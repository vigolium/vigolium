package runner

import (
	"testing"
)

func TestResolveParameterizedPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string // exact match not always possible for UUID, so we check structure
		skip bool   // skip exact match, just check length/format
	}{
		{
			name: "no params",
			path: "/api/users",
			want: "/api/users",
		},
		{
			name: "colon param id",
			path: "/api/users/:id",
			want: "/api/users/1",
		},
		{
			name: "colon param userId",
			path: "/api/users/:userId/posts",
			want: "/api/users/1/posts",
		},
		{
			name: "curly brace param",
			path: "/api/users/{id}",
			want: "/api/users/1",
		},
		{
			name: "angle bracket typed param",
			path: "/api/users/<int:pk>",
			want: "/api/users/1",
		},
		{
			name: "multiple params",
			path: "/api/users/:userId/posts/:postId",
			want: "/api/users/1/posts/1",
		},
		{
			name: "slug param",
			path: "/blog/:slug",
			want: "/blog/test",
		},
		{
			name: "email param",
			path: "/users/{email}",
			want: "/users/test@example.com",
		},
		{
			name: "uuid param",
			path: "/items/:uuid",
			skip: true, // UUID is random, just verify it's replaced
		},
		{
			name: "empty path",
			path: "",
			want: "",
		},
		{
			name: "path param",
			path: "/files/:path",
			want: "/files/test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveParameterizedPath(tt.path)

			if tt.skip {
				// Just verify the placeholder was replaced
				if got == tt.path {
					t.Errorf("resolveParameterizedPath(%q) = %q, placeholder was not replaced", tt.path, got)
				}
				return
			}

			if got != tt.want {
				t.Errorf("resolveParameterizedPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
