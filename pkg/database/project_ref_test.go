package database

import (
	"context"
	"errors"
	"testing"
)

func TestResolveProjectRef(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	for _, p := range []*Project{
		{UUID: "11111111-aaaa-4aaa-8aaa-000000000001", Name: "alpha", OwnerUUID: DefaultUserUUID},
		{UUID: "11111111-bbbb-4bbb-8bbb-000000000002", Name: "beta", OwnerUUID: DefaultUserUUID},
		{UUID: "22222222-cccc-4ccc-8ccc-000000000003", Name: "beta", OwnerUUID: DefaultUserUUID},
	} {
		if err := repo.CreateProject(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	for ref, want := range map[string]string{
		"11111111-aaaa-4aaa-8aaa-000000000001": "11111111-aaaa-4aaa-8aaa-000000000001",
		"alpha":                                "11111111-aaaa-4aaa-8aaa-000000000001",
		"22222222":                             "22222222-cccc-4ccc-8ccc-000000000003",
		"11111111-b":                           "11111111-bbbb-4bbb-8bbb-000000000002",
	} {
		p, err := repo.ResolveProjectRef(ctx, ref)
		if err != nil || p.UUID != want {
			t.Errorf("ResolveProjectRef(%q) = %v, %v; want %s", ref, p, err, want)
		}
	}
	for ref, want := range map[string]error{
		"beta":                                 ErrProjectRefAmbiguous,
		"11111111":                             ErrProjectRefAmbiguous,
		"1111111":                              ErrProjectNotFound, // too short for a prefix
		"nope":                                 ErrProjectNotFound,
		"99999999-9999-9999-9999-999999999999": ErrProjectNotFound,
	} {
		if _, err := repo.ResolveProjectRef(ctx, ref); !errors.Is(err, want) {
			t.Errorf("ResolveProjectRef(%q) = %v, want %v", ref, err, want)
		}
	}
}
