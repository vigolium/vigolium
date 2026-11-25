package clicommon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

// With no configuration, an outdated store is refused for reads and for
// writes with schema_outdated naming `vigolium db migrate --db <path>`, and the
// file is left as it was; VIGOLIUM_AUTO_MIGRATE=1 lets a write open migrate it.
func TestGetDBFor_DefaultRefusesOutdatedStore(t *testing.T) {
	t.Setenv(config.AutoMigrateEnvVar, "")
	for _, intent := range []OpenIntent{IntentRead, IntentWrite} {
		isolateDBState(t)
		path := v1Store(t)
		_, err := GetDBFor(intent, "", path)
		var outdated *database.SchemaOutdatedError
		if !errors.As(err, &outdated) {
			t.Fatalf("%v: err = %v, want *SchemaOutdatedError", intent, err)
		}
		if !strings.Contains(err.Error(), "vigolium db migrate --db "+path) {
			t.Errorf("%v: the error does not name the migrate command for %s: %v", intent, path, err)
		}
		ResetDBCache()
		cfg := config.DefaultDatabaseConfig()
		cfg.SQLite.Path = path
		db, err := database.NewDB(cfg)
		if err != nil {
			t.Fatal(err)
		}
		info, _ := db.SchemaInfo(context.Background())
		_ = db.Close()
		if info.Version != 1 {
			t.Errorf("%v: a refused open migrated the store to v%d", intent, info.Version)
		}
	}

	isolateDBState(t)
	t.Setenv(config.AutoMigrateEnvVar, "1")
	path := v1Store(t)
	db, err := GetDBFor(IntentWrite, "", path)
	if err != nil {
		t.Fatalf("write open with VIGOLIUM_AUTO_MIGRATE=1: %v", err)
	}
	if info, err := db.SchemaInfo(context.Background()); err != nil || info.Version != database.CurrentSchemaVersion() {
		t.Fatalf("after an allowed migration: %+v, %v", info, err)
	}
}
