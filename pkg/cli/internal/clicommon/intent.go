package clicommon

// OpenIntent is what a command means to do with the store it opens. It decides
// HOW the store is opened, which is the whole difference between a read that
// never waits on a scan and one that queues behind it for busy_timeout:
//
//   - IntentWrite: the read-write store; the schema is made ready (migrated if
//     needed) on open. The zero value, so an opener nobody classified gets the
//     read-write store.
//   - IntentRead: the read pool — query_only, deferred transactions, no
//     journal-mode change, no checkpointing. Schema checked, never migrated by
//     this pool (see openForRead for the auto_migrate_on_read path).
//   - IntentEvidence: --read-only. mode=ro; nothing about the file may change.
//
// Commands declare their intent once, in the CLI's command table
// (commandTraits); the CLI sets Policy.Intent from it before the command
// runs. A flag that turns a read into a write flips it there too.
type OpenIntent int

const (
	IntentWrite OpenIntent = iota
	IntentRead
	IntentEvidence
)

// String names the intent.
func (i OpenIntent) String() string {
	switch i {
	case IntentRead:
		return "read"
	case IntentEvidence:
		return "evidence"
	default:
		return "write"
	}
}

// serves reports whether a handle opened for i can be used for want. A writer
// can read; an evidence handle is what --read-only forced for everything.
func (i OpenIntent) serves(want OpenIntent) bool {
	switch i {
	case IntentWrite:
		return want != IntentEvidence
	case IntentEvidence:
		return true
	default:
		return want == IntentRead
	}
}

// effectiveIntent folds --read-only in: it forces evidence intent for the whole
// process, whatever a call site asked for.
func effectiveIntent(want OpenIntent) OpenIntent {
	if Policy.ReadOnly {
		return IntentEvidence
	}
	return want
}
