package runner

import (
	"context"
	"sync"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

// runRecords is the set of stored records this run's inputs landed on: every
// record the seed and discovery executors stored or deduplicated onto. Read
// only when the scan excludes stored records (Options.StoredRecords).
type runRecords struct {
	mu    sync.Mutex
	uuids map[string]struct{}
}

func (s *runRecords) note(uuid string, _ *httpmsg.HttpRequestResponse) {
	if uuid == "" {
		return
	}
	s.mu.Lock()
	if s.uuids == nil {
		s.uuids = map[string]struct{}{}
	}
	s.uuids[uuid] = struct{}{}
	s.mu.Unlock()
}

func (s *runRecords) list() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.uuids))
	for u := range s.uuids {
		out = append(out, u)
	}
	return out
}

// onRecordStored is the executor hook that collects the run's records, nil
// when the scan includes every stored record anyway.
func (r *Runner) onRecordStored() func(string, *httpmsg.HttpRequestResponse) {
	if !r.options.ExcludesStoredRecords() {
		return nil
	}
	return r.seededRecords.note
}

// runRecordFilter narrows record reads to this run's records when the scan
// excludes stored ones: what scanUUID wrote, plus the stored records its
// inputs deduplicated onto. nil means every in-scope record.
func (r *Runner) runRecordFilter(ctx context.Context, scanUUID string) *database.RunRecordFilter {
	if !r.options.ExcludesStoredRecords() || r.repository == nil || scanUUID == "" {
		return nil
	}
	f := &database.RunRecordFilter{ScanUUID: scanUUID}
	if noted := r.seededRecords.list(); len(noted) > 0 {
		seeds, err := r.repository.RecordsFromOtherScans(ctx, scanUUID, noted)
		if err != nil {
			// Fall back to every noted record: a longer IN list, never a
			// wider scan.
			zap.L().Debug("run records: resolve seeds", zap.Error(err))
			seeds = noted
		}
		f.Seeds = seeds
	}
	return f
}
