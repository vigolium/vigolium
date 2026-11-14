package cli

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// projectReceiverInterval is how often a scan-on-receive server looks for
// projects that received traffic and have no receiver yet.
const projectReceiverInterval = 30 * time.Second

// newScanOnReceiveRow builds the persistent scan row one scan-on-receive
// receiver tracks its cursor on, in projectUUID.
func newScanOnReceiveRow(projectUUID, target, modules string, threads int) *database.Scan {
	id := uuid.New().String()
	return &database.Scan{
		UUID:        fmt.Sprintf("scan-%s", id),
		ProjectUUID: projectUUID,
		Name:        fmt.Sprintf("server-scan-on-receive-%s", id[:8]),
		Status:      "running",
		Target:      target,
		Modules:     modules,
		Threads:     threads,
		ScanSource:  "scan-on-receive",
		ScanMode:    "incremental",
		StartedAt:   time.Now(),
	}
}

// receiver is one project's scan-on-receive runner, as the server sees it.
type receiver interface {
	Close()
}

// projectReceivers keeps one scan-on-receive receiver per project that has
// received traffic, so records ingested into any project are scanned. A
// receiver is a full runner, so a project gets one only once it holds an
// ingested record (IngestRecordSources); the default project's is started
// with the server.
type projectReceivers struct {
	mu        sync.Mutex
	receivers map[string]receiver
	// start builds and starts the receiver for a project.
	start func(projectUUID string) (receiver, error)
}

func newProjectReceivers(start func(projectUUID string) (receiver, error)) *projectReceivers {
	return &projectReceivers{receivers: make(map[string]receiver), start: start}
}

// add registers an already-running receiver (the default project's).
func (p *projectReceivers) add(projectUUID string, r receiver) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.receivers[projectUUID] = r
}

// ensure starts a receiver for projectUUID when it has none.
func (p *projectReceivers) ensure(projectUUID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.receivers[projectUUID]; ok {
		return
	}
	r, err := p.start(projectUUID)
	if err != nil {
		zap.L().Warn("scan-on-receive: cannot start a receiver for project", zap.String("project", projectUUID), zap.Error(err))
		return
	}
	p.receivers[projectUUID] = r
	zap.L().Info("scan-on-receive: watching project", zap.String("project", projectUUID))
}

// has reports whether projectUUID already has a receiver.
func (p *projectReceivers) has(projectUUID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.receivers[projectUUID]
	return ok
}

// sync starts a receiver for every project that holds ingested traffic and
// has none yet.
func (p *projectReceivers) sync(ctx context.Context, repo *database.Repository) {
	if repo == nil {
		return
	}
	projects, err := repo.ListProjects(ctx, "")
	if err != nil {
		zap.L().Debug("scan-on-receive: cannot list projects", zap.Error(err))
		return
	}
	for _, proj := range projects {
		if strings.TrimSpace(proj.UUID) == "" || p.has(proj.UUID) {
			continue
		}
		ingested, err := repo.HasRecordsFromSources(ctx, proj.UUID, database.IngestRecordSources)
		if err != nil {
			zap.L().Debug("scan-on-receive: cannot check project for ingested records", zap.String("project", proj.UUID), zap.Error(err))
			continue
		}
		if ingested {
			p.ensure(proj.UUID)
		}
	}
}

// watch runs sync now and every interval until ctx ends.
func (p *projectReceivers) watch(ctx context.Context, repo *database.Repository, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		p.sync(ctx, repo)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// closeAll stops every receiver.
func (p *projectReceivers) closeAll() {
	p.mu.Lock()
	rs := make([]receiver, 0, len(p.receivers))
	for _, r := range p.receivers {
		rs = append(rs, r)
	}
	p.receivers = map[string]receiver{}
	p.mu.Unlock()
	for _, r := range rs {
		r.Close()
	}
}
