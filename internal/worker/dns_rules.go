package worker

import (
	"context"

	"github.com/Kori1c/ecs-controller/internal/store"
)

// dnsRuleCleanupJob drains rule-change cleanup queued by older versions; the
// name reconciler now removes names no machine holds.
func (w *Worker) dnsRuleCleanupJob(context.Context, *store.Job) error {
	return nil
}
