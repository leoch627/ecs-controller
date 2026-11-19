package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Kori1c/ecs-controller/internal/dns"
	"github.com/Kori1c/ecs-controller/internal/store"
)

func (w *Worker) dnsRuleCleanupJob(ctx context.Context, job *store.Job) error {
	var retired []store.DNSBinding
	if err := json.Unmarshal([]byte(job.Payload), &retired); err != nil {
		return err
	}
	w.Store.DNSConfigMu.Lock()
	defer w.Store.DNSConfigMu.Unlock()
	return w.cleanupDNSBindings(ctx, w.dnsSettings(), retired)
}

func (w *Worker) cleanupDNSBindings(ctx context.Context, settings dns.Settings, retired []store.DNSBinding) error {
	owned := map[string]bool{}
	replacements := map[string]dns.Rule{}
	for _, rule := range settings.EffectiveRules() {
		if rule.Enabled && rule.Kind == "pool" {
			binding := store.DNSBinding{Rule: rule, Name: rule.FQDN()}
			owned[binding.Key()] = true
			replacements[rule.ID] = rule
		}
	}
	custom, err := w.Store.CustomDNSLabels()
	if err != nil {
		return err
	}
	var failures []error
	for _, binding := range retired {
		if owned[binding.Key()] || dns.IsCustomName(binding.Name, binding.Rule.Domain, custom) {
			continue
		}
		// Only a replacement for this pool needs to be ready before removing
		// its old name. Legacy single-instance names have no replacement.
		if replacement, ok := replacements[binding.Rule.ID]; binding.Rule.Kind == "pool" && ok {
			accounts, err := w.Store.LoadAccounts(false)
			if err != nil {
				return err
			}
			if !w.syncPoolRule(ctx, time.Now(), settings, replacement, accounts) {
				failures = append(failures, fmt.Errorf("%s 尚未同步，稍后重试旧解析清理", replacement.FQDN()))
				continue
			}
		}
		service, err := w.dnsService(settings.ForRule(binding.Rule))
		if err == nil {
			var deleted bool
			deleted, err = service.DeleteByName(ctx, binding.Name)
			if deleted {
				w.Store.AddLog("info", "已删除旧解析 "+binding.Name)
			}
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("删除旧解析 %s: %w", binding.Name, err))
		}
	}
	return errors.Join(failures...)
}
