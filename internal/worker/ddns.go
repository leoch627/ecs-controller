package worker

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/dns"
	"github.com/Kori1c/ecs-controller/internal/store"
)

const poolRetryDelay = 10 * time.Minute

func (w *Worker) dnsSettings() dns.Settings {
	return dns.LoadSettings(w.Store.GetSetting, w.Store.OpenSecret)
}

func (w *Worker) dnsService(settings dns.Settings) (*dns.Service, error) {
	return dns.NewService(settings, w.DNSClient)
}

// SyncAccountDNS updates all affected pool memberships after a public IP swap.
func (w *Worker) SyncAccountDNS(ctx context.Context, _ int64) {
	w.syncDDNSPool(ctx, time.Now())
}

// syncDDNSPool reconciles each pool independently; one failing provider must
// not block other domains. Empty membership removes the old pool records.
func (w *Worker) syncDDNSPool(ctx context.Context, now time.Time) {
	w.Store.DNSConfigMu.Lock()
	defer w.Store.DNSConfigMu.Unlock()
	if ctx.Err() != nil {
		return
	}
	settings := w.dnsSettings()
	accounts, err := w.Store.LoadAccounts(false)
	if err != nil {
		return
	}
	for _, rule := range settings.EffectiveRules() {
		if !rule.Enabled || rule.Kind != "pool" {
			continue
		}
		w.syncPoolRule(ctx, now, settings, rule, accounts)
	}
}

func (w *Worker) syncPoolRule(ctx context.Context, now time.Time, settings dns.Settings, rule dns.Rule, accounts []app.Account) bool {
	scoped := settings.ForRule(rule)
	ips := make([]string, 0, len(accounts))
	for _, account := range accounts {
		if !rule.Scope.Matches(account) || account.InstanceStatus != "Running" || account.CloudPresence == "missing" || w.Store.InstanceExpiry(account.InstanceID).Expired(now) {
			continue
		}
		if ip := store.AccountPublicIP(account); dns.IsPublicIPv4(ip) {
			ips = append(ips, ip)
		}
	}
	slices.Sort(ips)
	ips = slices.Compact(ips)
	name := rule.FQDN()
	prefix := "ddns_rule_pool_" + rule.ID
	if rule.ID == "legacy-pool" {
		prefix = "ddns_pool"
	}
	// Credentials, zone and selector changes also invalidate a cached success.
	raw, _ := json.Marshal(struct {
		Rule        dns.Rule
		Credentials map[string]dns.Config
		IPs         []string
	}{rule, scoped.Credentials, ips})
	state := fmt.Sprintf("pool-only:%x", sha256.Sum256(raw))
	retryAt, _ := strconv.ParseInt(w.Store.GetSetting(prefix+"_retry_at", "0"), 10, 64)
	syncedAt, _ := strconv.ParseInt(w.Store.GetSetting(prefix+"_synced_at", "0"), 10, 64)
	if now.Unix() < retryAt && w.Store.GetSetting(prefix+"_attempt", "") == state {
		return false
	}
	if w.Store.GetSetting(prefix+"_state", "") == state && now.Unix()-syncedAt < 6*60*60 {
		return true
	}
	service, err := w.dnsService(scoped)
	if err == nil {
		var added, removed int
		if len(ips) == 0 {
			var deleted bool
			deleted, err = service.DeleteByName(ctx, name)
			if deleted {
				removed = 1
			}
		} else {
			added, removed, err = service.SyncPool(ctx, name, ips)
		}
		if err == nil {
			_ = w.Store.SetSetting(prefix+"_state", state)
			_ = w.Store.SetSetting(prefix+"_synced_at", strconv.FormatInt(now.Unix(), 10))
			_ = w.Store.SetSetting(prefix+"_retry_at", "0")
			if added+removed > 0 {
				w.Store.AddLog("info", fmt.Sprintf("负载均衡解析已同步 %s：%d 个 IP（新增 %d，移除 %d）", name, len(ips), added, removed))
			}
			return true
		}
	}
	// A partially applied update can invalidate even a previously successful set.
	_ = w.Store.SetSetting(prefix+"_state", "")
	_ = w.Store.SetSetting(prefix+"_attempt", state)
	_ = w.Store.SetSetting(prefix+"_retry_at", strconv.FormatInt(now.Add(poolRetryDelay).Unix(), 10))
	w.Store.AddLog("warning", "负载均衡解析同步失败 ["+name+"]: "+err.Error())
	return false
}
