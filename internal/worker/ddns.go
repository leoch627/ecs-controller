package worker

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/dns"
	"github.com/Kori1c/ecs-controller/internal/store"
)

const (
	poolRetryDelay = 10 * time.Minute
	// dnsRefresh rewrites unchanged names now and then to undo manual edits.
	dnsRefresh = 6 * time.Hour
)

func (w *Worker) dnsSettings() dns.Settings {
	return dns.LoadSettings(w.Store.GetSetting, w.Store.OpenSecret)
}

func (w *Worker) dnsService(settings dns.Settings) (*dns.Service, error) {
	return dns.NewService(settings, w.DNSClient)
}

// SyncAccountDNS brings every name up to date right after an IP swap or a
// name change, instead of waiting for the monitor.
func (w *Worker) SyncAccountDNS(ctx context.Context, _ int64) {
	w.syncDNSNames(ctx, time.Now())
}

// dnsNamePlan is what one name should resolve to now.
type dnsNamePlan struct {
	IPs []string
	// Held is true while any existing machine lists the name, even a stopped
	// one; only names nobody holds are deleted.
	Held bool
}

// planDNSNames collects, for every name a machine holds, the public IPs of
// the holders that can serve: running, present and not expired.
func (w *Worker) planDNSNames(accounts []app.Account, now time.Time) map[string]*dnsNamePlan {
	hosts := w.Store.DNSHosts()
	plans := map[string]*dnsNamePlan{}
	for _, account := range accounts {
		if account.InstanceID == "" || account.IsDeleted != 0 || account.CloudPresence == "missing" {
			continue
		}
		for _, name := range hosts[dns.InstanceKey(account)] {
			plan := plans[name]
			if plan == nil {
				plan = &dnsNamePlan{}
				plans[name] = plan
			}
			plan.Held = true
			if account.InstanceStatus != "Running" || w.Store.InstanceExpiry(account.InstanceID).Expired(now) {
				continue
			}
			if ip := store.AccountPublicIP(account); dns.IsPublicIPv4(ip) && !slices.Contains(plan.IPs, ip) {
				plan.IPs = append(plan.IPs, ip)
			}
		}
	}
	for _, plan := range plans {
		slices.Sort(plan.IPs)
	}
	return plans
}

// syncDNSNames points each held name at its holders' IPs: one holder is a
// plain DDNS record, several are a round-robin set. A name whose holders
// are all stopped keeps its last records; a name no machine holds any more
// is deleted. Each name is handled on its own, so one failing provider never
// blocks the others, and a failure backs off for poolRetryDelay.
func (w *Worker) syncDNSNames(ctx context.Context, now time.Time) {
	w.Store.DNSConfigMu.Lock()
	defer w.Store.DNSConfigMu.Unlock()
	if ctx.Err() != nil {
		return
	}
	accounts, err := w.Store.LoadAccounts(false)
	if err != nil {
		return
	}
	settings := w.dnsSettings()
	plans := w.planDNSNames(accounts, now)
	managed := w.Store.DNSManaged()
	names := make([]string, 0, len(plans)+len(managed))
	for name := range plans {
		names = append(names, name)
	}
	for name := range managed {
		if plans[name] == nil {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, name := range names {
		if ctx.Err() != nil {
			break
		}
		plan := plans[name]
		if plan != nil && len(plan.IPs) == 0 {
			continue
		}
		domain, ok := settings.DomainFor(name)
		if !ok {
			continue
		}
		scoped := settings.ForDomain(domain)
		var ips []string
		if plan != nil {
			ips = plan.IPs
		}
		// Credentials and zone changes also invalidate a cached success.
		raw, _ := json.Marshal(struct {
			Domain      dns.Domain
			Credentials dns.Config
			IPs         []string
		}{domain, scoped.Credentials[domain.Provider], ips})
		state := fmt.Sprintf("%x", sha256.Sum256(raw))
		current := managed[name]
		if now.Unix() < current.RetryAt && current.Attempt == state {
			continue
		}
		if current.State == state && now.Unix()-current.SyncedAt < int64(dnsRefresh/time.Second) {
			continue
		}
		service, err := w.dnsService(scoped)
		var added, removed int
		if err == nil {
			if plan == nil {
				var deleted bool
				if deleted, err = service.DeleteByName(ctx, name); err == nil {
					delete(managed, name)
					if deleted {
						w.Store.AddLog("info", "已删除不再使用的解析 "+name)
					}
					continue
				}
			} else {
				added, removed, err = service.SyncPool(ctx, name, ips)
			}
		}
		if err != nil {
			// A partly applied update can invalidate even an earlier success.
			managed[name] = store.DNSNameState{Attempt: state, RetryAt: now.Add(poolRetryDelay).Unix()}
			w.Store.AddLog("warning", fmt.Sprintf("解析同步失败 [%s]: %v", name, err))
			continue
		}
		managed[name] = store.DNSNameState{State: state, SyncedAt: now.Unix()}
		if added+removed > 0 {
			if len(ips) == 1 {
				w.Store.AddLog("info", fmt.Sprintf("解析已同步 %s -> %s", name, ips[0]))
			} else {
				w.Store.AddLog("info", fmt.Sprintf("负载均衡解析已同步 %s：%d 个 IP（新增 %d，移除 %d）", name, len(ips), added, removed))
			}
		}
	}
	if err := w.Store.SetDNSManaged(managed); err != nil {
		w.Store.AddLog("warning", "保存解析同步状态失败: "+err.Error())
	}
}
