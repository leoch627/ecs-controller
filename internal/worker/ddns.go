package worker

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/dns"
	"github.com/Kori1c/ecs-controller/internal/store"
)

func (w *Worker) dnsSettings() dns.Settings {
	return dns.LoadSettings(w.Store.GetSetting, w.Store.OpenSecret)
}

func (w *Worker) dnsService(settings dns.Settings) (*dns.Service, error) {
	return dns.NewService(settings, w.DNSClient)
}

// syncDDNSAccount points the account's DDNS name at its public IP. It
// returns false only when the provider call failed, so the caller can retry.
func (w *Worker) syncDDNSAccount(ctx context.Context, account app.Account) bool {
	settings := w.dnsSettings()
	if !settings.DDNSActive() || account.InstanceID == "" || account.CloudPresence == "missing" {
		return true
	}
	// An expired instance's IP is being removed from DNS; writing it back
	// here would undo the cleanup.
	if w.Store.InstanceExpiry(account.InstanceID).Expired(time.Now()) {
		return true
	}
	address := store.AccountPublicIP(account)
	if address == "" {
		return true
	}
	service, err := w.dnsService(settings)
	if err != nil {
		w.Store.AddLog("warning", "DDNS 同步失败: "+err.Error())
		return false
	}
	accounts, _ := w.Store.LoadAccounts(false)
	name := w.ddnsRecordName(account, accounts)
	action, err := service.SyncA(ctx, name, address)
	if err != nil {
		w.Store.AddLog("warning", service.Label()+" DDNS 同步失败: "+err.Error())
		return false
	}
	if action != "unchanged" {
		w.Store.AddLog("info", fmt.Sprintf("DDNS 已同步 [%s] %s -> %s", accountLabel(account), name, address))
	}
	return true
}

// SyncAccountDNS updates the instance's DDNS record and the round-robin name
// right after its public IP changed, instead of waiting for the monitor. A
// failed DDNS update is retried on the monitor's next pass.
func (w *Worker) SyncAccountDNS(ctx context.Context, accountID int64) {
	account, err := w.Store.Account(accountID, false)
	if err != nil {
		return
	}
	if !w.syncDDNSAccount(ctx, *account) {
		_ = w.Store.SetSetting("last_ddns_reconcile", "0")
	}
	w.syncDDNSPool(ctx, time.Now())
}

// deleteDDNSAccount removes the record of an instance that is gone, then
// forgets the name chosen for it.
func (w *Worker) deleteDDNSAccount(ctx context.Context, account app.Account, before []app.Account) error {
	if account.InstanceID == "" {
		return nil
	}
	settings := w.dnsSettings()
	if !settings.DDNSActive() {
		_ = w.Store.DeleteCustomDNSName(account)
		return nil
	}
	service, err := w.dnsService(settings)
	if err != nil {
		return err
	}
	name := w.ddnsRecordName(account, before)
	deleted, err := service.DeleteByName(ctx, name)
	if err != nil {
		w.Store.AddLog("warning", service.Label()+" DDNS 清理失败: "+err.Error())
		return err
	}
	if deleted {
		w.Store.AddLog("info", "DDNS 已删除: "+name)
	}
	_ = w.Store.DeleteCustomDNSName(account)
	return nil
}

func ddnsPayloadAccount(account app.Account) map[string]any {
	return map[string]any{"GroupKey": account.GroupKey, "AccessKeyID": account.AccessKeyID, "RegionID": account.RegionID, "InstanceID": account.InstanceID, "Remark": account.Remark, "InstanceName": account.InstanceName, "SiteType": account.SiteType}
}

func ddnsPayloadAccounts(accounts []app.Account) []map[string]any {
	result := make([]map[string]any, 0, len(accounts))
	for _, account := range accounts {
		result = append(result, ddnsPayloadAccount(account))
	}
	return result
}

func (w *Worker) syncAllDDNS(ctx context.Context) {
	if !w.ddnsEnabled() {
		return
	}
	accounts, _ := w.Store.LoadAccounts(false)
	for _, account := range accounts {
		w.syncDDNSAccount(ctx, account)
	}
}

// syncDDNSPool points the round-robin name at every running instance. It
// only calls the provider when that set changed, or every six hours to undo
// manual edits, and backs off for ten minutes after a failure.
func (w *Worker) syncDDNSPool(ctx context.Context, now time.Time) {
	settings := w.dnsSettings()
	if !settings.PoolActive() {
		return
	}
	accounts, err := w.Store.LoadAccounts(false)
	if err != nil {
		return
	}
	ips := make([]string, 0, len(accounts))
	for _, account := range accounts {
		// A stopped instance keeps its EIP but cannot serve, so leave it out.
		if account.InstanceStatus != "Running" || account.CloudPresence == "missing" || w.Store.InstanceExpiry(account.InstanceID).Expired(now) {
			continue
		}
		if ip := store.AccountPublicIP(account); ip != "" {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		// Keep the last records rather than leave the name resolving to nothing.
		return
	}
	slices.Sort(ips)
	ips = slices.Compact(ips)
	name := settings.PoolFQDN()
	state := name + "=" + strings.Join(ips, ",")
	retryAt, _ := strconv.ParseInt(w.Store.GetSetting("ddns_pool_retry_at", "0"), 10, 64)
	syncedAt, _ := strconv.ParseInt(w.Store.GetSetting("ddns_pool_synced_at", "0"), 10, 64)
	if now.Unix() < retryAt || (w.Store.GetSetting("ddns_pool_state", "") == state && now.Unix()-syncedAt < 6*60*60) {
		return
	}
	service, err := w.dnsService(settings)
	if err == nil {
		var added, removed int
		if added, removed, err = service.SyncPool(ctx, name, ips); err == nil {
			_ = w.Store.SetSetting("ddns_pool_state", state)
			_ = w.Store.SetSetting("ddns_pool_synced_at", strconv.FormatInt(now.Unix(), 10))
			_ = w.Store.SetSetting("ddns_pool_retry_at", "0")
			if added+removed > 0 {
				w.Store.AddLog("info", fmt.Sprintf("轮询解析已同步 %s：%d 个 IP（新增 %d，移除 %d）", name, len(ips), added, removed))
			}
			return
		}
	}
	_ = w.Store.SetSetting("ddns_pool_retry_at", strconv.FormatInt(now.Add(10*time.Minute).Unix(), 10))
	w.Store.AddLog("warning", "轮询解析同步失败: "+err.Error())
}

func (w *Worker) ddnsEnabled() bool {
	return w.dnsSettings().DDNSActive()
}

func (w *Worker) ddnsRecordName(account app.Account, accounts []app.Account) string {
	return w.Store.DDNSRecordName(account, accounts)
}
