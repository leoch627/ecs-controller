package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Kori1c/ecs-controller/internal/dns"
	"github.com/Kori1c/ecs-controller/internal/notify"
	"github.com/Kori1c/ecs-controller/internal/store"
)

// DNSCleanupResult is stored on a finished cleanup job for the history view.
type DNSCleanupResult struct {
	Outcome string       `json:"outcome"` // done | skipped
	Message string       `json:"message"`
	Changes []dns.Change `json:"changes,omitempty"`
}

// dnsCleanupJob removes an IP that no longer belongs to a live instance from
// every A record in scope. Errors are retried by the job runner.
func (w *Worker) dnsCleanupJob(ctx context.Context, job *store.Job) error {
	var payload store.DNSCleanupPayload
	if err := json.Unmarshal([]byte(job.Payload), &payload); err != nil {
		return err
	}
	settings := w.dnsSettings()
	if !settings.CleanupEnabled {
		return w.finishDNSCleanup(job, DNSCleanupResult{Outcome: "skipped", Message: "解析清理已关闭，未处理"})
	}
	if !settings.Configured() {
		return fmt.Errorf("解析服务商凭据没有填写完整")
	}
	if user := w.activeInstanceUsingIP(payload.IP); user != "" {
		w.Store.AddLog("info", fmt.Sprintf("解析清理已跳过 %s：仍被实例 %s 使用", payload.IP, user))
		return w.finishDNSCleanup(job, DNSCleanupResult{Outcome: "skipped", Message: "IP 仍被实例 " + user + " 使用，已跳过"})
	}
	service, err := w.dnsService(settings)
	if err != nil {
		return err
	}
	cleanupCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	changes, err := service.RemoveIP(cleanupCtx, payload.IP)
	if err != nil {
		w.Store.AddLog("warning", fmt.Sprintf("解析清理失败 [%s] %s（第 %d 次）：%v", payload.Label, payload.IP, job.Attempts, err))
		return err
	}
	summary := dns.SummarizeChanges(changes)
	w.Store.AddLog("info", fmt.Sprintf("解析清理完成 [%s] %s：%s", payload.Label, payload.IP, summary))
	if len(changes) > 0 {
		w.dispatchEvent(ctx, dnsCleanupEvent(payload, "失效实例的解析已清理", summary))
	}
	return w.finishDNSCleanup(job, DNSCleanupResult{Outcome: "done", Message: summary, Changes: changes})
}

func (w *Worker) finishDNSCleanup(job *store.Job, result DNSCleanupResult) error {
	raw, _ := json.Marshal(result)
	return w.Store.SetJobResult(job.JobID, string(raw))
}

// activeInstanceUsingIP names a live, unexpired instance that still has ip.
// Such an IP must stay in DNS even if an older owner of it went away.
func (w *Worker) activeInstanceUsingIP(ip string) string {
	accounts, err := w.Store.LoadAccounts(false)
	if err != nil {
		return ""
	}
	expiries := w.Store.ExpiryByInstance()
	now := time.Now()
	for _, account := range accounts {
		if account.InstanceID == "" || expiries[account.InstanceID].Expired(now) {
			continue
		}
		if store.AccountPublicIP(account) == ip {
			return accountLabel(account) + " " + account.InstanceID
		}
	}
	return ""
}

func (w *Worker) notifyDNSCleanupFailed(ctx context.Context, job *store.Job, cause error) {
	var payload store.DNSCleanupPayload
	if json.Unmarshal([]byte(job.Payload), &payload) != nil {
		return
	}
	w.dispatchEvent(ctx, dnsCleanupEvent(payload, "解析清理失败", fmt.Sprintf("重试 %d 次仍失败：%v", job.Attempts, cause)))
}

func dnsCleanupEvent(payload store.DNSCleanupPayload, title, result string) notify.Event {
	reason := store.DNSCleanupReasonText(payload.Reason)
	return notify.Event{
		Title:     title,
		Summary:   result,
		AccountID: payload.Label,
		Text: fmt.Sprintf("【ECS 控制台】%s\n实例: %s\n公网 IP: %s\n触发原因: %s\n处理结果: %s\n时间: %s",
			title, payload.Label, payload.IP, reason, result, time.Now().Format("2006-01-02 15:04:05")),
		Fields: map[string]string{"ip": payload.IP, "instance_id": payload.InstanceID, "reason": payload.Reason},
	}
}
