package worker

import (
	"context"
	"fmt"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/notify"
)

func (w *Worker) dispatchEvent(ctx context.Context, event notify.Event) error {
	settings := w.Store.Settings()
	cfg := notify.ConfigFromSettings(settings, w.Store.OpenSecret)
	notifyCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- (notify.Dispatcher{Config: cfg}).Dispatch(notifyCtx, event) }()
	var err error
	select {
	case err = <-done:
	case <-notifyCtx.Done():
		err = notifyCtx.Err()
	}
	if err != nil {
		w.Store.AddLog("warning", "通知发送失败: "+err.Error())
		return err
	}
	return nil
}

func accountLabel(account app.Account) string {
	if account.Remark != "" {
		return account.Remark
	}
	if account.InstanceName != "" {
		return account.InstanceName
	}
	if account.InstanceID != "" {
		return account.InstanceID
	}
	return account.AccessKeyID
}

func statusEvent(account app.Account, from, to, reason string) notify.Event {
	return notify.Event{Title: "实例状态变化", Summary: fmt.Sprintf("%s 状态从 %s 变为 %s", accountLabel(account), from, to), AccountID: accountLabel(account), Lines: append(notify.InstanceLines(accountLabel(account), account.InstanceID, account.RegionID), notify.L("原状态", from), notify.L("新状态", to), notify.L("说明", reason)), Fields: map[string]string{"instance_id": account.InstanceID, "region": account.RegionID, "from_status": from, "to_status": to}}
}

func trafficEvent(account app.Account, used, percent, threshold float64, action string) notify.Event {
	return notify.Event{Title: "流量保护告警", Summary: fmt.Sprintf("%s 当前使用率 %.2f%%", accountLabel(account), percent), AccountID: accountLabel(account), Lines: append(notify.InstanceLines(accountLabel(account), account.InstanceID, account.RegionID), notify.L("当前流量", fmt.Sprintf("%.2f GB", used)), notify.L("使用率", fmt.Sprintf("%.2f%%", percent)), notify.L("阈值", fmt.Sprintf("%.2f%%", threshold)), notify.L("动作", action)), Fields: map[string]string{"traffic": fmt.Sprintf("%.2f GB", used), "max_traffic": fmt.Sprintf("%.2f%%", threshold), "percentage": fmt.Sprintf("%.2f%%", percent), "action": action, "instance_id": account.InstanceID}}
}
