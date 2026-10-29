package worker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/notify"
)

const (
	dailyTrafficEnabledSetting = "notify_daily_enabled"
	dailyTrafficTimeSetting    = "notify_daily_time"
	dailyTrafficLastDate       = "notify_daily_last_date"
)

func (w *Worker) runDailyTrafficSummary(ctx context.Context, now time.Time) {
	if w.Store.GetSetting(dailyTrafficEnabledSetting, "0") != "1" {
		return
	}
	reportTime, err := time.ParseInLocation("15:04", w.Store.GetSetting(dailyTrafficTimeSetting, "00:00"), now.Location())
	if err != nil {
		w.Store.AddLog("warning", "每日流量摘要时间配置无效")
		return
	}
	scheduled := time.Date(now.Year(), now.Month(), now.Day(), reportTime.Hour(), reportTime.Minute(), 0, 0, now.Location())
	if now.Before(scheduled) {
		return
	}
	reportDay := now.AddDate(0, 0, -1)
	reportDate := reportDay.Format("2006-01-02")
	if w.Store.GetSetting(dailyTrafficLastDate, "") == reportDate {
		return
	}

	settings := w.Store.Settings()
	cfg := notify.ConfigFromSettings(settings, w.Store.OpenSecret)
	if !hasConfiguredNotificationChannel(cfg) {
		return
	}
	event, err := w.dailyTrafficEvent(ctx, reportDay)
	if err != nil {
		w.Store.AddLog("warning", "每日流量摘要生成失败: "+err.Error())
		return
	}
	if err := w.dispatchEvent(ctx, event); err != nil {
		return
	}
	if err := w.Store.SetSetting(dailyTrafficLastDate, reportDate); err != nil {
		w.Store.AddLog("warning", "每日流量摘要发送状态保存失败: "+err.Error())
	}
}

func hasConfiguredNotificationChannel(cfg notify.EventConfig) bool {
	return (cfg.EmailEnabled && cfg.Email != "" && cfg.SMTPHost != "") ||
		(cfg.TelegramEnabled && cfg.TelegramToken != "" && cfg.TelegramChatID != "") ||
		(cfg.WebhookEnabled && cfg.WebhookURL != "")
}

func (w *Worker) dailyTrafficEvent(ctx context.Context, reportDay time.Time) (notify.Event, error) {
	groups, err := w.Store.LoadGroups()
	if err != nil {
		return notify.Event{}, err
	}
	complete := true
	cdtLines := make([]string, 0, len(groups))
	for _, group := range groups {
		client := w.Cloud
		if w.CloudFactory != nil {
			client = w.CloudFactory(group)
		}
		if client == nil {
			complete = false
			cdtLines = append(cdtLines, fmt.Sprintf("- %s：数据不可用", groupLabel(group)))
			continue
		}
		traffic, trafficErr := client.GetTraffic(ctx, group.RegionID)
		if trafficErr != nil {
			complete = false
			cdtLines = append(cdtLines, fmt.Sprintf("- %s：数据不可用", groupLabel(group)))
			continue
		}
		if group.MaxTraffic > 0 {
			cdtLines = append(cdtLines, fmt.Sprintf("- %s：%.2f GB/%g GB", groupLabel(group), traffic, group.MaxTraffic))
		} else {
			complete = false
			cdtLines = append(cdtLines, fmt.Sprintf("- %s：%.2f GB/额度未设置", groupLabel(group), traffic))
		}
	}
	if len(cdtLines) == 0 {
		cdtLines = append(cdtLines, "- 暂无有效账号数据")
	}

	status := "完整"
	if !complete {
		status = "不完整"
	}
	text := strings.Join([]string{
		fmt.Sprintf("每日流量摘要（%s）", reportDay.Format("2006-01-02")),
		"",
		"账号流量已使用：",
		strings.Join(cdtLines, "\n"),
		"",
		"数据状态：" + status,
	}, "\n")
	return notify.Event{
		Title:   "每日流量摘要",
		Summary: fmt.Sprintf("每日流量摘要（%s）", reportDay.Format("2006-01-02")),
		Text:    text,
		Fields: map[string]string{
			"report_date": reportDay.Format("2006-01-02"),
			"data_status": status,
		},
	}, nil
}

func groupLabel(group app.AccountGroup) string {
	if strings.TrimSpace(group.Remark) != "" {
		return group.Remark
	}
	if strings.TrimSpace(group.AccessKeyID) != "" {
		return group.AccessKeyID
	}
	return group.RegionID
}
