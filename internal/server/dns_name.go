package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Kori1c/ecs-controller/internal/dns"
)

// setInstanceDNSNames replaces the DNS names one machine holds. A name only
// this machine holds points at it; a name other machines hold too becomes a
// round-robin set. Names dropped by every machine are deleted by the sync.
func (s *Server) setInstanceDNSNames(w http.ResponseWriter, data map[string]any) {
	id := int64(number(data["accountId"], 0))
	a, err := s.Store.Account(id, false)
	if err != nil {
		s.error(w, 404, "账号不存在")
		return
	}
	var raw []string
	switch value := data["names"].(type) {
	case []any:
		for _, item := range value {
			raw = append(raw, stringValue(item))
		}
	case string:
		raw = strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '，' || r == ' ' || r == '\n' })
	}
	s.Store.DNSConfigMu.Lock()
	settings := dns.LoadSettings(s.Store.GetSetting, nil)
	if len(settings.Domains) == 0 {
		s.Store.DNSConfigMu.Unlock()
		s.error(w, 400, "请先在「系统设置 → 域名解析」里添加根域名")
		return
	}
	names, err := settings.NormalizeHostNames(raw)
	if err == nil && len(names) > 10 {
		err = fmt.Errorf("一台机器最多 10 个解析名称")
	}
	if err == nil {
		err = s.Store.SetDNSHostNames(*a, names)
	}
	s.Store.DNSConfigMu.Unlock()
	if err != nil {
		s.error(w, 400, err.Error())
		return
	}
	summary := strings.Join(names, "、")
	if summary == "" {
		summary = "（无）"
	}
	s.Store.AddLog("info", fmt.Sprintf("%s 的解析名称已设为：%s", accountDisplay(*a), summary))
	if s.SyncDNS != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		s.SyncDNS(ctx, id)
		cancel()
	}
	s.json(w, 200, map[string]any{"success": true, "message": "解析名称已保存，记录已同步（失败会在系统日志里显示并自动重试）", "data": map[string]any{"dnsNames": names}})
}
