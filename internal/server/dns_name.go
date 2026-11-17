package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Kori1c/ecs-controller/internal/dns"
	"github.com/Kori1c/ecs-controller/internal/store"
)

// setInstanceDNSName gives one instance its own DNS name, or puts it back on
// the automatic one when the name is empty. With DDNS on, the new record is
// written before the old one is removed, so the machine stays reachable.
func (s *Server) setInstanceDNSName(w http.ResponseWriter, data map[string]any) {
	id := int64(number(data["accountId"], 0))
	a, err := s.Store.Account(id, false)
	if err != nil {
		s.error(w, 404, "账号不存在")
		return
	}
	settings := dns.LoadSettings(s.Store.GetSetting, s.Store.OpenSecret)
	custom, err := store.NormalizeDNSName(stringValue(data["name"]), settings.Domain)
	if err != nil {
		s.error(w, 400, err.Error())
		return
	}
	accounts, err := s.Store.LoadAccounts(false)
	if err != nil {
		s.error(w, 500, "读取实例失败")
		return
	}
	oldName := s.Store.DDNSRecordName(*a, accounts)
	newName := s.Store.DDNSNameWith(*a, accounts, custom)
	if pool := settings.PoolFQDN(); pool != "" && newName == pool {
		s.error(w, 400, "解析名称不能和轮询解析的名称相同")
		return
	}
	for _, other := range accounts {
		if other.ID != a.ID && other.InstanceID != "" && s.Store.DDNSRecordName(other, accounts) == newName {
			s.error(w, 400, fmt.Sprintf("%s 已被实例 %s 使用", newName, accountDisplay(other)))
			return
		}
	}
	previous := s.Store.CustomDNSName(*a)
	if err := s.Store.SetCustomDNSName(*a, custom); err != nil {
		s.error(w, 500, "保存解析名称失败: "+err.Error())
		return
	}
	reply := func(message string) {
		s.json(w, 200, map[string]any{"success": true, "message": message, "data": map[string]any{"dnsName": newName, "dnsCustom": custom != ""}})
	}
	if !settings.DDNSActive() {
		reply(fmt.Sprintf("已保存，开启 DDNS 后会解析到 %s", newName))
		return
	}
	ip := store.AccountPublicIP(*a)
	if oldName == newName || ip == "" {
		reply(fmt.Sprintf("解析名称为 %s", newName))
		return
	}
	service, err := dns.NewService(settings, s.DNSClient)
	if err != nil {
		_ = s.Store.SetCustomDNSName(*a, previous)
		s.error(w, 400, "解析服务不可用: "+err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if _, err := service.SyncA(ctx, newName, ip); err != nil {
		_ = s.Store.SetCustomDNSName(*a, previous)
		s.error(w, 400, fmt.Sprintf("写入 %s 失败，名称未修改: %s", newName, err.Error()))
		return
	}
	s.Store.AddLog("info", fmt.Sprintf("%s 的解析已改为 %s -> %s", accountDisplay(*a), newName, ip))
	if _, err := service.DeleteByName(ctx, oldName); err != nil {
		s.Store.AddLog("warning", fmt.Sprintf("旧解析 %s 删除失败: %s", oldName, err.Error()))
		reply(fmt.Sprintf("已解析到 %s，但旧名称 %s 删除失败，请到 DNS 服务商手动删除", newName, oldName))
		return
	}
	reply(fmt.Sprintf("已解析到 %s，旧名称 %s 已删除", newName, oldName))
}
