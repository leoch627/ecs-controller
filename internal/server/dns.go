package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Kori1c/ecs-controller/internal/dns"
	"github.com/Kori1c/ecs-controller/internal/store"
)

// dnsConfig is the DNS section of get_config. Secrets are masked; every
// provider's values are included so switching providers keeps them.
func (s *Server) dnsConfig() map[string]any {
	settings := dns.LoadSettings(s.Store.GetSetting, nil)
	credentials := map[string]any{}
	for _, info := range dns.Providers() {
		values := map[string]any{}
		for _, field := range info.Fields {
			raw := settings.Credentials[info.ID][field.Key]
			switch field.Type {
			case "secret":
				values[field.Key] = masked(raw)
			case "switch":
				values[field.Key] = raw == "1"
			default:
				values[field.Key] = raw
			}
		}
		credentials[info.ID] = values
	}
	rules := append([]dns.Rule{}, settings.EffectiveRules()...)
	return map[string]any{
		"rules":           rules,
		"cleanup_enabled": settings.CleanupEnabled,
		"provider":        settings.Provider,
		"domain":          settings.Domain,
		"pool_name":       settings.PoolName,
		"credentials":     credentials,
	}
}

// saveDNSConfig stores the DNS section of save_config.
func (s *Server) saveDNSConfig(ddns map[string]any) error {
	s.Store.DNSConfigMu.Lock()
	defer s.Store.DNSConfigMu.Unlock()
	previous := dns.LoadSettings(s.Store.GetSetting, s.Store.OpenSecret)
	values := map[string]string{
		"ddns_enabled": "0", "dns_cleanup_enabled": bool01(ddns["cleanup_enabled"]),
		// Let the next monitor pass write every machine's own record.
		"last_ddns_reconcile": "0",
		"ddns_provider":       dns.NormalizeID(stringValue(ddns["provider"])),
		"ddns_domain":         dns.NormalizeDomain(stringValue(ddns["domain"])),
		"ddns_pool_name":      dns.NormalizeDomain(stringValue(ddns["pool_name"])),
	}
	if raw, exists := ddns["rules"]; exists {
		encoded, err := json.Marshal(raw)
		if err != nil {
			return err
		}
		rules := []dns.Rule{}
		if string(encoded) == "null" {
			return fmt.Errorf("解析规则必须是列表，关闭全部规则请传空列表")
		}
		if err := json.Unmarshal(encoded, &rules); err != nil {
			return fmt.Errorf("解析规则格式无效: %w", err)
		}
		if err := dns.ValidateRules(rules); err != nil {
			return err
		}
		encoded, _ = json.Marshal(rules)
		values["ddns_rules"] = string(encoded)
	}
	credentials, _ := ddns["credentials"].(map[string]any)
	if credentials == nil {
		credentials = map[string]any{}
	}
	if legacy, ok := ddns["cloudflare"].(map[string]any); ok && credentials["cloudflare"] == nil {
		credentials["cloudflare"] = legacy
	}
	for _, info := range dns.Providers() {
		fields, ok := credentials[info.ID].(map[string]any)
		if !ok {
			continue
		}
		for _, field := range info.Fields {
			value, supplied := fields[field.Key]
			if !supplied {
				continue
			}
			key := dns.SettingKey(info.ID, field.Key)
			switch field.Type {
			case "secret":
				plain := strings.TrimSpace(stringValue(value))
				if plain == "" || plain == "********" {
					continue
				}
				sealed, err := s.Store.Seal(plain)
				if err != nil {
					return err
				}
				values[key] = sealed
			case "switch":
				values[key] = bool01(value)
			default:
				values[key] = strings.TrimSpace(stringValue(value))
			}
		}
	}
	draft := dns.LoadSettings(func(key, fallback string) string {
		if value, ok := values[key]; ok {
			return value
		}
		return s.Store.GetSetting(key, fallback)
	}, s.Store.OpenSecret)
	accounts, err := s.Store.LoadAccounts(false)
	if err != nil {
		return err
	}
	if draft.RulesConfigured {
		for _, rule := range draft.Rules {
			if rule.Enabled && !draft.ForRule(rule).Configured() {
				return fmt.Errorf("%s 的 %s 凭据没有填写完整", rule.Domain, dns.Lookup(rule.Provider).Label)
			}
		}
	}
	bindings := s.Store.DNSBindings(draft, accounts)
	names, keys := map[string]bool{}, map[string]bool{}
	for _, binding := range bindings {
		if names[binding.Name] {
			return fmt.Errorf("解析名称 %s 重复，负载均衡名称不能和单机解析名称相同", binding.Name)
		}
		names[binding.Name], keys[binding.Key()] = true, true
	}
	retired := []store.DNSBinding{}
	for _, binding := range s.Store.DNSBindings(previous, accounts) {
		if !keys[binding.Key()] {
			retired = append(retired, binding)
		}
	}
	return s.Store.SaveDNSSettings(values, retired)
}

// testDNS checks the form's (possibly unsaved) provider settings. Masked
// secrets fall back to the saved values.
func (s *Server) testDNS(w http.ResponseWriter, data map[string]any) {
	draft, _ := data["Ddns"].(map[string]any)
	settings := dns.LoadSettings(s.Store.GetSetting, s.Store.OpenSecret)
	settings.Provider = dns.NormalizeID(stringValue(draft["provider"]))
	settings.Domain = dns.NormalizeDomain(stringValue(draft["domain"]))
	info := dns.Lookup(settings.Provider)
	credentials, _ := draft["credentials"].(map[string]any)
	values, _ := credentials[info.ID].(map[string]any)
	cfg := dns.Config{}
	for key, value := range settings.Credentials[info.ID] {
		cfg[key] = value
	}
	for _, field := range info.Fields {
		value := strings.TrimSpace(stringValue(values[field.Key]))
		switch {
		case field.Type == "switch":
			cfg[field.Key] = bool01(values[field.Key])
		case field.Type == "secret" && (value == "********" || value == ""):
			// keep the saved secret
		default:
			cfg[field.Key] = value
		}
	}
	settings.Credentials[info.ID] = cfg
	if raw, ok := data["rule"]; ok {
		encoded, _ := json.Marshal(raw)
		var rule dns.Rule
		if err := json.Unmarshal(encoded, &rule); err != nil {
			s.error(w, 400, "解析规则格式无效")
			return
		}
		rules := []dns.Rule{rule}
		if err := dns.ValidateRules(rules); err != nil {
			s.error(w, 400, err.Error())
			return
		}
		settings = settings.ForRule(rules[0])
	}

	service, err := dns.NewService(settings, s.DNSClient)
	if err != nil {
		s.json(w, 200, map[string]any{"success": false, "message": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if truthy(data["list_zones"]) {
		zones, err := service.Zones(ctx)
		if err != nil {
			s.error(w, 400, err.Error())
			return
		}
		s.json(w, 200, map[string]any{"success": true, "zones": zones})
		return
	}
	message, err := service.Test(ctx)
	if err != nil {
		s.json(w, 200, map[string]any{"success": false, "message": err.Error()})
		return
	}
	s.json(w, 200, map[string]any{"success": true, "message": message, "scope": service.Scope()})
}

// dnsCleanupTasks lists recent cleanup jobs for the DNS settings page.
func (s *Server) dnsCleanupTasks(w http.ResponseWriter) {
	jobs, err := s.Store.ListJobs(store.DNSCleanupKind, 50)
	if err != nil {
		s.error(w, 500, "读取清理记录失败")
		return
	}
	items := make([]map[string]any, 0, len(jobs))
	for _, job := range jobs {
		var payload store.DNSCleanupPayload
		_ = json.Unmarshal([]byte(job.Payload), &payload)
		var result struct {
			Outcome string `json:"outcome"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal([]byte(job.Result), &result)
		status, message := "pending", job.LastError
		switch job.Status {
		case "done":
			status, message = "done", result.Message
			if result.Outcome == "skipped" {
				status = "skipped"
			}
		case "failed":
			status = "failed"
		}
		items = append(items, map[string]any{
			"id": job.JobID, "ip": payload.IP, "instanceId": payload.InstanceID, "label": payload.Label,
			"reason": payload.Reason, "reasonText": store.DNSCleanupReasonText(payload.Reason),
			"status": status, "attempts": job.Attempts, "message": message,
			"createdAt": time.Unix(job.CreatedAt, 0).Format("2006-01-02 15:04"),
			"updatedAt": time.Unix(job.UpdatedAt, 0).Format("2006-01-02 15:04"),
		})
	}
	s.json(w, 200, map[string]any{"success": true, "data": items})
}

// retryDNSCleanup puts a finished or failed cleanup back on the queue.
func (s *Server) retryDNSCleanup(w http.ResponseWriter, data map[string]any) {
	if err := s.Store.RequeueJob(stringValue(data["id"])); err != nil {
		s.error(w, 400, err.Error())
		return
	}
	s.json(w, 200, map[string]any{"success": true, "message": "已重新加入队列，几秒内会处理"})
}
