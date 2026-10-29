package server

import (
	"context"
	"encoding/json"
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
	return map[string]any{
		"enabled":         settings.DDNSEnabled,
		"cleanup_enabled": settings.CleanupEnabled,
		"provider":        settings.Provider,
		"domain":          settings.Domain,
		"pool_name":       settings.PoolName,
		"credentials":     credentials,
	}
}

// saveDNSConfig stores the DNS section of save_config.
func (s *Server) saveDNSConfig(ddns map[string]any) error {
	_ = s.Store.SetSetting("ddns_enabled", bool01(ddns["enabled"]))
	_ = s.Store.SetSetting("dns_cleanup_enabled", bool01(ddns["cleanup_enabled"]))
	_ = s.Store.SetSetting("ddns_provider", dns.NormalizeID(stringValue(ddns["provider"])))
	_ = s.Store.SetSetting("ddns_domain", dns.NormalizeDomain(stringValue(ddns["domain"])))
	_ = s.Store.SetSetting("ddns_pool_name", dns.NormalizeDomain(stringValue(ddns["pool_name"])))
	credentials, _ := ddns["credentials"].(map[string]any)
	if credentials == nil {
		credentials = map[string]any{}
	}
	// Older clients sent Cloudflare settings as Ddns.cloudflare.
	if legacy, ok := ddns["cloudflare"].(map[string]any); ok && credentials["cloudflare"] == nil {
		credentials["cloudflare"] = legacy
	}
	for _, info := range dns.Providers() {
		values, ok := credentials[info.ID].(map[string]any)
		if !ok {
			continue
		}
		for _, field := range info.Fields {
			key := dns.SettingKey(info.ID, field.Key)
			switch field.Type {
			case "secret":
				if err := s.saveSecret(key, strings.TrimSpace(stringValue(values[field.Key]))); err != nil {
					return err
				}
			case "switch":
				_ = s.Store.SetSetting(key, bool01(values[field.Key]))
			default:
				_ = s.Store.SetSetting(key, strings.TrimSpace(stringValue(values[field.Key])))
			}
		}
	}
	return nil
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

	service, err := dns.NewService(settings, s.DNSClient)
	if err != nil {
		s.json(w, 200, map[string]any{"success": false, "message": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
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
