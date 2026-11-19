package store

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/dns"
)

type DNSBinding struct {
	Rule dns.Rule `json:"rule"`
	Name string   `json:"name"`
}

func (b DNSBinding) Key() string {
	// Switching between automatic zone lookup and an explicit zone ID must
	// not delete the replacement record at the same provider and name.
	return b.Rule.Provider + "|" + b.Name
}

func (s *Store) DNSBindings(settings dns.Settings, accounts []app.Account) []DNSBinding {
	result := []DNSBinding{}
	for _, rule := range settings.EffectiveRules() {
		if rule.Enabled && rule.Kind == "pool" {
			result = append(result, DNSBinding{rule, rule.FQDN()})
		}
	}
	for _, account := range accounts {
		if rule, ok := settings.InstanceRule(account); ok {
			// A user-chosen hostname is not an automatically generated alias.
			if s.CustomDNSName(account) != "" {
				continue
			}
			name := s.DDNSNameForDomain(account, accounts, "", rule.Domain)
			result = append(result, DNSBinding{rule, name})
		}
	}
	return result
}

// SaveDNSSettings commits the configuration and its obsolete-record cleanup
// together, so an interrupted save cannot strand records in the old domain.
func (s *Store) SaveDNSSettings(values map[string]string, retired []DNSBinding) error {
	raw, err := json.Marshal(retired)
	if err != nil {
		return err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range values {
		if _, err := tx.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value); err != nil {
			return err
		}
	}
	if len(retired) > 0 {
		now := time.Now().Unix()
		id := fmt.Sprintf("dns-rules-%d", time.Now().UnixNano())
		if _, err := tx.Exec(`INSERT INTO jobs(job_id,kind,entity_key,status,payload,attempts,available_at,created_at,updated_at) VALUES(?,?,?,'queued',?,0,?,?,?)`, id, "dns_rule_cleanup", id, string(raw), now, now, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// retireInstanceDNS keeps the old bindings long enough to delete their records
// after upgrade. Only the saved pool rules are used for future synchronization.
func (s *Store) retireInstanceDNS() error {
	settings := dns.LoadSettings(s.GetSetting, nil)
	var legacy []dns.Rule
	pools := make([]dns.Rule, 0)
	for _, rule := range settings.EffectiveRules() {
		if rule.Kind == "instance" && (rule.Enabled || settings.RulesConfigured) {
			legacy = append(legacy, rule)
		}
		if rule.Kind == "pool" {
			pools = append(pools, rule)
		}
	}
	if len(legacy) == 0 {
		return nil
	}
	accounts, err := s.LoadAccounts(true)
	if err != nil {
		return err
	}
	var retired []DNSBinding
	for _, binding := range s.DNSBindings(settings, accounts) {
		if binding.Rule.Kind == "instance" {
			retired = append(retired, binding)
		}
	}
	oldRules, err := json.Marshal(legacy)
	if err != nil {
		return err
	}
	values := map[string]string{"ddns_enabled": "0", "ddns_retired_instance_rules": string(oldRules)}
	if settings.RulesConfigured {
		raw, err := json.Marshal(pools)
		if err != nil {
			return err
		}
		values["ddns_rules"] = string(raw)
	}
	return s.SaveDNSSettings(values, retired)
}
