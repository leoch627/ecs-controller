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
			name := s.DDNSNameForDomain(account, accounts, s.CustomDNSName(account), rule.Domain)
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

// restoreInstanceDNS undoes an earlier migration that retired the per-machine
// rules into ddns_retired_instance_rules: those rules go back into the active
// list so each machine's own A record follows its IP again.
func (s *Store) restoreInstanceDNS() error {
	raw := s.GetSetting("ddns_retired_instance_rules", "")
	if raw == "" {
		return nil
	}
	var retired []dns.Rule
	if err := json.Unmarshal([]byte(raw), &retired); err != nil || len(retired) == 0 {
		_, err = s.DB.Exec(`DELETE FROM settings WHERE key='ddns_retired_instance_rules'`)
		return err
	}
	restored := map[string]bool{}
	for _, rule := range retired {
		restored[rule.ID] = rule.Kind == "instance"
	}
	// The retired copy wins over a same-ID rule, which that migration disabled.
	rules := []dns.Rule{}
	for _, rule := range dns.LoadSettings(s.GetSetting, nil).EffectiveRules() {
		if !restored[rule.ID] {
			rules = append(rules, rule)
		}
	}
	for _, rule := range retired {
		if rule.Kind == "instance" {
			rules = append(rules, rule)
		}
	}
	encoded, err := json.Marshal(rules)
	if err != nil {
		return err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO settings(key,value) VALUES('ddns_rules',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, string(encoded)); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM settings WHERE key='ddns_retired_instance_rules'`); err != nil {
		return err
	}
	return tx.Commit()
}
