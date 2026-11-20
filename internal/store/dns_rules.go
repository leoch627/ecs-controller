package store

import (
	"encoding/json"

	"github.com/Kori1c/ecs-controller/internal/dns"
)

// DNSBinding is a name an older version queued for deletion.
type DNSBinding struct {
	Rule dns.Rule `json:"rule"`
	Name string   `json:"name"`
}

// SaveDNSSettings commits the DNS settings together.
func (s *Store) SaveDNSSettings(values map[string]string) error {
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
	return tx.Commit()
}

// restoreInstanceDNS undoes an earlier migration that retired the per-machine
// rules into ddns_retired_instance_rules: each rule comes back limited to the
// machines that have a custom name, so those records follow their IP again.
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
	// Only machines the user named explicitly get their record back; the old
	// rule must not hand every other machine an automatic name again.
	accounts, err := s.LoadAccounts(false)
	if err != nil {
		return err
	}
	restored := map[string]bool{}
	for i, rule := range retired {
		restored[rule.ID] = rule.Kind == "instance"
		keys := []string{}
		for _, account := range accounts {
			if rule.Scope.Matches(account) && s.CustomDNSName(account) != "" {
				keys = append(keys, dns.InstanceKey(account))
			}
		}
		if len(keys) == 0 {
			retired[i].Enabled = false
		} else {
			retired[i].Scope = dns.MachineScope{Mode: "instances", InstanceKeys: keys}
		}
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
