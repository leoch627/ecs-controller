package store

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/dns"
)

// Each machine lists its own DNS names. A name held by one running machine
// resolves to that machine; a name held by several resolves to all of them
// (DNS round robin). Machines start with no names.
const (
	settingDNSDomains = "ddns_domains"
	settingDNSHosts   = "ddns_hosts"
	settingDNSManaged = "ddns_managed"
)

// DNSNameState is what the reconciler remembers about a name it writes.
// Presence in the managed map means the panel owns the name's A records.
type DNSNameState struct {
	State    string `json:"state,omitempty"`
	SyncedAt int64  `json:"synced_at,omitempty"`
	RetryAt  int64  `json:"retry_at,omitempty"`
	Attempt  string `json:"attempt,omitempty"`
}

// DNSHosts maps dns.InstanceKey to the names that machine holds.
func (s *Store) DNSHosts() map[string][]string {
	hosts := map[string][]string{}
	_ = json.Unmarshal([]byte(s.GetSetting(settingDNSHosts, "{}")), &hosts)
	return hosts
}

// DNSHostNames are the names the machine holds.
func (s *Store) DNSHostNames(account app.Account) []string {
	return s.DNSHosts()[dns.InstanceKey(account)]
}

// SetDNSHostNames replaces the machine's names; an empty list removes them.
// Callers hold DNSConfigMu.
func (s *Store) SetDNSHostNames(account app.Account, names []string) error {
	hosts := s.DNSHosts()
	key := dns.InstanceKey(account)
	if len(names) == 0 {
		delete(hosts, key)
	} else {
		hosts[key] = slices.Clone(names)
	}
	raw, err := json.Marshal(hosts)
	if err != nil {
		return err
	}
	return s.SetSetting(settingDNSHosts, string(raw))
}

func (s *Store) DNSManaged() map[string]DNSNameState {
	managed := map[string]DNSNameState{}
	_ = json.Unmarshal([]byte(s.GetSetting(settingDNSManaged, "{}")), &managed)
	return managed
}

func (s *Store) SetDNSManaged(managed map[string]DNSNameState) error {
	raw, err := json.Marshal(managed)
	if err != nil {
		return err
	}
	return s.SetSetting(settingDNSManaged, string(raw))
}

// migrateDNSHosts turns the older rule-based configuration into root domains
// and per-machine names, once. Each machine keeps exactly the names the old
// rules gave it, so nothing that resolved before stops resolving.
func (s *Store) migrateDNSHosts() error {
	if s.GetSetting(settingDNSDomains, "") != "" {
		return nil
	}
	settings := dns.LoadSettings(s.GetSetting, nil)
	rules := settings.EffectiveRules()
	domains := []dns.Domain{}
	seen := map[string]bool{}
	addDomain := func(provider, domain, zoneID string) {
		domain = dns.NormalizeDomain(domain)
		if domain == "" || seen[domain] {
			return
		}
		seen[domain] = true
		domains = append(domains, dns.Domain{ID: fmt.Sprintf("domain-%d", len(domains)+1), Provider: dns.NormalizeID(provider), Domain: domain, ZoneID: zoneID})
	}
	for _, rule := range rules {
		addDomain(rule.Provider, rule.Domain, rule.ZoneID)
	}
	if len(rules) == 0 && settings.Domain != "" {
		_, cfg := settings.Current()
		addDomain(settings.Provider, settings.Domain, cfg["zone_id"])
	}
	accounts, err := s.LoadAccounts(false)
	if err != nil {
		return err
	}
	hosts := map[string][]string{}
	managed := map[string]DNSNameState{}
	add := func(account app.Account, name string) {
		key := dns.InstanceKey(account)
		if name == "" || slices.Contains(hosts[key], name) {
			return
		}
		hosts[key] = append(hosts[key], name)
		slices.Sort(hosts[key])
		managed[name] = DNSNameState{}
	}
	for _, account := range accounts {
		if account.InstanceID == "" {
			continue
		}
		for _, rule := range rules {
			if rule.Enabled && rule.Kind == "pool" && rule.Scope.Matches(account) {
				add(account, rule.FQDN())
			}
		}
		if rule, ok := settings.InstanceRule(account); ok {
			add(account, s.InstanceDNSName(account, accounts, rule.Domain))
		}
	}
	values := map[string]any{settingDNSDomains: domains, settingDNSHosts: hosts, settingDNSManaged: managed}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range values {
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, string(raw)); err != nil {
			return err
		}
	}
	return tx.Commit()
}
