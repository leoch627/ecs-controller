package dns

import (
	"fmt"
	"slices"
	"strings"
)

// Domain is a root domain the panel may write records under, with the DNS
// provider that hosts it. Credentials are shared per provider.
type Domain struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Domain   string `json:"domain"`
	ZoneID   string `json:"zone_id"`
}

// ForDomain scopes the settings to one root domain and its zone.
func (s Settings) ForDomain(d Domain) Settings {
	return s.ForRule(Rule{Provider: d.Provider, Domain: d.Domain, ZoneID: d.ZoneID})
}

// DomainFor picks the configured root domain that name belongs to, preferring
// the longest match so a.b.example.com can live under b.example.com.
func (s Settings) DomainFor(name string) (Domain, bool) {
	name = NormalizeDomain(name)
	best, found := Domain{}, false
	for _, d := range s.Domains {
		if (name == d.Domain || strings.HasSuffix(name, "."+d.Domain)) && len(d.Domain) > len(best.Domain) {
			best, found = d, true
		}
	}
	return best, found
}

// ValidateDomains normalizes and checks the root domain list in place.
func ValidateDomains(domains []Domain) error {
	if len(domains) > 50 {
		return fmt.Errorf("最多配置 50 个根域名")
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for i := range domains {
		d := &domains[i]
		d.Domain = NormalizeDomain(d.Domain)
		d.ZoneID = strings.TrimSpace(d.ZoneID)
		d.Provider = NormalizeID(d.Provider)
		if !ruleIDPattern.MatchString(d.ID) || ids[d.ID] {
			return fmt.Errorf("根域名编号为空、无效或重复")
		}
		ids[d.ID] = true
		if !slices.ContainsFunc(Providers(), func(info Info) bool { return info.ID == d.Provider }) {
			return fmt.Errorf("未知 DNS 服务商 %s", d.Provider)
		}
		if !validHostname(d.Domain) || !strings.Contains(d.Domain, ".") {
			return fmt.Errorf("第 %d 个根域名无效", i+1)
		}
		if names[d.Domain] {
			return fmt.Errorf("根域名 %s 重复", d.Domain)
		}
		names[d.Domain] = true
	}
	return nil
}

// NormalizeHostNames cleans the names typed for one machine. A bare label is
// placed under the root domain when exactly one is configured; anything else
// must end with a configured root domain.
func (s Settings) NormalizeHostNames(raw []string) ([]string, error) {
	result := []string{}
	for _, name := range raw {
		name = NormalizeDomain(name)
		if name == "" {
			continue
		}
		if _, ok := s.DomainFor(name); !ok {
			if strings.Contains(name, ".") || len(s.Domains) != 1 {
				return nil, fmt.Errorf("%s 不在已配置的根域名下", name)
			}
			name += "." + s.Domains[0].Domain
		}
		if !validHostname(name) {
			return nil, fmt.Errorf("解析名称 %s 无效：只能包含小写字母、数字、短横线和点", name)
		}
		if !slices.Contains(result, name) {
			result = append(result, name)
		}
	}
	slices.Sort(result)
	return result, nil
}
