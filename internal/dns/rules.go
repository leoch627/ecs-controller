package dns

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/Kori1c/ecs-controller/internal/app"
)

// Rule binds one domain to a selected set of machines. Credentials are shared
// by provider, while zone selection belongs to the rule, never another domain.
type Rule struct {
	ID       string       `json:"id"`
	Enabled  bool         `json:"enabled"`
	Kind     string       `json:"kind"` // instance | pool
	Provider string       `json:"provider"`
	Domain   string       `json:"domain"`
	ZoneID   string       `json:"zone_id"`
	Name     string       `json:"name"`
	Scope    MachineScope `json:"scope"`
}

type MachineScope struct {
	Mode         string   `json:"mode"` // aliyun | aws | all | groups | instances
	GroupKeys    []string `json:"group_keys"`
	InstanceKeys []string `json:"instance_keys"`
}

// InstanceKey survives inventory refreshes and does not expose cloud keys.
func InstanceKey(a app.Account) string {
	hash := sha256.Sum256([]byte(a.AccessKeyID + "|" + a.RegionID + "|" + a.InstanceID))
	return hex.EncodeToString(hash[:])
}

func (s MachineScope) Matches(a app.Account) bool {
	if a.InstanceID == "" {
		return false
	}
	switch s.Mode {
	case "all":
		return true
	case "aliyun":
		return a.SiteType == "" || a.SiteType == "international" || a.SiteType == "china"
	case "aws":
		return a.SiteType == "aws"
	case "groups":
		key := a.GroupKey
		if key == "" {
			key = a.AccessKeyID + "|" + a.RegionID
		}
		return slices.Contains(s.GroupKeys, key)
	case "instances":
		return slices.Contains(s.InstanceKeys, InstanceKey(a))
	}
	return false
}

func (r Rule) FQDN() string {
	if r.Domain == "" || r.Name == "" {
		return ""
	}
	if r.Name == "@" || r.Name == r.Domain {
		return r.Domain
	}
	if strings.HasSuffix(r.Name, "."+r.Domain) {
		return r.Name
	}
	return r.Name + "." + r.Domain
}

// IsCustomName matches a full record name against explicitly assigned labels.
func IsCustomName(name, domain string, labels []string) bool {
	for _, label := range labels {
		if name == (Rule{Domain: domain, Name: label}).FQDN() {
			return true
		}
	}
	return false
}

// EffectiveRules migrates the old round-robin pool to Alibaba Cloud only.
// An explicitly saved empty list disables all automatic DNS bindings.
func (s Settings) EffectiveRules() []Rule {
	if s.RulesConfigured {
		return s.Rules
	}
	rules := []Rule{}
	_, cfg := s.Current()
	if s.Domain != "" {
		rules = append(rules, Rule{ID: "legacy-instance", Enabled: s.DDNSEnabled, Kind: "instance", Provider: s.Provider, Domain: s.Domain, ZoneID: cfg.get("zone_id"), Scope: MachineScope{Mode: "all"}})
		if s.PoolName != "" {
			rules = append(rules, Rule{ID: "legacy-pool", Enabled: true, Kind: "pool", Provider: s.Provider, Domain: s.Domain, ZoneID: cfg.get("zone_id"), Name: s.PoolName, Scope: MachineScope{Mode: "aliyun"}})
		}
	}
	return rules
}

func (s Settings) ForRule(r Rule) Settings {
	result := s
	result.Rules, result.RulesConfigured = nil, false
	result.Provider, result.Domain = r.Provider, r.Domain
	result.DDNSEnabled = r.Enabled && r.Kind == "instance"
	result.PoolName = ""
	if r.Enabled && r.Kind == "pool" {
		result.PoolName = r.Name
	}
	result.Credentials = make(map[string]Config, len(s.Credentials))
	for provider, values := range s.Credentials {
		result.Credentials[provider] = values
	}
	cfg := Config{}
	for key, value := range s.Credentials[r.Provider] {
		cfg[key] = value
	}
	cfg["zone_id"] = r.ZoneID
	result.Credentials[r.Provider] = cfg
	return result
}

func (s Settings) InstanceRule(a app.Account) (Rule, bool) {
	for _, rule := range s.EffectiveRules() {
		if rule.Enabled && rule.Kind == "instance" && rule.Scope.Matches(a) {
			return rule, true
		}
	}
	return Rule{}, false
}

var ruleIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,80}$`)
var labelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func validHostname(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !labelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

// ValidateRules validates disabled drafts too, so enabling a saved rule is safe.
func ValidateRules(rules []Rule) error {
	if len(rules) > 100 {
		return fmt.Errorf("最多配置 100 条解析规则")
	}
	ids, pools := map[string]bool{}, map[string]bool{}
	for i := range rules {
		r := &rules[i]
		r.Domain = NormalizeDomain(r.Domain)
		r.Name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Name)), ".")
		r.ZoneID = strings.TrimSpace(r.ZoneID)
		if !ruleIDPattern.MatchString(r.ID) || ids[r.ID] {
			return fmt.Errorf("解析规则编号为空、无效或重复")
		}
		ids[r.ID] = true
		if r.Kind != "instance" && r.Kind != "pool" {
			return fmt.Errorf("请选择单机解析或负载均衡")
		}
		known := false
		for _, info := range Providers() {
			known = known || info.ID == r.Provider
		}
		if !known {
			return fmt.Errorf("未知 DNS 服务商 %s", r.Provider)
		}
		if !validHostname(r.Domain) || !strings.Contains(r.Domain, ".") {
			return fmt.Errorf("第 %d 条规则的根域名无效", i+1)
		}
		switch r.Scope.Mode {
		case "aliyun", "aws", "all":
		case "groups":
			if len(r.Scope.GroupKeys) == 0 {
				return fmt.Errorf("第 %d 条规则请至少选择一个账号组", i+1)
			}
		case "instances":
			if len(r.Scope.InstanceKeys) == 0 {
				return fmt.Errorf("第 %d 条规则请至少选择一台机器", i+1)
			}
		default:
			return fmt.Errorf("第 %d 条规则请选择机器范围", i+1)
		}
		if r.Kind == "pool" {
			if !validHostname(r.FQDN()) {
				return fmt.Errorf("第 %d 条规则的负载均衡解析名称无效", i+1)
			}
			if r.Enabled && pools[r.FQDN()] {
				return fmt.Errorf("负载均衡域名 %s 不能重复", r.FQDN())
			}
			pools[r.FQDN()] = pools[r.FQDN()] || r.Enabled
		}
	}
	return nil
}
