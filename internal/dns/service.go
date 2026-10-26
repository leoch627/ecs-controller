package dns

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Settings is the saved DNS configuration, with secrets already decrypted.
type Settings struct {
	Provider       string
	Domain         string
	DDNSEnabled    bool
	CleanupEnabled bool
	// Credentials holds every provider's form values so switching providers
	// in the UI never loses the other one's keys.
	Credentials map[string]Config
}

// LoadSettings reads the DNS settings through the store's accessors.
func LoadSettings(get func(key, fallback string) string, open func(string) (string, error)) Settings {
	settings := Settings{
		Provider:       NormalizeID(get("ddns_provider", "cloudflare")),
		Domain:         NormalizeDomain(get("ddns_domain", "")),
		DDNSEnabled:    get("ddns_enabled", "0") == "1",
		CleanupEnabled: get("dns_cleanup_enabled", "0") == "1",
		Credentials:    map[string]Config{},
	}
	for _, info := range registry {
		cfg := Config{}
		for _, field := range info.Fields {
			value := get(SettingKey(info.ID, field.Key), field.Default)
			if field.Type == "secret" && open != nil {
				if plain, err := open(value); err == nil {
					value = plain
				}
			}
			cfg[field.Key] = value
		}
		settings.Credentials[info.ID] = cfg
	}
	return settings
}

// Current returns the selected provider's metadata and form values.
func (s Settings) Current() (Info, Config) {
	info := Lookup(s.Provider)
	cfg := s.Credentials[info.ID]
	if cfg == nil {
		cfg = Config{}
	}
	return info, cfg
}

// Configured reports whether the selected provider has all required values.
func (s Settings) Configured() bool {
	info, cfg := s.Current()
	return info.Configured(cfg)
}

// DDNSActive: automatic A records need the switch, credentials and a root domain.
func (s Settings) DDNSActive() bool {
	return s.DDNSEnabled && s.Domain != "" && s.Configured()
}

// CleanupActive: removing dead IPs needs the switch and credentials. Without a
// root domain every zone in the provider account is in scope.
func (s Settings) CleanupActive() bool {
	return s.CleanupEnabled && s.Configured()
}

// Service runs DDNS and cleanup operations against the selected provider.
type Service struct {
	settings Settings
	info     Info
	cfg      Config
	provider Provider
}

// NewService builds a service for the selected provider.
func NewService(settings Settings, client *http.Client) (*Service, error) {
	info, cfg := settings.Current()
	provider, err := New(info.ID, cfg, client)
	if err != nil {
		return nil, err
	}
	return &Service{settings: settings, info: info, cfg: cfg, provider: provider}, nil
}

// NewServiceWithProvider is used by tests to inject a fake provider.
func NewServiceWithProvider(settings Settings, provider Provider) *Service {
	info, cfg := settings.Current()
	return &Service{settings: settings, info: info, cfg: cfg, provider: provider}
}

// Label is the provider's display name.
func (s *Service) Label() string { return s.info.Label }

// SyncA points name at ip. It returns "created", "updated" or "unchanged".
func (s *Service) SyncA(ctx context.Context, name, ip string) (string, error) {
	name = normalizeName(name)
	if !isPublicIPv4(ip) {
		return "", fmt.Errorf("公网 IP 为空或不是公网 IPv4")
	}
	zone, err := s.zoneFor(ctx, name)
	if err != nil {
		return "", err
	}
	records, err := s.provider.ListA(ctx, zone, name, "")
	if err != nil {
		return "", err
	}
	for _, record := range records {
		if s.matches(record, ip) {
			return "unchanged", nil
		}
	}
	if len(records) > 0 {
		return "updated", s.provider.UpdateA(ctx, zone, records[0], []string{ip})
	}
	return "created", s.provider.CreateA(ctx, zone, name, ip)
}

// DeleteByName removes every A record with exactly this name.
func (s *Service) DeleteByName(ctx context.Context, name string) (bool, error) {
	name = normalizeName(name)
	if name == "" {
		return false, fmt.Errorf("DDNS 记录名为空")
	}
	zone, err := s.zoneFor(ctx, name)
	if err != nil {
		return false, err
	}
	records, err := s.provider.ListA(ctx, zone, name, "")
	if err != nil {
		return false, err
	}
	for _, record := range records {
		if err := s.provider.DeleteA(ctx, zone, record); err != nil {
			return false, err
		}
	}
	return len(records) > 0, nil
}

// Change is one record touched by RemoveIP.
type Change struct {
	Record    string `json:"record"`
	Action    string `json:"action"` // deleted | updated
	Remaining int    `json:"remaining,omitempty"`
}

// RemoveIP deletes records that only point at ip and removes ip from records
// that also point elsewhere.
func (s *Service) RemoveIP(ctx context.Context, ip string) ([]Change, error) {
	if net.ParseIP(strings.TrimSpace(ip)).To4() == nil {
		return nil, fmt.Errorf("IP 地址无效：%s", ip)
	}
	zones, err := s.scopeZones(ctx)
	if err != nil {
		return nil, err
	}
	changes := make([]Change, 0)
	for _, zone := range zones {
		records, err := s.provider.ListA(ctx, zone, "", ip)
		if err != nil {
			return changes, err
		}
		for _, record := range records {
			remaining := withoutValue(record.Values, ip)
			if len(remaining) == 0 {
				if err := s.provider.DeleteA(ctx, zone, record); err != nil {
					return changes, err
				}
				changes = append(changes, Change{Record: record.Name, Action: "deleted"})
				continue
			}
			if err := s.provider.UpdateA(ctx, zone, record, remaining); err != nil {
				return changes, err
			}
			changes = append(changes, Change{Record: record.Name, Action: "updated", Remaining: len(remaining)})
		}
	}
	return changes, nil
}

// SummarizeChanges renders RemoveIP's result for logs and the UI.
func SummarizeChanges(changes []Change) string {
	if len(changes) == 0 {
		return "解析中没有指向该 IP 的 A 记录"
	}
	parts := make([]string, 0, len(changes))
	for _, change := range changes {
		if change.Action == "deleted" {
			parts = append(parts, "已删除 "+change.Record)
		} else {
			parts = append(parts, fmt.Sprintf("已从 %s 移除（剩余 %d 个 IP）", change.Record, change.Remaining))
		}
	}
	return strings.Join(parts, "；")
}

// Test checks the credentials and reports what is in scope.
func (s *Service) Test(ctx context.Context) (string, error) {
	zones, err := s.scopeZones(ctx)
	if err != nil {
		return "", err
	}
	if s.configuredZone() != nil || s.settings.Domain != "" {
		zone := zones[0]
		records, err := s.provider.ListA(ctx, zone, "", "")
		if err != nil {
			return "", err
		}
		name := zone.Name
		if name == "" {
			name = zone.ID
		}
		return fmt.Sprintf("%s 鉴权通过，已找到域名 %s，当前有 %d 条 A 记录。", s.info.Label, name, len(records)), nil
	}
	names := make([]string, 0, len(zones))
	for _, zone := range zones {
		names = append(names, zone.Name)
	}
	listed := ""
	if len(names) > 0 {
		shown := names
		if len(shown) > 5 {
			shown = shown[:5]
		}
		listed = "：" + strings.Join(shown, "、")
		if len(names) > 5 {
			listed += " 等"
		}
	}
	return fmt.Sprintf("%s 鉴权通过，账号下共有 %d 个域名%s。未填写根域名时，失效清理会处理全部域名。", s.info.Label, len(zones), listed), nil
}

// Scope describes which records cleanup may touch.
func (s *Service) Scope() string { return CleanupScope(s.settings) }

// CleanupScope describes which records cleanup may touch.
func CleanupScope(settings Settings) string {
	info, cfg := settings.Current()
	if cfg.get("zone_id") != "" {
		return "指定 Zone 下的全部 A 记录"
	}
	if settings.Domain != "" {
		return settings.Domain + " 下的全部 A 记录"
	}
	return info.Label + " 账号下全部域名的 A 记录"
}

func (s *Service) matches(record Record, ip string) bool {
	if matcher, ok := s.provider.(recordMatcher); ok {
		return matcher.Matches(record, ip)
	}
	return len(record.Values) == 1 && record.Values[0] == ip
}

func (s *Service) configuredZone() *Zone {
	if id := s.cfg.get("zone_id"); id != "" {
		return &Zone{ID: id, Name: s.settings.Domain}
	}
	return nil
}

// zoneFor finds the zone that hosts name: the configured zone, else the zone
// of the root domain, walking up from name when no root domain is set.
func (s *Service) zoneFor(ctx context.Context, name string) (Zone, error) {
	if zone := s.configuredZone(); zone != nil {
		return *zone, nil
	}
	lookup := s.settings.Domain
	if lookup == "" {
		lookup = name
	}
	zones, err := s.provider.ListZones(ctx)
	if err != nil {
		return Zone{}, err
	}
	if zone, ok := findZone(zones, lookup); ok {
		return zone, nil
	}
	return Zone{}, fmt.Errorf("%s 账号下没有找到域名 %s，请确认域名托管在这家服务商，且凭据有解析权限", s.info.Label, lookup)
}

func (s *Service) scopeZones(ctx context.Context) ([]Zone, error) {
	if zone := s.configuredZone(); zone != nil {
		return []Zone{*zone}, nil
	}
	if s.settings.Domain != "" {
		zone, err := s.zoneFor(ctx, s.settings.Domain)
		if err != nil {
			return nil, err
		}
		return []Zone{zone}, nil
	}
	return s.provider.ListZones(ctx)
}

// findZone picks the zone hosting domain, walking up from subdomains.
func findZone(zones []Zone, domain string) (Zone, bool) {
	byName := map[string]Zone{}
	for _, zone := range zones {
		zone.Name = normalizeName(zone.Name)
		byName[zone.Name] = zone
	}
	labels := strings.Split(normalizeName(domain), ".")
	for len(labels) >= 2 {
		if zone, ok := byName[strings.Join(labels, ".")]; ok {
			return zone, true
		}
		labels = labels[1:]
	}
	return Zone{}, false
}

// NormalizeDomain strips a scheme, path and trailing dot from a root domain.
func NormalizeDomain(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(strings.TrimPrefix(value, "https://"), "http://")
	if index := strings.IndexByte(value, '/'); index >= 0 {
		value = value[:index]
	}
	return strings.Trim(value, ".")
}

func isPublicIPv4(value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	return ip != nil && ip.To4() != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}
