package dns

import (
	"fmt"
	"net/http"
	"strings"
)

// Field describes one input in the provider's settings form.
type Field struct {
	Key         string   `json:"key"`
	Label       string   `json:"label"`
	Type        string   `json:"type"` // text | secret | select | switch
	Required    bool     `json:"required,omitempty"`
	Placeholder string   `json:"placeholder,omitempty"`
	Hint        string   `json:"hint,omitempty"`
	Default     string   `json:"default,omitempty"`
	Options     []Option `json:"options,omitempty"`
}

type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// Info is the provider's metadata, also sent to the UI to render its form.
type Info struct {
	ID     string  `json:"id"`
	Label  string  `json:"label"`
	Market string  `json:"market"` // cn | global
	Hint   string  `json:"hint"`
	TTL    int     `json:"ttl"`
	Fields []Field `json:"fields"`
	// prefix keeps the settings keys of providers that existed before this
	// package (Cloudflare used ddns_cf_*), so old configurations keep working.
	prefix string
	create func(Config, *http.Client) Provider
}

var registry = []Info{
	{
		ID: "aliyun", Label: "阿里云", Market: "cn", TTL: 600,
		Hint: "建议单独建一个 RAM 用户并授予 AliyunDNSFullAccess；也可以用 ECS 账号的 AK，前提是它有云解析权限。免费版解析的 TTL 最低 600 秒。",
		Fields: []Field{
			{Key: "access_key_id", Label: "AccessKey ID", Type: "text", Required: true, Placeholder: "LTAI…"},
			{Key: "access_key_secret", Label: "AccessKey Secret", Type: "secret", Required: true},
			{Key: "endpoint", Label: "接入点", Type: "select", Default: "alidns.aliyuncs.com", Options: []Option{
				{Value: "alidns.aliyuncs.com", Label: "中国站 · alidns.aliyuncs.com"},
				{Value: "alidns.ap-southeast-1.aliyuncs.com", Label: "国际站 · alidns.ap-southeast-1.aliyuncs.com"},
			}},
		},
		create: func(c Config, h *http.Client) Provider { return newAliyun(c, h) },
	},
	{
		ID: "dnspod", Label: "腾讯云 DNSPod", Market: "cn", TTL: 600,
		Hint: "使用腾讯云「访问管理 → API 密钥」的 SecretId / SecretKey（不是旧版 DNSPod Token），子用户需要 QcloudDNSPodFullAccess。免费套餐 TTL 最低 600 秒。",
		Fields: []Field{
			{Key: "secret_id", Label: "SecretId", Type: "text", Required: true, Placeholder: "AKID…"},
			{Key: "secret_key", Label: "SecretKey", Type: "secret", Required: true},
			{Key: "endpoint", Label: "接入点", Type: "select", Default: "dnspod.tencentcloudapi.com", Options: []Option{
				{Value: "dnspod.tencentcloudapi.com", Label: "腾讯云中国站"},
				{Value: "dnspod.intl.tencentcloudapi.com", Label: "腾讯云国际站"},
			}},
		},
		create: func(c Config, h *http.Client) Provider { return &dnspod{cfg: c, http: h} },
	},
	{
		ID: "huawei", Label: "华为云", Market: "cn", TTL: 300, prefix: "hw",
		Hint: "在华为云 IAM 为该 AK 授予 DNS FullAccess，或自定义策略包含 dns:zone:list、dns:recordset:list、dns:recordset:create、dns:recordset:update、dns:recordset:delete。",
		Fields: []Field{
			{Key: "ak", Label: "Access Key ID", Type: "text", Required: true, Placeholder: "华为云 AK"},
			{Key: "sk", Label: "Secret Access Key", Type: "secret", Required: true, Placeholder: "华为云 SK"},
			{Key: "region", Label: "接入点", Type: "select", Default: "cn-north-4", Hint: "公网解析是全局服务，中国站选北京四，国际站选香港即可。", Options: []Option{
				{Value: "cn-north-4", Label: "中国站 · 华北-北京四"},
				{Value: "cn-east-3", Label: "中国站 · 华东-上海一"},
				{Value: "cn-south-1", Label: "中国站 · 华南-广州"},
				{Value: "ap-southeast-1", Label: "国际站 · 中国-香港"},
				{Value: "ap-southeast-3", Label: "国际站 · 亚太-新加坡"},
			}},
			{Key: "zone_id", Label: "Zone ID", Type: "text", Placeholder: "留空自动查询"},
		},
		create: func(c Config, h *http.Client) Provider { return &huawei{cfg: c, http: h} },
	},
	{
		ID: "cloudflare", Label: "Cloudflare", Market: "global", TTL: 1, prefix: "cf",
		Hint: "在 Cloudflare「My Profile → API Tokens」创建 Token，权限选 Zone · DNS · Edit 和 Zone · Zone · Read，资源选要管理的域名。",
		Fields: []Field{
			{Key: "token", Label: "API Token", Type: "secret", Required: true, Placeholder: "需要 Zone · DNS · Edit 权限"},
			{Key: "zone_id", Label: "Zone ID", Type: "text", Placeholder: "留空自动查询"},
			{Key: "proxied", Label: "自动解析的记录经过 Cloudflare 代理（橙色云朵）", Type: "switch", Hint: "只代理 HTTP/HTTPS，开启后 SSH 等端口无法通过域名直连。"},
		},
		create: func(c Config, h *http.Client) Provider { return &cloudflare{cfg: c, http: h} },
	},
	{
		ID: "route53", Label: "AWS Route 53", Market: "global", TTL: 300,
		Hint: "IAM 策略需要 route53:ListHostedZones、route53:ListResourceRecordSets、route53:ChangeResourceRecordSets。带路由策略或别名的记录会被跳过。",
		Fields: []Field{
			{Key: "access_key_id", Label: "Access Key ID", Type: "text", Required: true, Placeholder: "AKIA…"},
			{Key: "secret_access_key", Label: "Secret Access Key", Type: "secret", Required: true},
			{Key: "zone_id", Label: "Hosted Zone ID", Type: "text", Placeholder: "留空自动查询"},
		},
		create: func(c Config, h *http.Client) Provider { return &route53{cfg: c, http: h} },
	},
	{
		ID: "namesilo", Label: "NameSilo", Market: "global", TTL: 3600,
		Hint: "在 NameSilo「Account → API Manager」生成 API Key，不要勾选只读；设置了 IP 白名单的话要加入服务器 IP。NameSilo 的 TTL 最低 3600 秒，解析生效会慢一些。",
		Fields: []Field{
			{Key: "api_key", Label: "API Key", Type: "secret", Required: true, Placeholder: "在 Account → API Manager 生成"},
		},
		create: func(c Config, h *http.Client) Provider { return &namesilo{cfg: c, http: h} },
	},
	{
		ID: "porkbun", Label: "Porkbun", Market: "global", TTL: 600,
		Hint: "在 porkbun.com/account/api 创建密钥，并在域名设置里打开「API Access」，否则会提示无权限。",
		Fields: []Field{
			{Key: "api_key", Label: "API Key", Type: "secret", Required: true, Placeholder: "pk1_…"},
			{Key: "secret_api_key", Label: "Secret API Key", Type: "secret", Required: true, Placeholder: "sk1_…"},
		},
		create: func(c Config, h *http.Client) Provider { return &porkbun{cfg: c, http: h} },
	},
	{
		ID: "godaddy", Label: "GoDaddy", Market: "global", TTL: 600,
		Hint: "在 developer.godaddy.com/keys 创建 Production 环境的 Key。注意：GoDaddy 只对拥有 10 个以上域名或订阅了 Discount Domain Club 的账号开放 API，否则会返回 403。",
		Fields: []Field{
			{Key: "api_key", Label: "API Key", Type: "text", Required: true},
			{Key: "api_secret", Label: "API Secret", Type: "secret", Required: true},
		},
		create: func(c Config, h *http.Client) Provider { return &godaddy{cfg: c, http: h} },
	},
	{
		ID: "digitalocean", Label: "DigitalOcean", Market: "global", TTL: 300,
		Hint: "在 DigitalOcean「API → Tokens」创建 Token，自定义权限至少勾选 domain 的 read、create、update、delete。",
		Fields: []Field{
			{Key: "token", Label: "Personal Access Token", Type: "secret", Required: true, Placeholder: "dop_v1_…"},
		},
		create: func(c Config, h *http.Client) Provider { return &digitalOcean{cfg: c, http: h} },
	},
}

// Providers lists every supported provider in display order.
func Providers() []Info {
	result := make([]Info, len(registry))
	copy(result, registry)
	return result
}

// Lookup returns a provider's metadata; unknown IDs fall back to Cloudflare,
// which was the only provider before this package existed.
func Lookup(id string) Info {
	var fallback Info
	for _, info := range registry {
		if info.ID == id {
			return info
		}
		if info.ID == "cloudflare" {
			fallback = info
		}
	}
	return fallback
}

// NormalizeID maps unknown IDs to the default provider.
func NormalizeID(id string) string { return Lookup(strings.TrimSpace(id)).ID }

// SettingKey is the settings-table key of one provider field, e.g. ddns_hw_sk.
func SettingKey(id, field string) string {
	info := Lookup(id)
	prefix := info.prefix
	if prefix == "" {
		prefix = info.ID
	}
	return "ddns_" + prefix + "_" + field
}

// SecretSettingKeys lists the settings that must be stored encrypted.
func SecretSettingKeys() []string {
	keys := make([]string, 0)
	for _, info := range registry {
		for _, field := range info.Fields {
			if field.Type == "secret" {
				keys = append(keys, SettingKey(info.ID, field.Key))
			}
		}
	}
	return keys
}

// Configured reports whether every required field has a value.
func (info Info) Configured(cfg Config) bool {
	for _, field := range info.Fields {
		if field.Required && cfg.get(field.Key) == "" {
			return false
		}
	}
	return true
}

// New builds a provider. client may be nil to use a default HTTP client.
func New(id string, cfg Config, client *http.Client) (Provider, error) {
	info := Lookup(id)
	if !info.Configured(cfg) {
		return nil, fmt.Errorf("请先填写 %s 的凭据", info.Label)
	}
	if client == nil {
		client = &http.Client{Timeout: requestTimeout}
	}
	return info.create(cfg, client), nil
}
