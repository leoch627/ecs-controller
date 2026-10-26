// Package dns talks to DNS providers for two features: keeping each instance's
// A record pointed at its public IP (DDNS), and removing an IP from DNS once
// the instance that owned it expires, disappears or is released.
//
// Every provider reduces to the same small surface: list zones, list A records
// filtered by name or value, create, change values, delete. Providers that store
// one IP per record (Cloudflare, Aliyun, DNSPod, ...) return single-value
// records; record-set providers (Huawei, Route 53, GoDaddy) may return several.
package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Zone is a hosted domain. Providers addressed by domain name use the name as ID.
type Zone struct {
	ID   string
	Name string
}

// Record is an A record (or record set) with its full lowercase name and no
// trailing dot. Raw keeps provider-specific fields needed to update it later.
type Record struct {
	ID     string
	Name   string
	Values []string
	TTL    int
	Raw    map[string]any
}

// Provider is implemented by every DNS service.
type Provider interface {
	ListZones(ctx context.Context) ([]Zone, error)
	// ListA returns A records, optionally limited to an exact name and/or
	// records containing ip. Empty strings mean "no filter".
	ListA(ctx context.Context, zone Zone, name, ip string) ([]Record, error)
	CreateA(ctx context.Context, zone Zone, name, ip string) error
	// UpdateA replaces the record's values. Single-value providers only ever
	// receive one value.
	UpdateA(ctx context.Context, zone Zone, record Record, values []string) error
	DeleteA(ctx context.Context, zone Zone, record Record) error
}

// recordMatcher lets a provider add its own notion of "already up to date"
// (Cloudflare also compares the proxy flag).
type recordMatcher interface {
	Matches(record Record, ip string) bool
}

// Config holds one provider's form values keyed by Field.Key. Switches are "1"/"0".
type Config map[string]string

func (c Config) get(key string) string { return strings.TrimSpace(c[key]) }

const requestTimeout = 20 * time.Second

func normalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// relativeName turns a full name into the host part of zone; the zone apex
// becomes apex ("@" or "" depending on the provider).
func relativeName(fqdn, zone, apex string) (string, error) {
	fqdn, zone = normalizeName(fqdn), normalizeName(zone)
	if fqdn == zone {
		return apex, nil
	}
	if zone != "" && strings.HasSuffix(fqdn, "."+zone) {
		return strings.TrimSuffix(fqdn, "."+zone), nil
	}
	return "", fmt.Errorf("记录 %s 不属于域名 %s", fqdn, zone)
}

func absoluteName(host, zone string) string {
	host = strings.TrimSpace(host)
	if host == "" || host == "@" {
		return normalizeName(zone)
	}
	return normalizeName(host + "." + zone)
}

// filterRecords applies exact matching on top of provider-side search, which
// is often fuzzy (searching 1.2.3.4 also returns 1.2.3.45).
func filterRecords(records []Record, name, ip string) []Record {
	name = normalizeName(name)
	result := make([]Record, 0, len(records))
	for _, record := range records {
		if name != "" && record.Name != name {
			continue
		}
		if ip != "" && !containsValue(record.Values, ip) {
			continue
		}
		result = append(result, record)
	}
	return result
}

func containsValue(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func withoutValue(values []string, value string) []string {
	result := make([]string, 0, len(values))
	for _, item := range values {
		if item != value {
			result = append(result, item)
		}
	}
	return result
}

// doHTTP sends a request and returns the status and body. Network failures are
// returned as errors; HTTP error statuses are left for the caller to interpret.
func doHTTP(ctx context.Context, client *http.Client, label, method, endpoint string, header http.Header, body []byte) (int, []byte, error) {
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return 0, nil, err
	}
	for key, values := range header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if client == nil {
		client = &http.Client{Timeout: requestTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s 网络请求失败：%w", label, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("%s 读取响应失败：%w", label, err)
	}
	return resp.StatusCode, raw, nil
}

// marshalJSON encodes request bodies without HTML escaping so the signed body
// is exactly what a provider's own SDK would send.
func marshalJSON(value any) []byte {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
	return bytes.TrimRight(buffer.Bytes(), "\n")
}

// Each provider reports bad keys differently (400, 401, 403 and even 404), so
// recognise credential failures by their error codes as well as the status.
var credentialPattern = regexp.MustCompile(`(?i)InvalidAccessKeyId|SignatureDoesNotMatch|InvalidClientTokenId|AuthFailure|APIGW\.030|INVALID_API_KEY|Invalid API Key|Invalid request headers|UNABLE_TO_AUTHENTICATE|Unable to authenticate`)

func providerError(label string, status int, detail string) error {
	detail = strings.TrimSpace(detail)
	hint := ""
	switch {
	case credentialPattern.MatchString(detail) || status == http.StatusUnauthorized:
		hint = "凭据不正确或已失效。"
	case status == http.StatusForbidden:
		hint = "凭据没有操作解析的权限。"
	}
	if detail == "" {
		detail = "没有返回详情"
	}
	where := label + " 返回"
	if status > 0 {
		where += fmt.Sprintf(" HTTP %d", status)
	}
	return fmt.Errorf("%s%s：%s", hint, where, detail)
}

func truncate(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len([]rune(value)) <= limit {
		return value
	}
	return string([]rune(value)[:limit]) + "…"
}
