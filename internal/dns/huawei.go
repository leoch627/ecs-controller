package dns

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// huawei is Huawei Cloud DNS. Requests are signed with the APIG
// "SDK-HMAC-SHA256" scheme, matching Huawei's official SDK byte for byte.
// Public zones are global, so any regional endpoint serves them.
type huawei struct {
	cfg  Config
	http *http.Client
}

var huaweiRegionPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

func (h *huawei) host() string {
	region := strings.ToLower(h.cfg.get("region"))
	if !huaweiRegionPattern.MatchString(region) {
		region = "cn-north-4"
	}
	return "dns." + region + ".myhuaweicloud.com"
}

func (h *huawei) ListZones(ctx context.Context) ([]Zone, error) {
	zones := make([]Zone, 0)
	for offset := 0; ; {
		var response struct {
			Zones []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"zones"`
			Metadata struct {
				TotalCount int `json:"total_count"`
			} `json:"metadata"`
		}
		query := map[string]string{"type": "public", "limit": "500", "offset": strconv.Itoa(offset)}
		if err := h.api(ctx, http.MethodGet, "/v2/zones", query, nil, &response); err != nil {
			return nil, err
		}
		for _, zone := range response.Zones {
			zones = append(zones, Zone{ID: zone.ID, Name: normalizeName(zone.Name)})
		}
		offset += len(response.Zones)
		if len(response.Zones) == 0 || offset >= response.Metadata.TotalCount {
			return zones, nil
		}
	}
}

func (h *huawei) ListA(ctx context.Context, zone Zone, name, ip string) ([]Record, error) {
	query := map[string]string{"zone_type": "public", "type": "A", "zone_id": zone.ID, "limit": "500"}
	if name != "" {
		query["name"] = normalizeName(name) + "."
		query["search_mode"] = "equal"
	}
	if ip != "" {
		query["records"] = ip
	}
	records := make([]Record, 0)
	for offset := 0; ; {
		query["offset"] = strconv.Itoa(offset)
		var response struct {
			RecordSets []struct {
				ID      string   `json:"id"`
				ZoneID  string   `json:"zone_id"`
				Name    string   `json:"name"`
				TTL     int      `json:"ttl"`
				Records []string `json:"records"`
				Default bool     `json:"default"`
			} `json:"recordsets"`
			Metadata struct {
				TotalCount int `json:"total_count"`
			} `json:"metadata"`
		}
		if err := h.api(ctx, http.MethodGet, "/v2.1/recordsets", query, nil, &response); err != nil {
			return nil, err
		}
		for _, set := range response.RecordSets {
			// default record sets are the system NS/SOA; they cannot be changed.
			if set.Default {
				continue
			}
			values := make([]string, 0, len(set.Records))
			for _, value := range set.Records {
				values = append(values, strings.TrimSpace(value))
			}
			records = append(records, Record{ID: set.ID, Name: normalizeName(set.Name), Values: values, TTL: set.TTL, Raw: map[string]any{"zone_id": set.ZoneID}})
		}
		offset += len(response.RecordSets)
		if len(response.RecordSets) == 0 || offset >= response.Metadata.TotalCount {
			return filterRecords(records, name, ip), nil
		}
	}
}

func (h *huawei) CreateA(ctx context.Context, zone Zone, name, ip string) error {
	return h.api(ctx, http.MethodPost, "/v2.1/zones/"+url.PathEscape(zone.ID)+"/recordsets", nil, map[string]any{
		"name": normalizeName(name) + ".", "type": "A", "ttl": 300, "records": []string{ip}, "description": "Managed by ECS 控制台",
	}, nil)
}

func (h *huawei) UpdateA(ctx context.Context, zone Zone, record Record, values []string) error {
	return h.api(ctx, http.MethodPut, "/v2.1/zones/"+url.PathEscape(h.zoneOf(zone, record))+"/recordsets/"+url.PathEscape(record.ID), nil, map[string]any{
		"name": record.Name + ".", "type": "A", "ttl": record.TTL, "records": values,
	}, nil)
}

func (h *huawei) DeleteA(ctx context.Context, zone Zone, record Record) error {
	return h.api(ctx, http.MethodDelete, "/v2.1/zones/"+url.PathEscape(h.zoneOf(zone, record))+"/recordsets/"+url.PathEscape(record.ID), nil, nil, nil)
}

func (h *huawei) zoneOf(zone Zone, record Record) string {
	if id, _ := record.Raw["zone_id"].(string); id != "" {
		return id
	}
	return zone.ID
}

func (h *huawei) api(ctx context.Context, method, path string, query map[string]string, payload any, output any) error {
	var body []byte
	if payload != nil {
		body = marshalJSON(payload)
	}
	queryString := huaweiCanonicalQuery(query)
	sdkDate := time.Now().UTC().Format("20060102T150405Z")
	endpoint := "https://" + h.host() + path
	if queryString != "" {
		endpoint += "?" + queryString
	}
	header := http.Header{
		"Content-Type":  {"application/json"},
		"X-Sdk-Date":    {sdkDate},
		"Authorization": {huaweiAuthorization(h.cfg.get("ak"), h.cfg.get("sk"), method, h.host(), path, queryString, body, sdkDate)},
	}
	status, raw, err := doHTTP(ctx, h.http, "华为云", method, endpoint, header, body)
	if err != nil {
		return err
	}
	if status >= 400 {
		var problem struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			ErrorCode string `json:"error_code"`
			ErrorMsg  string `json:"error_msg"`
		}
		detail := truncate(string(raw), 200)
		if json.Unmarshal(raw, &problem) == nil && (problem.Code+problem.ErrorCode) != "" {
			detail = strings.TrimSpace(problem.Code + problem.ErrorCode + " " + problem.Message + problem.ErrorMsg)
		}
		return providerError("华为云", status, detail)
	}
	if output != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, output); err != nil {
			return providerError("华为云", status, "响应无法解析")
		}
	}
	return nil
}

// huaweiAuthorization builds the APIG SDK-HMAC-SHA256 Authorization header.
func huaweiAuthorization(ak, sk, method, host, path, queryString string, body []byte, sdkDate string) string {
	signedHeaders := "content-type;host;x-sdk-date"
	canonicalHeaders := "content-type:application/json\nhost:" + host + "\nx-sdk-date:" + sdkDate + "\n"
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		segments[i] = rfc3986(segment)
	}
	canonicalURI := strings.Join(segments, "/")
	if !strings.HasSuffix(canonicalURI, "/") {
		canonicalURI += "/"
	}
	bodyHash := sha256.Sum256(body)
	canonicalRequest := strings.Join([]string{strings.ToUpper(method), canonicalURI, queryString, canonicalHeaders, signedHeaders, hex.EncodeToString(bodyHash[:])}, "\n")
	requestHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := "SDK-HMAC-SHA256\n" + sdkDate + "\n" + hex.EncodeToString(requestHash[:])
	mac := hmac.New(sha256.New, []byte(sk))
	mac.Write([]byte(stringToSign))
	return "SDK-HMAC-SHA256 Access=" + ak + ", SignedHeaders=" + signedHeaders + ", Signature=" + hex.EncodeToString(mac.Sum(nil))
}

func huaweiCanonicalQuery(query map[string]string) string {
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, rfc3986(key)+"="+rfc3986(query[key]))
	}
	return strings.Join(pairs, "&")
}

// rfc3986 percent-encodes everything except unreserved characters, matching
// Python's quote(s, safe='~') used by the Huawei and AWS SDKs.
func rfc3986(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}
