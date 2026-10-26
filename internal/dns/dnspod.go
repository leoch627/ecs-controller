package dns

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// dnspod is Tencent Cloud DNSPod (API 3.0, version 2021-03-23) signed with
// TC3-HMAC-SHA256, matching Tencent's official SDK.
type dnspod struct {
	cfg  Config
	http *http.Client
}

const dnspodVersion = "2021-03-23"

func (d *dnspod) host() string {
	if d.cfg.get("endpoint") == "dnspod.intl.tencentcloudapi.com" {
		return "dnspod.intl.tencentcloudapi.com"
	}
	return "dnspod.tencentcloudapi.com"
}

func (d *dnspod) ListZones(ctx context.Context) ([]Zone, error) {
	zones := make([]Zone, 0)
	for offset := 0; ; {
		var response struct {
			DomainList []struct {
				Name string `json:"Name"`
			} `json:"DomainList"`
			DomainCountInfo struct {
				AllTotal    int `json:"AllTotal"`
				DomainTotal int `json:"DomainTotal"`
			} `json:"DomainCountInfo"`
		}
		if err := d.call(ctx, "DescribeDomainList", map[string]any{"Offset": offset, "Limit": 3000}, &response, ""); err != nil {
			return nil, err
		}
		for _, item := range response.DomainList {
			zones = append(zones, Zone{ID: item.Name, Name: normalizeName(item.Name)})
		}
		offset += len(response.DomainList)
		total := response.DomainCountInfo.AllTotal
		if total == 0 {
			total = response.DomainCountInfo.DomainTotal
		}
		if len(response.DomainList) == 0 || offset >= total {
			return zones, nil
		}
	}
}

type dnspodRecord struct {
	RecordID uint64 `json:"RecordId"`
	Name     string `json:"Name"`
	Type     string `json:"Type"`
	Value    string `json:"Value"`
	TTL      int    `json:"TTL"`
	Line     string `json:"Line"`
	LineID   string `json:"LineId"`
}

func (d *dnspod) ListA(ctx context.Context, zone Zone, name, ip string) ([]Record, error) {
	params := map[string]any{"Domain": zone.Name, "RecordType": "A", "Limit": 3000, "ErrorOnEmpty": "no"}
	if name != "" {
		host, err := relativeName(name, zone.Name, "@")
		if err != nil {
			return nil, err
		}
		params["Subdomain"] = host
	}
	if ip != "" {
		params["Keyword"] = ip
	}
	records := make([]Record, 0)
	for offset := 0; ; {
		params["Offset"] = offset
		var response struct {
			RecordList      []dnspodRecord `json:"RecordList"`
			RecordCountInfo struct {
				TotalCount int `json:"TotalCount"`
			} `json:"RecordCountInfo"`
		}
		if err := d.call(ctx, "DescribeRecordList", params, &response, "ResourceNotFound.NoDataOfRecord"); err != nil {
			return nil, err
		}
		for _, item := range response.RecordList {
			if item.Type != "A" {
				continue
			}
			records = append(records, Record{
				ID: strconv.FormatUint(item.RecordID, 10), Name: absoluteName(item.Name, zone.Name),
				Values: []string{strings.TrimSpace(item.Value)}, TTL: item.TTL,
				Raw: map[string]any{"host": item.Name, "line": item.Line, "line_id": item.LineID},
			})
		}
		offset += len(response.RecordList)
		if len(response.RecordList) == 0 || offset >= response.RecordCountInfo.TotalCount {
			return filterRecords(records, name, ip), nil
		}
	}
}

func (d *dnspod) CreateA(ctx context.Context, zone Zone, name, ip string) error {
	host, err := relativeName(name, zone.Name, "@")
	if err != nil {
		return err
	}
	return d.call(ctx, "CreateRecord", map[string]any{"Domain": zone.Name, "SubDomain": host, "RecordType": "A", "RecordLine": "默认", "Value": ip, "TTL": 600}, nil, "")
}

func (d *dnspod) UpdateA(ctx context.Context, zone Zone, record Record, values []string) error {
	id, _ := strconv.ParseUint(record.ID, 10, 64)
	line, _ := record.Raw["line"].(string)
	if line == "" {
		line = "默认"
	}
	params := map[string]any{"Domain": zone.Name, "RecordId": id, "SubDomain": record.Raw["host"], "RecordType": "A", "RecordLine": line, "Value": values[0], "TTL": record.TTL}
	if lineID, _ := record.Raw["line_id"].(string); lineID != "" {
		params["RecordLineId"] = lineID
	}
	return d.call(ctx, "ModifyRecord", params, nil, "")
}

func (d *dnspod) DeleteA(ctx context.Context, zone Zone, record Record) error {
	id, _ := strconv.ParseUint(record.ID, 10, 64)
	return d.call(ctx, "DeleteRecord", map[string]any{"Domain": zone.Name, "RecordId": id}, nil, "")
}

// call sends one action. emptyCode is an error code that means "no data"
// rather than a failure.
func (d *dnspod) call(ctx context.Context, action string, params map[string]any, output any, emptyCode string) error {
	payload := marshalJSON(params)
	timestamp := time.Now().Unix()
	host := d.host()
	header := http.Header{
		"Authorization":  {dnspodAuthorization(d.cfg.get("secret_id"), d.cfg.get("secret_key"), host, payload, timestamp)},
		"Content-Type":   {"application/json; charset=utf-8"},
		"X-Tc-Action":    {action},
		"X-Tc-Timestamp": {strconv.FormatInt(timestamp, 10)},
		"X-Tc-Version":   {dnspodVersion},
	}
	status, raw, err := doHTTP(ctx, d.http, "腾讯云 DNSPod", http.MethodPost, "https://"+host+"/", header, payload)
	if err != nil {
		return err
	}
	var envelope struct {
		Response json.RawMessage `json:"Response"`
	}
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Response) == 0 {
		return providerError("腾讯云 DNSPod", status, truncate(string(raw), 200))
	}
	var problem struct {
		Error *struct{ Code, Message string } `json:"Error"`
	}
	_ = json.Unmarshal(envelope.Response, &problem)
	if problem.Error != nil {
		if emptyCode != "" && problem.Error.Code == emptyCode {
			return nil
		}
		code := problem.Error.Code
		if strings.HasPrefix(code, "AuthFailure") {
			status = http.StatusUnauthorized
		} else if strings.HasPrefix(code, "UnauthorizedOperation") {
			status = http.StatusForbidden
		} else if status == http.StatusOK {
			status = 0
		}
		return providerError("腾讯云 DNSPod", status, code+" "+problem.Error.Message)
	}
	if output != nil {
		return json.Unmarshal(envelope.Response, output)
	}
	return nil
}

// dnspodAuthorization builds the TC3-HMAC-SHA256 Authorization header.
func dnspodAuthorization(secretID, secretKey, host string, payload []byte, timestamp int64) string {
	date := time.Unix(timestamp, 0).UTC().Format("2006-01-02")
	payloadHash := sha256.Sum256(payload)
	canonicalRequest := "POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:" + host + "\n\ncontent-type;host\n" + hex.EncodeToString(payloadHash[:])
	scope := date + "/dnspod/tc3_request"
	requestHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := fmt.Sprintf("TC3-HMAC-SHA256\n%d\n%s\n%s", timestamp, scope, hex.EncodeToString(requestHash[:]))
	secretDate := hmacSHA256([]byte("TC3"+secretKey), date)
	secretService := hmacSHA256(secretDate, "dnspod")
	secretSigning := hmacSHA256(secretService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(secretSigning, stringToSign))
	return "TC3-HMAC-SHA256 Credential=" + secretID + "/" + scope + ", SignedHeaders=content-type;host, Signature=" + signature
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}
