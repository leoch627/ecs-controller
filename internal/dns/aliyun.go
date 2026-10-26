package dns

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Kori1c/ecs-controller/internal/cloud"
)

// aliyun is Alibaba Cloud DNS (Alidns 2015-01-09). It reuses the controller's
// RPC signer, so it signs requests exactly like the ECS calls do.
type aliyun struct {
	rpc *cloud.RPCClient
}

func newAliyun(cfg Config, client *http.Client) *aliyun {
	host := cfg.get("endpoint")
	if host != "alidns.ap-southeast-1.aliyuncs.com" {
		host = "alidns.aliyuncs.com"
	}
	return &aliyun{rpc: &cloud.RPCClient{
		HTTPClient: client,
		Endpoint:   "https://" + host + "/",
		Version:    "2015-01-09",
		Product:    "Alidns",
		AccessKey:  cfg.get("access_key_id"),
		Secret:     cfg.get("access_key_secret"),
	}}
}

func (a *aliyun) ListZones(ctx context.Context) ([]Zone, error) {
	zones := make([]Zone, 0)
	for page := 1; ; page++ {
		result, err := a.call(ctx, "DescribeDomains", map[string]string{"PageNumber": strconv.Itoa(page), "PageSize": "100"})
		if err != nil {
			return nil, err
		}
		for _, item := range nestedList(result, "Domains", "Domain") {
			name := fmt.Sprint(item["DomainName"])
			zones = append(zones, Zone{ID: name, Name: normalizeName(name)})
		}
		if page*100 >= intOf(result["TotalCount"]) {
			return zones, nil
		}
	}
}

func (a *aliyun) ListA(ctx context.Context, zone Zone, name, ip string) ([]Record, error) {
	params := map[string]string{"DomainName": zone.Name, "TypeKeyWord": "A", "PageSize": "500"}
	if name != "" {
		host, err := relativeName(name, zone.Name, "@")
		if err != nil {
			return nil, err
		}
		params["RRKeyWord"] = host
	}
	if ip != "" {
		params["ValueKeyWord"] = ip
	}
	records := make([]Record, 0)
	for page := 1; ; page++ {
		params["PageNumber"] = strconv.Itoa(page)
		result, err := a.call(ctx, "DescribeDomainRecords", params)
		if err != nil {
			return nil, err
		}
		for _, item := range nestedList(result, "DomainRecords", "Record") {
			if fmt.Sprint(item["Type"]) != "A" {
				continue
			}
			rr := fmt.Sprint(item["RR"])
			records = append(records, Record{
				ID:     fmt.Sprint(item["RecordId"]),
				Name:   absoluteName(rr, zone.Name),
				Values: []string{strings.TrimSpace(fmt.Sprint(item["Value"]))},
				TTL:    intOf(item["TTL"]),
				Raw:    map[string]any{"rr": rr, "line": fmt.Sprint(item["Line"])},
			})
		}
		if page*500 >= intOf(result["TotalCount"]) {
			return filterRecords(records, name, ip), nil
		}
	}
}

func (a *aliyun) CreateA(ctx context.Context, zone Zone, name, ip string) error {
	host, err := relativeName(name, zone.Name, "@")
	if err != nil {
		return err
	}
	_, err = a.call(ctx, "AddDomainRecord", map[string]string{"DomainName": zone.Name, "RR": host, "Type": "A", "Value": ip, "TTL": "600"})
	return err
}

func (a *aliyun) UpdateA(ctx context.Context, zone Zone, record Record, values []string) error {
	params := map[string]string{"RecordId": record.ID, "RR": fmt.Sprint(record.Raw["rr"]), "Type": "A", "Value": values[0], "TTL": strconv.Itoa(record.TTL)}
	if line, _ := record.Raw["line"].(string); line != "" && line != "<nil>" {
		params["Line"] = line
	}
	_, err := a.call(ctx, "UpdateDomainRecord", params)
	return err
}

func (a *aliyun) DeleteA(ctx context.Context, zone Zone, record Record) error {
	_, err := a.call(ctx, "DeleteDomainRecord", map[string]string{"RecordId": record.ID})
	return err
}

func (a *aliyun) call(ctx context.Context, action string, params map[string]string) (map[string]any, error) {
	result, err := a.rpc.Call(ctx, action, params)
	if err != nil {
		var apiErr *cloud.APIError
		if errors.As(err, &apiErr) {
			return nil, providerError("阿里云", apiErr.HTTPStatus, apiErr.Code+" "+apiErr.Message)
		}
		return nil, fmt.Errorf("阿里云 网络请求失败：%w", err)
	}
	return result, nil
}

func nestedList(root map[string]any, parent, child string) []map[string]any {
	container, _ := root[parent].(map[string]any)
	items, _ := container[child].([]any)
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			result = append(result, m)
		}
	}
	return result
}

func intOf(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, _ := strconv.Atoi(v)
		return n
	}
	return 0
}
