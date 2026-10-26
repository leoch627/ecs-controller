package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const cloudflareAPI = "https://api.cloudflare.com/client/v4"

type cloudflare struct {
	cfg  Config
	http *http.Client
}

type cloudflareResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    any    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo struct {
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func (c *cloudflare) ListZones(ctx context.Context) ([]Zone, error) {
	zones := make([]Zone, 0)
	for page := 1; ; page++ {
		response, err := c.api(ctx, http.MethodGet, fmt.Sprintf("/zones?per_page=50&page=%d", page), nil)
		if err != nil {
			return nil, err
		}
		var items []struct{ ID, Name string }
		if err := json.Unmarshal(response.Result, &items); err != nil {
			return nil, err
		}
		for _, item := range items {
			zones = append(zones, Zone{ID: item.ID, Name: item.Name})
		}
		if page >= response.ResultInfo.TotalPages {
			return zones, nil
		}
	}
}

func (c *cloudflare) ListA(ctx context.Context, zone Zone, name, ip string) ([]Record, error) {
	query := url.Values{"type": {"A"}, "per_page": {"100"}}
	if name != "" {
		query.Set("name", normalizeName(name))
	}
	if ip != "" {
		query.Set("content", ip)
	}
	records := make([]Record, 0)
	for page := 1; ; page++ {
		query.Set("page", fmt.Sprint(page))
		response, err := c.api(ctx, http.MethodGet, "/zones/"+url.PathEscape(zone.ID)+"/dns_records?"+query.Encode(), nil)
		if err != nil {
			return nil, err
		}
		var items []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Content string `json:"content"`
			TTL     int    `json:"ttl"`
			Proxied bool   `json:"proxied"`
		}
		if err := json.Unmarshal(response.Result, &items); err != nil {
			return nil, err
		}
		for _, item := range items {
			records = append(records, Record{ID: item.ID, Name: normalizeName(item.Name), Values: []string{strings.TrimSpace(item.Content)}, TTL: item.TTL, Raw: map[string]any{"proxied": item.Proxied}})
		}
		if page >= response.ResultInfo.TotalPages {
			return filterRecords(records, name, ip), nil
		}
	}
}

// Matches also compares the proxy flag so toggling it is applied on the next sync.
func (c *cloudflare) Matches(record Record, ip string) bool {
	proxied, _ := record.Raw["proxied"].(bool)
	return len(record.Values) == 1 && record.Values[0] == ip && proxied == c.proxied()
}

func (c *cloudflare) CreateA(ctx context.Context, zone Zone, name, ip string) error {
	_, err := c.api(ctx, http.MethodPost, "/zones/"+url.PathEscape(zone.ID)+"/dns_records", map[string]any{
		"type": "A", "name": normalizeName(name), "content": ip, "ttl": 1, "proxied": c.proxied(), "comment": "Managed by ECS 控制台",
	})
	return err
}

func (c *cloudflare) UpdateA(ctx context.Context, zone Zone, record Record, values []string) error {
	_, err := c.api(ctx, http.MethodPatch, "/zones/"+url.PathEscape(zone.ID)+"/dns_records/"+url.PathEscape(record.ID), map[string]any{
		"content": values[0], "proxied": c.proxied(),
	})
	return err
}

func (c *cloudflare) DeleteA(ctx context.Context, zone Zone, record Record) error {
	_, err := c.api(ctx, http.MethodDelete, "/zones/"+url.PathEscape(zone.ID)+"/dns_records/"+url.PathEscape(record.ID), nil)
	return err
}

func (c *cloudflare) proxied() bool { return c.cfg.get("proxied") == "1" }

func (c *cloudflare) api(ctx context.Context, method, path string, payload any) (*cloudflareResponse, error) {
	header := http.Header{"Authorization": {"Bearer " + c.cfg.get("token")}}
	var body []byte
	if payload != nil {
		body = marshalJSON(payload)
		header.Set("Content-Type", "application/json")
	}
	status, raw, err := doHTTP(ctx, c.http, "Cloudflare", method, cloudflareAPI+path, header, body)
	if err != nil {
		return nil, err
	}
	var response cloudflareResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, providerError("Cloudflare", status, truncate(string(raw), 200))
	}
	if !response.Success {
		messages := make([]string, 0, len(response.Errors))
		for _, item := range response.Errors {
			messages = append(messages, strings.TrimSpace(fmt.Sprint(item.Code)+" "+item.Message))
		}
		return nil, providerError("Cloudflare", status, strings.Join(messages, "；"))
	}
	return &response, nil
}
