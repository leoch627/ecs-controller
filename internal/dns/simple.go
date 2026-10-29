package dns

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ---------------- NameSilo (GET + XML, reply code 300 = success) ----------------

type namesilo struct {
	cfg  Config
	http *http.Client
}

type namesiloReply struct {
	Code    string   `xml:"reply>code"`
	Detail  string   `xml:"reply>detail"`
	Domains []string `xml:"reply>domains>domain"`
	Records []struct {
		ID    string `xml:"record_id"`
		Type  string `xml:"type"`
		Host  string `xml:"host"`
		Value string `xml:"value"`
		TTL   int    `xml:"ttl"`
	} `xml:"reply>resource_record"`
}

func (n *namesilo) ListZones(ctx context.Context) ([]Zone, error) {
	reply, err := n.call(ctx, "listDomains", nil)
	if err != nil {
		return nil, err
	}
	zones := make([]Zone, 0, len(reply.Domains))
	for _, domain := range reply.Domains {
		domain = strings.TrimSpace(domain)
		zones = append(zones, Zone{ID: domain, Name: normalizeName(domain)})
	}
	return zones, nil
}

func (n *namesilo) ListA(ctx context.Context, zone Zone, name, ip string) ([]Record, error) {
	reply, err := n.call(ctx, "dnsListRecords", url.Values{"domain": {zone.Name}})
	if err != nil {
		return nil, err
	}
	records := make([]Record, 0, len(reply.Records))
	for _, item := range reply.Records {
		if item.Type == "A" {
			records = append(records, Record{ID: item.ID, Name: normalizeName(item.Host), Values: []string{strings.TrimSpace(item.Value)}, TTL: item.TTL})
		}
	}
	return filterRecords(records, name, ip), nil
}

func (n *namesilo) CreateA(ctx context.Context, zone Zone, name, ip string) error {
	host, err := relativeName(name, zone.Name, "")
	if err != nil {
		return err
	}
	_, err = n.call(ctx, "dnsAddRecord", url.Values{"domain": {zone.Name}, "rrtype": {"A"}, "rrhost": {host}, "rrvalue": {ip}, "rrttl": {"3600"}})
	return err
}

func (n *namesilo) UpdateA(ctx context.Context, zone Zone, record Record, values []string) error {
	host, err := relativeName(record.Name, zone.Name, "")
	if err != nil {
		return err
	}
	ttl := record.TTL
	if ttl < 3600 {
		ttl = 3600
	}
	_, err = n.call(ctx, "dnsUpdateRecord", url.Values{"domain": {zone.Name}, "rrid": {record.ID}, "rrhost": {host}, "rrvalue": {values[0]}, "rrttl": {strconv.Itoa(ttl)}})
	return err
}

func (n *namesilo) DeleteA(ctx context.Context, zone Zone, record Record) error {
	_, err := n.call(ctx, "dnsDeleteRecord", url.Values{"domain": {zone.Name}, "rrid": {record.ID}})
	return err
}

func (n *namesilo) call(ctx context.Context, operation string, params url.Values) (*namesiloReply, error) {
	query := url.Values{"version": {"1"}, "type": {"xml"}, "key": {n.cfg.get("api_key")}}
	for key, values := range params {
		query[key] = values
	}
	status, raw, err := doHTTP(ctx, n.http, "NameSilo", http.MethodGet, "https://www.namesilo.com/api/"+operation+"?"+query.Encode(), nil, nil)
	if err != nil {
		return nil, err
	}
	var reply namesiloReply
	if xml.Unmarshal(raw, &reply) != nil || reply.Code == "" {
		return nil, providerError("NameSilo", status, truncate(string(raw), 200))
	}
	if reply.Code != "300" {
		return nil, providerError("NameSilo", 0, "code "+reply.Code+" "+reply.Detail)
	}
	return &reply, nil
}

// ---------------- Porkbun (POST JSON, status SUCCESS) ----------------

type porkbun struct {
	cfg  Config
	http *http.Client
}

type porkbunRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     string `json:"ttl"`
}

func (p *porkbun) ListZones(ctx context.Context) ([]Zone, error) {
	zones := make([]Zone, 0)
	for start := 0; ; {
		var response struct {
			Domains []struct {
				Domain string `json:"domain"`
			} `json:"domains"`
		}
		if err := p.call(ctx, "domain/listAll", map[string]any{"start": start, "apiAccess": "yes"}, &response); err != nil {
			return nil, err
		}
		for _, item := range response.Domains {
			zones = append(zones, Zone{ID: item.Domain, Name: normalizeName(item.Domain)})
		}
		start += len(response.Domains)
		if len(response.Domains) < 1000 {
			return zones, nil
		}
	}
}

func (p *porkbun) ListA(ctx context.Context, zone Zone, name, ip string) ([]Record, error) {
	var response struct {
		Records []porkbunRecord `json:"records"`
	}
	if err := p.call(ctx, "dns/retrieve/"+url.PathEscape(zone.Name), nil, &response); err != nil {
		return nil, err
	}
	records := make([]Record, 0, len(response.Records))
	for _, item := range response.Records {
		if item.Type == "A" {
			ttl, _ := strconv.Atoi(item.TTL)
			records = append(records, Record{ID: item.ID, Name: normalizeName(item.Name), Values: []string{strings.TrimSpace(item.Content)}, TTL: ttl})
		}
	}
	return filterRecords(records, name, ip), nil
}

func (p *porkbun) CreateA(ctx context.Context, zone Zone, name, ip string) error {
	host, err := relativeName(name, zone.Name, "")
	if err != nil {
		return err
	}
	return p.call(ctx, "dns/create/"+url.PathEscape(zone.Name), map[string]any{"name": host, "type": "A", "content": ip, "ttl": 600}, nil)
}

func (p *porkbun) UpdateA(ctx context.Context, zone Zone, record Record, values []string) error {
	host, err := relativeName(record.Name, zone.Name, "")
	if err != nil {
		return err
	}
	return p.call(ctx, "dns/edit/"+url.PathEscape(zone.Name)+"/"+url.PathEscape(record.ID), map[string]any{"name": host, "type": "A", "content": values[0], "ttl": record.TTL}, nil)
}

func (p *porkbun) DeleteA(ctx context.Context, zone Zone, record Record) error {
	return p.call(ctx, "dns/delete/"+url.PathEscape(zone.Name)+"/"+url.PathEscape(record.ID), nil, nil)
}

func (p *porkbun) call(ctx context.Context, path string, params map[string]any, output any) error {
	payload := map[string]any{"apikey": p.cfg.get("api_key"), "secretapikey": p.cfg.get("secret_api_key")}
	for key, value := range params {
		payload[key] = value
	}
	status, raw, err := doHTTP(ctx, p.http, "Porkbun", http.MethodPost, "https://api.porkbun.com/api/json/v3/"+path, http.Header{"Content-Type": {"application/json"}}, marshalJSON(payload))
	if err != nil {
		return err
	}
	var result struct {
		Status  string `json:"status"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &result) != nil {
		return providerError("Porkbun", status, truncate(string(raw), 200))
	}
	if result.Status != "SUCCESS" {
		if status == http.StatusOK {
			status = 0
		}
		return providerError("Porkbun", status, strings.TrimSpace(result.Code+" "+result.Message))
	}
	if output != nil {
		return json.Unmarshal(raw, output)
	}
	return nil
}

// ---------------- GoDaddy (A records of one host are read and written as a set) ----------------

type godaddy struct {
	cfg  Config
	http *http.Client
}

func (*godaddy) recordSets() {}

func (g *godaddy) ListZones(ctx context.Context) ([]Zone, error) {
	var domains []struct {
		Domain string `json:"domain"`
	}
	if err := g.api(ctx, http.MethodGet, "/domains?statuses=ACTIVE&limit=1000", nil, &domains); err != nil {
		return nil, err
	}
	zones := make([]Zone, 0, len(domains))
	for _, item := range domains {
		zones = append(zones, Zone{ID: item.Domain, Name: normalizeName(item.Domain)})
	}
	return zones, nil
}

func (g *godaddy) ListA(ctx context.Context, zone Zone, name, ip string) ([]Record, error) {
	path := "/domains/" + url.PathEscape(zone.Name) + "/records/A"
	if name != "" {
		host, err := relativeName(name, zone.Name, "@")
		if err != nil {
			return nil, err
		}
		path += "/" + url.PathEscape(host)
	}
	var items []struct {
		Data string `json:"data"`
		Name string `json:"name"`
		TTL  int    `json:"ttl"`
	}
	if err := g.api(ctx, http.MethodGet, path, nil, &items); err != nil {
		return nil, err
	}
	order := make([]string, 0)
	sets := map[string]*Record{}
	for _, item := range items {
		host := item.Name
		if host == "" {
			host = "@"
		}
		set, ok := sets[host]
		if !ok {
			set = &Record{ID: host, Name: absoluteName(host, zone.Name), TTL: item.TTL, Raw: map[string]any{"host": host}}
			sets[host] = set
			order = append(order, host)
		}
		set.Values = append(set.Values, strings.TrimSpace(item.Data))
	}
	records := make([]Record, 0, len(order))
	for _, host := range order {
		records = append(records, *sets[host])
	}
	return filterRecords(records, name, ip), nil
}

func (g *godaddy) CreateA(ctx context.Context, zone Zone, name, ip string) error {
	host, err := relativeName(name, zone.Name, "@")
	if err != nil {
		return err
	}
	return g.put(ctx, zone, host, []string{ip}, 600)
}

func (g *godaddy) UpdateA(ctx context.Context, zone Zone, record Record, values []string) error {
	ttl := record.TTL
	if ttl < 600 {
		ttl = 600
	}
	return g.put(ctx, zone, fmt.Sprint(record.Raw["host"]), values, ttl)
}

// DeleteA removes every A record of the host, which is this record set.
func (g *godaddy) DeleteA(ctx context.Context, zone Zone, record Record) error {
	return g.api(ctx, http.MethodDelete, "/domains/"+url.PathEscape(zone.Name)+"/records/A/"+url.PathEscape(fmt.Sprint(record.Raw["host"])), nil, nil)
}

func (g *godaddy) put(ctx context.Context, zone Zone, host string, values []string, ttl int) error {
	payload := make([]map[string]any, 0, len(values))
	for _, value := range values {
		payload = append(payload, map[string]any{"data": value, "ttl": ttl})
	}
	return g.api(ctx, http.MethodPut, "/domains/"+url.PathEscape(zone.Name)+"/records/A/"+url.PathEscape(host), payload, nil)
}

func (g *godaddy) api(ctx context.Context, method, path string, payload any, output any) error {
	header := http.Header{"Authorization": {"sso-key " + g.cfg.get("api_key") + ":" + g.cfg.get("api_secret")}, "Accept": {"application/json"}}
	var body []byte
	if payload != nil {
		body = marshalJSON(payload)
		header.Set("Content-Type", "application/json")
	}
	status, raw, err := doHTTP(ctx, g.http, "GoDaddy", method, "https://api.godaddy.com/v1"+path, header, body)
	if err != nil {
		return err
	}
	if status >= 400 {
		var problem struct{ Code, Message string }
		_ = json.Unmarshal(raw, &problem)
		return providerError("GoDaddy", status, strings.TrimSpace(problem.Code+" "+problem.Message))
	}
	if output != nil && len(raw) > 0 {
		return json.Unmarshal(raw, output)
	}
	return nil
}

// ---------------- DigitalOcean ----------------

type digitalOcean struct {
	cfg  Config
	http *http.Client
}

type digitalOceanLinks struct {
	Pages struct {
		Next string `json:"next"`
	} `json:"pages"`
}

func (d *digitalOcean) ListZones(ctx context.Context) ([]Zone, error) {
	zones := make([]Zone, 0)
	for page := 1; ; page++ {
		var response struct {
			Domains []struct {
				Name string `json:"name"`
			} `json:"domains"`
			Links digitalOceanLinks `json:"links"`
		}
		if err := d.api(ctx, http.MethodGet, fmt.Sprintf("/domains?per_page=200&page=%d", page), nil, &response); err != nil {
			return nil, err
		}
		for _, item := range response.Domains {
			zones = append(zones, Zone{ID: item.Name, Name: normalizeName(item.Name)})
		}
		if response.Links.Pages.Next == "" {
			return zones, nil
		}
	}
}

func (d *digitalOcean) ListA(ctx context.Context, zone Zone, name, ip string) ([]Record, error) {
	query := url.Values{"type": {"A"}, "per_page": {"200"}}
	if name != "" {
		query.Set("name", normalizeName(name))
	}
	records := make([]Record, 0)
	for page := 1; ; page++ {
		query.Set("page", strconv.Itoa(page))
		var response struct {
			Records []struct {
				ID   int64  `json:"id"`
				Type string `json:"type"`
				Name string `json:"name"`
				Data string `json:"data"`
				TTL  int    `json:"ttl"`
			} `json:"domain_records"`
			Links digitalOceanLinks `json:"links"`
		}
		if err := d.api(ctx, http.MethodGet, "/domains/"+url.PathEscape(zone.Name)+"/records?"+query.Encode(), nil, &response); err != nil {
			return nil, err
		}
		for _, item := range response.Records {
			if item.Type == "A" {
				records = append(records, Record{ID: strconv.FormatInt(item.ID, 10), Name: absoluteName(item.Name, zone.Name), Values: []string{strings.TrimSpace(item.Data)}, TTL: item.TTL, Raw: map[string]any{"host": item.Name}})
			}
		}
		if response.Links.Pages.Next == "" {
			return filterRecords(records, name, ip), nil
		}
	}
}

func (d *digitalOcean) CreateA(ctx context.Context, zone Zone, name, ip string) error {
	host, err := relativeName(name, zone.Name, "@")
	if err != nil {
		return err
	}
	return d.api(ctx, http.MethodPost, "/domains/"+url.PathEscape(zone.Name)+"/records", map[string]any{"type": "A", "name": host, "data": ip, "ttl": 300}, nil)
}

func (d *digitalOcean) UpdateA(ctx context.Context, zone Zone, record Record, values []string) error {
	return d.api(ctx, http.MethodPut, "/domains/"+url.PathEscape(zone.Name)+"/records/"+url.PathEscape(record.ID), map[string]any{"type": "A", "name": record.Raw["host"], "data": values[0], "ttl": record.TTL}, nil)
}

func (d *digitalOcean) DeleteA(ctx context.Context, zone Zone, record Record) error {
	return d.api(ctx, http.MethodDelete, "/domains/"+url.PathEscape(zone.Name)+"/records/"+url.PathEscape(record.ID), nil, nil)
}

func (d *digitalOcean) api(ctx context.Context, method, path string, payload any, output any) error {
	header := http.Header{"Authorization": {"Bearer " + d.cfg.get("token")}}
	var body []byte
	if payload != nil {
		body = marshalJSON(payload)
		header.Set("Content-Type", "application/json")
	}
	status, raw, err := doHTTP(ctx, d.http, "DigitalOcean", method, "https://api.digitalocean.com/v2"+path, header, body)
	if err != nil {
		return err
	}
	if status >= 400 {
		var problem struct {
			ID      string `json:"id"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &problem)
		return providerError("DigitalOcean", status, strings.TrimSpace(problem.ID+" "+problem.Message))
	}
	if output != nil && len(raw) > 0 {
		return json.Unmarshal(raw, output)
	}
	return nil
}
