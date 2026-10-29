package dns

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeDNS is an in-memory DNS account shared by every provider fake. Each fake
// speaks its provider's documented request/response format against it.
type fakeDNS struct {
	mu    sync.Mutex
	rows  map[string]*fakeRow
	seq   int
	zones map[string]string // name -> id
}

type fakeRow struct {
	ID, Name, Value, Zone string
	TTL                   int
}

func newFakeDNS() *fakeDNS {
	f := &fakeDNS{rows: map[string]*fakeRow{}, seq: 100, zones: map[string]string{"example.com": "Z1EX", "other.net": "Z2OT"}}
	f.add("hk.example.com", "47.242.10.21", 600)
	f.add("pool.example.com", "8.8.4.4", 600)
	f.add("pool.example.com", "47.242.10.21", 600)
	f.add("other.example.com", "47.242.10.210", 600)
	f.add("x.other.net", "47.242.10.21", 600)
	return f
}

func (f *fakeDNS) add(name, value string, ttl int) string {
	f.seq++
	id := strconv.Itoa(f.seq)
	f.rows[id] = &fakeRow{ID: id, Name: name, Value: value, TTL: ttl, Zone: f.zoneOf(name)}
	return id
}

func (f *fakeDNS) zoneOf(name string) string {
	for zone := range f.zones {
		if name == zone || strings.HasSuffix(name, "."+zone) {
			return zone
		}
	}
	return ""
}

func (f *fakeDNS) zoneByID(id string) string {
	for name, zoneID := range f.zones {
		if zoneID == id || name == id {
			return name
		}
	}
	return id
}

func (f *fakeDNS) inZone(zone string) []*fakeRow {
	rows := make([]*fakeRow, 0)
	for _, row := range f.rows {
		if row.Zone == zone {
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Name < rows[j].Name || (rows[i].Name == rows[j].Name && rows[i].ID < rows[j].ID)
	})
	return rows
}

func (f *fakeDNS) setValues(name string, values []string, ttl int) {
	for id, row := range f.rows {
		if row.Name == name {
			delete(f.rows, id)
		}
	}
	for _, value := range values {
		f.add(name, value, ttl)
	}
}

func (f *fakeDNS) values(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	values := make([]string, 0)
	for _, row := range f.rows {
		if row.Name == name {
			values = append(values, row.Value)
		}
	}
	sort.Strings(values)
	return values
}

func rel(fqdn, zone, apex string) string {
	if fqdn == zone {
		return apex
	}
	return strings.TrimSuffix(fqdn, "."+zone)
}

func abs(host, zone string) string {
	if host == "" || host == "@" {
		return zone
	}
	return host + "." + zone
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func reply(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}
}

func jsonReply(status int, value any) *http.Response {
	raw, _ := json.Marshal(value)
	return reply(status, string(raw))
}

// handler answers one request for one provider; fakes lock the store.
type handler func(f *fakeDNS, r *http.Request, body []byte) *http.Response

var fakes = map[string]handler{
	"api.cloudflare.com": func(f *fakeDNS, r *http.Request, body []byte) *http.Response {
		if r.Header.Get("Authorization") != "Bearer tok" {
			return jsonReply(400, map[string]any{"success": false, "errors": []any{map[string]any{"code": 6003, "message": "Invalid request headers"}}})
		}
		ok := func(result any) *http.Response {
			return jsonReply(200, map[string]any{"success": true, "result": result, "result_info": map[string]any{"total_pages": 1}})
		}
		path, query := r.URL.Path, r.URL.Query()
		if path == "/client/v4/zones" {
			zones := make([]any, 0)
			for name, id := range f.zones {
				zones = append(zones, map[string]any{"id": id, "name": name})
			}
			return ok(zones)
		}
		parts := strings.Split(strings.TrimPrefix(path, "/client/v4/zones/"), "/")
		zone := f.zoneByID(parts[0])
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		switch r.Method {
		case http.MethodGet:
			items := make([]any, 0)
			for _, row := range f.inZone(zone) {
				if (query.Get("name") == "" || row.Name == query.Get("name")) && (query.Get("content") == "" || row.Value == query.Get("content")) {
					items = append(items, map[string]any{"id": row.ID, "name": row.Name, "type": "A", "content": row.Value, "ttl": 1, "proxied": false})
				}
			}
			return ok(items)
		case http.MethodPost:
			f.add(payload["name"].(string), payload["content"].(string), 1)
		case http.MethodPatch:
			f.rows[parts[2]].Value = payload["content"].(string)
		case http.MethodDelete:
			delete(f.rows, parts[2])
		}
		return ok(map[string]any{})
	},

	"dns.cn-north-4.myhuaweicloud.com": func(f *fakeDNS, r *http.Request, body []byte) *http.Response {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "SDK-HMAC-SHA256 Access=ak, SignedHeaders=content-type;host;x-sdk-date, Signature=") || r.Header.Get("X-Sdk-Date") == "" {
			return jsonReply(401, map[string]any{"code": "APIGW.0301", "message": "Incorrect IAM authentication information"})
		}
		path, query := r.URL.Path, r.URL.Query()
		var payload struct {
			Name    string   `json:"name"`
			TTL     int      `json:"ttl"`
			Records []string `json:"records"`
		}
		_ = json.Unmarshal(body, &payload)
		switch {
		case path == "/v2/zones":
			zones := make([]any, 0)
			for name, id := range f.zones {
				zones = append(zones, map[string]any{"id": id, "name": name + "."})
			}
			return jsonReply(200, map[string]any{"zones": zones, "metadata": map[string]any{"total_count": len(zones)}})
		case path == "/v2.1/recordsets":
			zone := f.zoneByID(query.Get("zone_id"))
			sets := []any{map[string]any{"id": "default", "zone_id": f.zones[zone], "name": zone + ".", "type": "A", "ttl": 300, "records": []string{"47.242.10.21"}, "default": true}}
			grouped := map[string][]string{}
			order := []string{}
			for _, row := range f.inZone(zone) {
				if _, seen := grouped[row.Name]; !seen {
					order = append(order, row.Name)
				}
				grouped[row.Name] = append(grouped[row.Name], row.Value)
			}
			for _, name := range order {
				if query.Get("name") != "" && name+"." != query.Get("name") {
					continue
				}
				if want := query.Get("records"); want != "" && !strings.Contains(strings.Join(grouped[name], ","), want) {
					continue
				}
				sets = append(sets, map[string]any{"id": "rs-" + name, "zone_id": f.zones[zone], "name": name + ".", "type": "A", "ttl": 300, "records": grouped[name]})
			}
			return jsonReply(200, map[string]any{"recordsets": sets, "metadata": map[string]any{"total_count": len(sets)}})
		case strings.HasPrefix(path, "/v2.1/zones/"):
			name := strings.TrimSuffix(payload.Name, ".")
			if index := strings.Index(path, "/recordsets/rs-"); index >= 0 {
				name = path[index+len("/recordsets/rs-"):]
			}
			switch r.Method {
			case http.MethodPost, http.MethodPut:
				f.setValues(name, payload.Records, payload.TTL)
			case http.MethodDelete:
				f.setValues(name, nil, 0)
			}
			return jsonReply(202, map[string]any{})
		}
		return jsonReply(404, map[string]any{"code": "x", "message": "unhandled " + path})
	},

	"alidns.aliyuncs.com": func(f *fakeDNS, r *http.Request, body []byte) *http.Response {
		q := r.URL.Query()
		if q.Get("AccessKeyId") != "LTAIx" || q.Get("Signature") == "" || q.Get("Version") != "2015-01-09" {
			return jsonReply(404, map[string]any{"Code": "InvalidAccessKeyId.NotFound", "Message": "Specified access key is not found."})
		}
		switch q.Get("Action") {
		case "DescribeDomains":
			domains := make([]any, 0)
			for name := range f.zones {
				domains = append(domains, map[string]any{"DomainName": name})
			}
			return jsonReply(200, map[string]any{"TotalCount": len(domains), "Domains": map[string]any{"Domain": domains}})
		case "DescribeDomainRecords":
			zone := q.Get("DomainName")
			items := make([]any, 0)
			for _, row := range f.inZone(zone) {
				rr := rel(row.Name, zone, "@")
				if (q.Get("RRKeyWord") == "" || strings.Contains(rr, q.Get("RRKeyWord"))) && (q.Get("ValueKeyWord") == "" || strings.Contains(row.Value, q.Get("ValueKeyWord"))) {
					items = append(items, map[string]any{"RecordId": row.ID, "RR": rr, "Type": "A", "Value": row.Value, "TTL": row.TTL, "Line": "default"})
				}
			}
			return jsonReply(200, map[string]any{"TotalCount": len(items), "DomainRecords": map[string]any{"Record": items}})
		case "AddDomainRecord":
			f.add(abs(q.Get("RR"), q.Get("DomainName")), q.Get("Value"), 600)
		case "UpdateDomainRecord":
			f.rows[q.Get("RecordId")].Value = q.Get("Value")
		case "DeleteDomainRecord":
			delete(f.rows, q.Get("RecordId"))
		}
		return jsonReply(200, map[string]any{"RequestId": "r"})
	},

	"dnspod.tencentcloudapi.com": func(f *fakeDNS, r *http.Request, body []byte) *http.Response {
		resp := func(data map[string]any) *http.Response {
			data["RequestId"] = "r"
			return jsonReply(200, map[string]any{"Response": data})
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "TC3-HMAC-SHA256 Credential=sid/") || r.Header.Get("X-Tc-Version") != "2021-03-23" {
			return resp(map[string]any{"Error": map[string]any{"Code": "AuthFailure.SecretIdNotFound", "Message": "bad"}})
		}
		var b map[string]any
		_ = json.Unmarshal(body, &b)
		str := func(key string) string { v, _ := b[key].(string); return v }
		switch r.Header.Get("X-Tc-Action") {
		case "DescribeDomainList":
			list := make([]any, 0)
			for name := range f.zones {
				list = append(list, map[string]any{"Name": name, "DomainId": 1})
			}
			return resp(map[string]any{"DomainList": list, "DomainCountInfo": map[string]any{"AllTotal": len(list)}})
		case "DescribeRecordList":
			zone := str("Domain")
			list := make([]any, 0)
			for _, row := range f.inZone(zone) {
				host := rel(row.Name, zone, "@")
				if (str("Subdomain") == "" || host == str("Subdomain")) && (str("Keyword") == "" || strings.Contains(row.Value, str("Keyword")) || strings.Contains(host, str("Keyword"))) {
					id, _ := strconv.Atoi(row.ID)
					list = append(list, map[string]any{"RecordId": id, "Name": host, "Type": "A", "Value": row.Value, "TTL": row.TTL, "Line": "默认", "LineId": "0"})
				}
			}
			if len(list) == 0 && str("ErrorOnEmpty") != "no" {
				return resp(map[string]any{"Error": map[string]any{"Code": "ResourceNotFound.NoDataOfRecord", "Message": "empty"}})
			}
			return resp(map[string]any{"RecordList": list, "RecordCountInfo": map[string]any{"TotalCount": len(list)}})
		case "CreateRecord":
			if str("RecordLine") != "默认" {
				return resp(map[string]any{"Error": map[string]any{"Code": "InvalidParameter", "Message": "RecordLine"}})
			}
			f.add(abs(str("SubDomain"), str("Domain")), str("Value"), 600)
		case "ModifyRecord":
			if str("RecordLine") == "" {
				return resp(map[string]any{"Error": map[string]any{"Code": "MissingParameter", "Message": "RecordLine"}})
			}
			f.rows[fmt.Sprint(b["RecordId"])].Value = str("Value")
		case "DeleteRecord":
			delete(f.rows, fmt.Sprint(b["RecordId"]))
		}
		return resp(map[string]any{})
	},

	"route53.amazonaws.com": func(f *fakeDNS, r *http.Request, body []byte) *http.Response {
		errXML := func(status int, code string) *http.Response {
			return reply(status, "<ErrorResponse><Error><Code>"+code+"</Code><Message>x</Message></Error></ErrorResponse>")
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIA/") {
			return errXML(403, "InvalidClientTokenId")
		}
		path, query := r.URL.Path, r.URL.Query()
		if path == "/2013-04-01/hostedzone" {
			x := "<ListHostedZonesResponse><HostedZones>"
			for name, id := range f.zones {
				x += "<HostedZone><Id>/hostedzone/" + id + "</Id><Name>" + name + ".</Name><Config><PrivateZone>false</PrivateZone></Config></HostedZone>"
			}
			x += "<HostedZone><Id>/hostedzone/ZPRIV</Id><Name>internal.local.</Name><Config><PrivateZone>true</PrivateZone></Config></HostedZone>"
			return reply(200, x+"</HostedZones><IsTruncated>false</IsTruncated></ListHostedZonesResponse>")
		}
		zone := f.zoneByID(strings.Split(strings.TrimPrefix(path, "/2013-04-01/hostedzone/"), "/")[0])
		if r.Method == http.MethodGet {
			type set struct {
				name, typ, extra string
				ttl              int
				values           []string
			}
			grouped := map[string]*set{}
			for _, row := range f.inZone(zone) {
				if grouped[row.Name] == nil {
					grouped[row.Name] = &set{name: row.Name, typ: "A", ttl: row.TTL}
				}
				grouped[row.Name].values = append(grouped[row.Name].values, row.Value)
			}
			sets := []*set{{name: zone, typ: "NS", ttl: 172800, values: []string{"ns1.aws."}}, {name: "weighted." + zone, typ: "A", ttl: 60, values: []string{"47.242.10.21"}, extra: "<SetIdentifier>w1</SetIdentifier><Weight>10</Weight>"}}
			for _, s := range grouped {
				sets = append(sets, s)
			}
			sort.Slice(sets, func(i, j int) bool {
				return sets[i].name < sets[j].name || (sets[i].name == sets[j].name && sets[i].typ < sets[j].typ)
			})
			x := "<ListResourceRecordSetsResponse><ResourceRecordSets>"
			for _, s := range sets {
				if start := query.Get("name"); start != "" && s.name+"." < start {
					continue // listing starts at the requested name
				}
				x += "<ResourceRecordSet><Name>" + s.name + ".</Name><Type>" + s.typ + "</Type>" + s.extra + "<TTL>" + strconv.Itoa(s.ttl) + "</TTL><ResourceRecords>"
				for _, v := range s.values {
					x += "<ResourceRecord><Value>" + v + "</Value></ResourceRecord>"
				}
				x += "</ResourceRecords></ResourceRecordSet>"
			}
			return reply(200, x+"</ResourceRecordSets><IsTruncated>false</IsTruncated></ListResourceRecordSetsResponse>")
		}
		var change struct {
			Action string   `xml:"ChangeBatch>Changes>Change>Action"`
			Name   string   `xml:"ChangeBatch>Changes>Change>ResourceRecordSet>Name"`
			TTL    int      `xml:"ChangeBatch>Changes>Change>ResourceRecordSet>TTL"`
			Values []string `xml:"ChangeBatch>Changes>Change>ResourceRecordSet>ResourceRecords>ResourceRecord>Value"`
		}
		if err := xml.Unmarshal(body, &change); err != nil {
			return errXML(400, "MalformedInput")
		}
		name := strings.TrimSuffix(change.Name, ".")
		current := f.valuesLocked(name)
		wanted := append([]string(nil), change.Values...)
		sort.Strings(wanted)
		switch change.Action {
		case "DELETE":
			if strings.Join(current, ",") != strings.Join(wanted, ",") {
				return errXML(400, "InvalidChangeBatch")
			}
			f.setValues(name, nil, 0)
		case "CREATE":
			if len(current) > 0 {
				return errXML(400, "InvalidChangeBatch")
			}
			f.setValues(name, change.Values, change.TTL)
		default:
			f.setValues(name, change.Values, change.TTL)
		}
		return reply(200, "<ChangeResourceRecordSetsResponse><ChangeInfo><Status>PENDING</Status></ChangeInfo></ChangeResourceRecordSetsResponse>")
	},

	"www.namesilo.com": func(f *fakeDNS, r *http.Request, body []byte) *http.Response {
		q := r.URL.Query()
		op := strings.TrimPrefix(r.URL.Path, "/api/")
		out := func(inner, code, detail string) *http.Response {
			return reply(200, "<namesilo><request><operation>"+op+"</operation></request><reply><code>"+code+"</code><detail>"+detail+"</detail>"+inner+"</reply></namesilo>")
		}
		if r.Method != http.MethodGet || q.Get("key") != "nskey" || q.Get("version") != "1" || q.Get("type") != "xml" {
			return out("", "110", "Invalid API Key")
		}
		switch op {
		case "listDomains":
			x := "<domains>"
			for name := range f.zones {
				x += `<domain created="2020-01-01">` + name + "</domain>"
			}
			return out(x+"</domains>", "300", "success")
		case "dnsListRecords":
			x := "<resource_record><record_id>mx1</record_id><type>MX</type><host>" + q.Get("domain") + "</host><value>mail.x</value><ttl>3600</ttl></resource_record>"
			for _, row := range f.inZone(q.Get("domain")) {
				x += "<resource_record><record_id>" + row.ID + "</record_id><type>A</type><host>" + row.Name + "</host><value>" + row.Value + "</value><ttl>" + strconv.Itoa(row.TTL) + "</ttl></resource_record>"
			}
			return out(x, "300", "success")
		case "dnsAddRecord", "dnsUpdateRecord":
			if ttl, _ := strconv.Atoi(q.Get("rrttl")); ttl < 3600 {
				return out("", "280", "TTL too low")
			}
			if op == "dnsUpdateRecord" {
				delete(f.rows, q.Get("rrid"))
			}
			id := f.add(abs(q.Get("rrhost"), q.Get("domain")), q.Get("rrvalue"), 3600)
			return out("<record_id>"+id+"</record_id>", "300", "success")
		case "dnsDeleteRecord":
			delete(f.rows, q.Get("rrid"))
			return out("", "300", "success")
		}
		return out("", "400", "unknown")
	},

	"api.porkbun.com": func(f *fakeDNS, r *http.Request, body []byte) *http.Response {
		var b map[string]any
		_ = json.Unmarshal(body, &b)
		if r.Method != http.MethodPost || b["apikey"] != "pk1" || b["secretapikey"] != "sk1" {
			return jsonReply(400, map[string]any{"status": "ERROR", "code": "INVALID_API_KEYS_001", "message": "Invalid API key."})
		}
		ok := func(data map[string]any) *http.Response { data["status"] = "SUCCESS"; return jsonReply(200, data) }
		p := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/json/v3/"), "/")
		switch {
		case p[0] == "domain" && p[1] == "listAll":
			list := make([]any, 0)
			for name := range f.zones {
				list = append(list, map[string]any{"domain": name})
			}
			return ok(map[string]any{"domains": list})
		case p[1] == "retrieve":
			list := make([]any, 0)
			for _, row := range f.inZone(p[2]) {
				list = append(list, map[string]any{"id": row.ID, "name": row.Name, "type": "A", "content": row.Value, "ttl": strconv.Itoa(row.TTL)})
			}
			return ok(map[string]any{"records": list})
		case p[1] == "create":
			return ok(map[string]any{"id": f.add(abs(b["name"].(string), p[2]), b["content"].(string), 600)})
		case p[1] == "edit":
			f.rows[p[3]].Value = b["content"].(string)
			return ok(map[string]any{})
		case p[1] == "delete":
			delete(f.rows, p[3])
			return ok(map[string]any{})
		}
		return jsonReply(404, map[string]any{"status": "ERROR", "message": "unhandled"})
	},

	"api.godaddy.com": func(f *fakeDNS, r *http.Request, body []byte) *http.Response {
		if r.Header.Get("Authorization") != "sso-key gdkey:gdsecret" {
			return reply(401, "")
		}
		path := r.URL.Path
		if path == "/v1/domains" {
			list := make([]any, 0)
			for name := range f.zones {
				list = append(list, map[string]any{"domain": name, "status": "ACTIVE"})
			}
			return jsonReply(200, list)
		}
		parts := strings.Split(strings.TrimPrefix(path, "/v1/domains/"), "/")
		zone := parts[0]
		host := ""
		if len(parts) > 3 {
			host, _ = url.PathUnescape(parts[3])
		}
		switch r.Method {
		case http.MethodGet:
			list := make([]any, 0)
			for _, row := range f.inZone(zone) {
				if host == "" || rel(row.Name, zone, "@") == host {
					list = append(list, map[string]any{"data": row.Value, "name": rel(row.Name, zone, "@"), "ttl": row.TTL, "type": "A"})
				}
			}
			return jsonReply(200, list)
		case http.MethodPut:
			var items []struct {
				Data string `json:"data"`
				TTL  int    `json:"ttl"`
			}
			_ = json.Unmarshal(body, &items)
			values := []string{}
			for _, item := range items {
				if item.TTL < 600 {
					return jsonReply(422, map[string]any{"code": "INVALID_BODY", "message": "ttl"})
				}
				values = append(values, item.Data)
			}
			f.setValues(abs(host, zone), values, items[0].TTL)
			return reply(200, "")
		case http.MethodDelete:
			f.setValues(abs(host, zone), nil, 0)
			return reply(204, "")
		}
		return jsonReply(404, map[string]any{"code": "NOT_FOUND"})
	},

	"api.digitalocean.com": func(f *fakeDNS, r *http.Request, body []byte) *http.Response {
		if r.Header.Get("Authorization") != "Bearer dotok" {
			return jsonReply(401, map[string]any{"id": "Unauthorized", "message": "Unable to authenticate you"})
		}
		path, query := r.URL.Path, r.URL.Query()
		var b map[string]any
		_ = json.Unmarshal(body, &b)
		if path == "/v2/domains" {
			list := make([]any, 0)
			for name := range f.zones {
				list = append(list, map[string]any{"name": name})
			}
			return jsonReply(200, map[string]any{"domains": list, "links": map[string]any{}})
		}
		parts := strings.Split(strings.TrimPrefix(path, "/v2/domains/"), "/")
		zone := parts[0]
		switch r.Method {
		case http.MethodGet:
			list := make([]any, 0)
			for _, row := range f.inZone(zone) {
				if query.Get("name") == "" || row.Name == query.Get("name") {
					id, _ := strconv.Atoi(row.ID)
					list = append(list, map[string]any{"id": id, "type": "A", "name": rel(row.Name, zone, "@"), "data": row.Value, "ttl": row.TTL})
				}
			}
			return jsonReply(200, map[string]any{"domain_records": list, "links": map[string]any{}})
		case http.MethodPost:
			f.add(abs(b["name"].(string), zone), b["data"].(string), 300)
			return jsonReply(201, map[string]any{"domain_record": map[string]any{}})
		case http.MethodPut:
			f.rows[parts[2]].Value = b["data"].(string)
			return jsonReply(200, map[string]any{"domain_record": map[string]any{}})
		case http.MethodDelete:
			delete(f.rows, parts[2])
			return reply(204, "")
		}
		return jsonReply(404, map[string]any{"id": "not_found"})
	},
}

func (f *fakeDNS) valuesLocked(name string) []string {
	values := make([]string, 0)
	for _, row := range f.rows {
		if row.Name == name {
			values = append(values, row.Value)
		}
	}
	sort.Strings(values)
	return values
}

func (f *fakeDNS) client() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		h, ok := fakes[r.URL.Host]
		if !ok {
			return nil, fmt.Errorf("unexpected host %s", r.URL.Host)
		}
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(r.Body)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		return h(f, r, body), nil
	})}
}

var testCredentials = map[string]Config{
	"cloudflare":   {"token": "tok"},
	"huawei":       {"ak": "ak", "sk": "sk", "region": "cn-north-4"},
	"aliyun":       {"access_key_id": "LTAIx", "access_key_secret": "s"},
	"dnspod":       {"secret_id": "sid", "secret_key": "skey"},
	"route53":      {"access_key_id": "AKIA", "secret_access_key": "secret"},
	"namesilo":     {"api_key": "nskey"},
	"porkbun":      {"api_key": "pk1", "secret_api_key": "sk1"},
	"godaddy":      {"api_key": "gdkey", "api_secret": "gdsecret"},
	"digitalocean": {"token": "dotok"},
}

func serviceFor(t *testing.T, id, domain string, cfg Config, f *fakeDNS) *Service {
	t.Helper()
	settings := Settings{Provider: id, Domain: domain, DDNSEnabled: true, CleanupEnabled: true, Credentials: map[string]Config{id: cfg}}
	service, err := NewService(settings, f.client())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return service
}

func TestEveryProviderIsCovered(t *testing.T) {
	for _, info := range Providers() {
		if _, ok := testCredentials[info.ID]; !ok {
			t.Errorf("provider %s has no scenario test", info.ID)
		}
	}
}

// TestProviderScenario runs the same cleanup and DDNS flow against every
// provider's fake API.
func TestProviderScenario(t *testing.T) {
	ctx := context.Background()
	for _, info := range Providers() {
		info := info
		t.Run(info.ID, func(t *testing.T) {
			cfg := testCredentials[info.ID]
			f := newFakeDNS()
			svc := serviceFor(t, info.ID, "example.com", cfg, f)

			message, err := svc.Test(ctx)
			if err != nil || !strings.Contains(message, "example.com") {
				t.Fatalf("test connection: %q %v", message, err)
			}

			changes, err := svc.RemoveIP(ctx, "47.242.10.21")
			if err != nil {
				t.Fatalf("remove ip: %v", err)
			}
			if got := f.values("hk.example.com"); len(got) != 0 {
				t.Errorf("single-IP record should be deleted, still %v", got)
			}
			if got := f.values("pool.example.com"); strings.Join(got, ",") != "8.8.4.4" {
				t.Errorf("multi-IP name should keep the other IP, got %v", got)
			}
			if got := f.values("other.example.com"); strings.Join(got, ",") != "47.242.10.210" {
				t.Errorf("look-alike IP touched: %v", got)
			}
			if got := f.values("x.other.net"); len(got) != 1 {
				t.Errorf("other domain must be untouched when scoped to example.com, got %v", got)
			}
			if len(changes) != 2 {
				t.Errorf("expected 2 changes, got %v (%s)", changes, SummarizeChanges(changes))
			}

			all := serviceFor(t, info.ID, "", cfg, f)
			if _, err := all.RemoveIP(ctx, "47.242.10.21"); err != nil {
				t.Fatalf("remove ip across account: %v", err)
			}
			if got := f.values("x.other.net"); len(got) != 0 {
				t.Errorf("no root domain should clean every zone, x.other.net still %v", got)
			}

			steps := []struct{ ip, want string }{{"1.2.3.4", "created"}, {"1.2.3.4", "unchanged"}, {"5.6.7.8", "updated"}}
			for _, step := range steps {
				action, err := svc.SyncA(ctx, "new.example.com", step.ip)
				if err != nil || action != step.want {
					t.Fatalf("sync %s: got %q %v, want %s", step.ip, action, err, step.want)
				}
			}
			if got := f.values("new.example.com"); strings.Join(got, ",") != "5.6.7.8" {
				t.Errorf("after sync got %v", got)
			}
			if deleted, err := svc.DeleteByName(ctx, "new.example.com"); err != nil || !deleted || len(f.values("new.example.com")) != 0 {
				t.Errorf("delete by name: %v %v %v", deleted, err, f.values("new.example.com"))
			}

			if action, err := svc.SyncA(ctx, "example.com", "9.9.9.9"); err != nil || action != "created" || strings.Join(f.values("example.com"), ",") != "9.9.9.9" {
				t.Errorf("apex record: %q %v %v", action, err, f.values("example.com"))
			}

			bad := Config{}
			for key, value := range cfg {
				bad[key] = value
			}
			for _, field := range info.Fields {
				if field.Required {
					bad[field.Key] = "wrong"
				}
			}
			_, err = serviceFor(t, info.ID, "example.com", bad, newFakeDNS()).Test(ctx)
			if err == nil || !strings.Contains(err.Error(), "凭据不正确或已失效") {
				t.Errorf("bad credentials should be reported clearly, got %v", err)
			}
		})
	}
}

func TestRoute53SkipsRoutingPolicyRecords(t *testing.T) {
	f := newFakeDNS()
	svc := serviceFor(t, "route53", "example.com", testCredentials["route53"], f)
	if _, err := svc.RemoveIP(context.Background(), "47.242.10.21"); err != nil {
		t.Fatal(err)
	}
	// The weighted record set lives only in the fake listing; it must not be
	// part of any change batch (DELETE would fail on mismatched values).
}

func TestFindZoneWalksUpFromSubdomain(t *testing.T) {
	zone, ok := findZone([]Zone{{ID: "1", Name: "example.com"}, {ID: "2", Name: "a.b.example.com"}}, "x.b.example.com")
	if !ok || zone.ID != "1" {
		t.Fatalf("got %+v %v", zone, ok)
	}
	zone, ok = findZone([]Zone{{ID: "1", Name: "example.com"}, {ID: "2", Name: "a.b.example.com"}}, "deep.a.b.example.com")
	if !ok || zone.ID != "2" {
		t.Fatalf("most specific zone should win, got %+v", zone)
	}
}

func TestLegacyCloudflareSettingKeys(t *testing.T) {
	if SettingKey("cloudflare", "token") != "ddns_cf_token" || SettingKey("huawei", "sk") != "ddns_hw_sk" || SettingKey("dnspod", "secret_key") != "ddns_dnspod_secret_key" {
		t.Fatal("setting keys changed; existing configurations would be lost")
	}
	if NormalizeID("nope") != "cloudflare" {
		t.Fatal("unknown provider must fall back to Cloudflare")
	}
}

// TestPoolScenario keeps one name pointed at a changing set of IPs on every
// provider, whether it stores one IP per record or a record set.
func TestPoolScenario(t *testing.T) {
	ctx := context.Background()
	for _, info := range Providers() {
		info := info
		t.Run(info.ID, func(t *testing.T) {
			f := newFakeDNS()
			svc := serviceFor(t, info.ID, "example.com", testCredentials[info.ID], f)
			steps := []struct {
				ips            []string
				want           string
				added, removed int
			}{
				{[]string{"3.3.3.3", "1.1.1.1", "2.2.2.2", "1.1.1.1", "10.0.0.1"}, "1.1.1.1,2.2.2.2,3.3.3.3", 3, 0},
				{[]string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}, "1.1.1.1,2.2.2.2,3.3.3.3", 0, 0},
				{[]string{"2.2.2.2", "3.3.3.3", "4.4.4.4"}, "2.2.2.2,3.3.3.3,4.4.4.4", 1, 1},
				{[]string{"5.5.5.5"}, "5.5.5.5", 1, 3},
			}
			for _, step := range steps {
				added, removed, err := svc.SyncPool(ctx, "rr.example.com", step.ips)
				if err != nil || added != step.added || removed != step.removed {
					t.Fatalf("sync %v: added=%d removed=%d err=%v, want %d/%d", step.ips, added, removed, err, step.added, step.removed)
				}
				if got := strings.Join(f.values("rr.example.com"), ","); got != step.want {
					t.Fatalf("sync %v: records %s, want %s", step.ips, got, step.want)
				}
			}
			// A name that already has several IPs is taken over.
			if _, _, err := svc.SyncPool(ctx, "pool.example.com", []string{"8.8.4.4", "6.6.6.6"}); err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(f.values("pool.example.com"), ","); got != "6.6.6.6,8.8.4.4" {
				t.Fatalf("pool.example.com records %s", got)
			}
			if got := strings.Join(f.values("hk.example.com"), ","); got != "47.242.10.21" {
				t.Fatalf("other names must be left alone, hk.example.com=%s", got)
			}
			if _, _, err := svc.SyncPool(ctx, "rr.example.com", []string{"10.0.0.1"}); err == nil {
				t.Fatal("a pool without public IPs must be refused, not emptied")
			}
		})
	}
}

func TestPoolFQDN(t *testing.T) {
	for _, tc := range []struct{ name, domain, want string }{
		{"rr", "886615.xyz", "rr.886615.xyz"},
		{"rr.886615.xyz", "886615.xyz", "rr.886615.xyz"},
		{"886615.xyz", "886615.xyz", "886615.xyz"},
		{"rr", "", ""},
		{"", "886615.xyz", ""},
	} {
		if got := (Settings{PoolName: tc.name, Domain: tc.domain}).PoolFQDN(); got != tc.want {
			t.Errorf("PoolFQDN(%q, %q)=%q, want %q", tc.name, tc.domain, got, tc.want)
		}
	}
}
