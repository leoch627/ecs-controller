package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Kori1c/ecs-controller/internal/store"
)

// recordingCloudflare keeps A records as "name ip" rows keyed by record ID.
type recordingCloudflare struct {
	mu      sync.Mutex
	records map[string]string
	next    int
}

func (f *recordingCloudflare) client() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		reply := func(result any) (*http.Response, error) {
			body, _ := json.Marshal(map[string]any{"success": true, "result": result, "result_info": map[string]any{"total_pages": 1}})
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}}, nil
		}
		path := strings.TrimPrefix(r.URL.Path, "/client/v4")
		id := strings.TrimPrefix(path, "/zones/zone-1/dns_records/")
		switch {
		case r.Method == http.MethodGet && path == "/zones":
			return reply([]map[string]any{{"id": "zone-1", "name": "example.com"}})
		case r.Method == http.MethodGet && path == "/zones/zone-1/dns_records":
			items := []map[string]any{}
			for recordID, row := range f.records {
				name, ip, _ := strings.Cut(row, " ")
				if want := r.URL.Query().Get("name"); want != "" && want != name {
					continue
				}
				items = append(items, map[string]any{"id": recordID, "name": name, "content": ip, "ttl": 1, "type": "A"})
			}
			return reply(items)
		case r.Method == http.MethodPost:
			var record struct{ Name, Content string }
			_ = json.NewDecoder(r.Body).Decode(&record)
			f.next++
			f.records[strings.Repeat("n", f.next)] = record.Name + " " + record.Content
			return reply(map[string]any{"id": "new"})
		case r.Method == http.MethodPatch:
			var record struct{ Content string }
			_ = json.NewDecoder(r.Body).Decode(&record)
			name, _, _ := strings.Cut(f.records[id], " ")
			f.records[id] = name + " " + record.Content
			return reply(map[string]any{"id": id})
		case r.Method == http.MethodDelete:
			delete(f.records, id)
			return reply(map[string]any{"id": id})
		}
		return reply(nil)
	})}
}

func (f *recordingCloudflare) names() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	rows := make([]string, 0, len(f.records))
	for _, row := range f.records {
		rows = append(rows, row)
	}
	return strings.Join(sortedStrings(rows), ";")
}

func sortedStrings(values []string) []string {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
	return values
}

func newDNSNameServer(t *testing.T) (*Server, *store.Store, *recordingCloudflare) {
	t.Helper()
	srv, st := newReplaceIPServer(t, lightsailAccount(), &sequenceEIPClient{})
	second := lightsailAccount()
	second.ID, second.InstanceID, second.InstanceName, second.PublicIP = 2, "i-2", "jp-2", "203.0.113.20"
	if err := st.UpsertAccount(second); err != nil {
		t.Fatal(err)
	}
	token, _ := st.Seal("cf-token")
	for key, value := range map[string]string{"ddns_enabled": "1", "ddns_provider": "cloudflare", "ddns_domain": "example.com", "ddns_cf_token": token} {
		if err := st.SetSetting(key, value); err != nil {
			t.Fatal(err)
		}
	}
	cf := &recordingCloudflare{records: map[string]string{"a": "jp-1.example.com 203.0.113.10", "b": "jp-2.example.com 203.0.113.20"}}
	srv.DNSClient = cf.client()
	return srv, st, cf
}

func setDNSName(srv *Server, id int, name string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	srv.setInstanceDNSName(recorder, map[string]any{"accountId": id, "name": name})
	return recorder
}

func TestSetInstanceDNSNameMovesTheRecord(t *testing.T) {
	srv, st, cf := newDNSNameServer(t)
	accounts, _ := st.LoadAccounts(false)
	auto := map[int64]string{}
	for _, account := range accounts {
		auto[account.ID] = st.DDNSRecordName(account, accounts)
	}
	if auto[1] != "jp-1.example.com" || auto[2] != "jp-2.example.com" {
		t.Fatalf("automatic names=%v", auto)
	}

	recorder := setDNSName(srv, 1, "Tokyo1")
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"dnsName":"tokyo1.example.com"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := cf.names(); got != "jp-2.example.com 203.0.113.20;tokyo1.example.com 203.0.113.10" {
		t.Fatalf("records=%s", got)
	}

	// Another machine cannot take a name that is in use.
	if recorder := setDNSName(srv, 2, "tokyo1.example.com"); recorder.Code != http.StatusBadRequest {
		t.Fatalf("duplicate name status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder := setDNSName(srv, 2, "bad_name"); recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid name status=%d", recorder.Code)
	}

	// Clearing the name goes back to the automatic one.
	if recorder := setDNSName(srv, 1, ""); recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := cf.names(); got != "jp-1.example.com 203.0.113.10;jp-2.example.com 203.0.113.20" {
		t.Fatalf("records after reset=%s", got)
	}
	account, _ := st.Account(1, false)
	if st.CustomDNSName(*account) != "" {
		t.Fatal("custom name was not cleared")
	}
}

func TestStatusShowsDNSNamesOnlyWhenDDNSIsOn(t *testing.T) {
	srv, st, _ := newDNSNameServer(t)
	read := func() map[string]any {
		recorder := httptest.NewRecorder()
		srv.status(recorder)
		var body struct {
			Data []map[string]any `json:"data"`
		}
		_ = json.Unmarshal(recorder.Body.Bytes(), &body)
		for _, item := range body.Data {
			if item["id"] == float64(1) {
				return item
			}
		}
		t.Fatalf("instance missing: %s", recorder.Body.String())
		return nil
	}
	if item := read(); item["dnsName"] != "jp-1.example.com" || item["dnsCustom"] != false {
		t.Fatalf("item=%v", item)
	}
	_ = st.SetSetting("ddns_enabled", "0")
	if _, shown := read()["dnsName"]; shown {
		t.Fatal("DNS name shown with DDNS off")
	}
}
