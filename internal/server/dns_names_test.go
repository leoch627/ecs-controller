package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kori1c/ecs-controller/internal/dns"
	"github.com/Kori1c/ecs-controller/internal/store"
)

func newDNSNamesServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	srv, st := newReplaceIPServer(t, lightsailAccount(), &sequenceEIPClient{})
	second := lightsailAccount()
	second.ID, second.InstanceID, second.InstanceName, second.PublicIP = 2, "i-2", "jp-2", "203.0.113.20"
	if err := st.UpsertAccount(second); err != nil {
		t.Fatal(err)
	}
	token, _ := st.Seal("cf-token")
	if err := st.SetSetting("ddns_cf_token", token); err != nil {
		t.Fatal(err)
	}
	domain := dns.Domain{ID: "d1", Provider: "cloudflare", Domain: "Example.com."}
	if err := srv.saveDNSConfig(map[string]any{"domains": []dns.Domain{domain}}); err != nil {
		t.Fatal(err)
	}
	return srv, st
}

func setNamesFor(t *testing.T, srv *Server, id int64, names any) map[string]any {
	t.Helper()
	recorder := httptest.NewRecorder()
	srv.setInstanceDNSNames(recorder, map[string]any{"accountId": float64(id), "names": names})
	var body map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	return body
}

func TestDNSDomainsRoundTripAndValidate(t *testing.T) {
	srv, st := newDNSNamesServer(t)
	domains := srv.dnsConfig()["domains"].([]dns.Domain)
	if len(domains) != 1 || domains[0].Domain != "example.com" {
		t.Fatalf("round trip: %+v", domains)
	}
	duplicate := []dns.Domain{{ID: "a", Provider: "cloudflare", Domain: "example.com"}, {ID: "b", Provider: "cloudflare", Domain: "example.com"}}
	if err := srv.saveDNSConfig(map[string]any{"domains": duplicate}); err == nil {
		t.Fatal("duplicate root domain accepted")
	}
	missing := []dns.Domain{{ID: "a", Provider: "dnspod", Domain: "example.org"}}
	if err := srv.saveDNSConfig(map[string]any{"domains": missing}); err == nil || !strings.Contains(err.Error(), "凭据") {
		t.Fatalf("domain without credentials accepted: %v", err)
	}
	if got := st.GetSetting("ddns_domains", ""); !strings.Contains(got, `"example.com"`) {
		t.Fatalf("failed save changed domains: %s", got)
	}
}

func TestInstanceDNSNamesAreNormalizedAndShownWithHolders(t *testing.T) {
	srv, st := newDNSNamesServer(t)
	var synced []int64
	srv.SyncDNS = func(_ context.Context, id int64) { synced = append(synced, id) }
	accounts, _ := st.LoadAccounts(false)
	first, second := accounts[0].ID, accounts[1].ID
	if body := setNamesFor(t, srv, first, "lb, jp1.example.com，LB"); body["success"] != true {
		t.Fatalf("set names: %v", body)
	}
	if body := setNamesFor(t, srv, second, []any{"lb.example.com"}); body["success"] != true {
		t.Fatalf("set names: %v", body)
	}
	if len(synced) != 2 {
		t.Fatalf("names were not synced right away: %v", synced)
	}
	if got := strings.Join(st.DNSHostNames(accounts[0]), ","); got != "jp1.example.com,lb.example.com" {
		t.Fatalf("names=%s", got)
	}
	if body := setNamesFor(t, srv, first, "api.other.net"); body["success"] == true {
		t.Fatal("name outside every root domain accepted")
	}

	recorder := httptest.NewRecorder()
	srv.status(recorder)
	var status struct {
		Data       []map[string]any `json:"data"`
		DDNSActive bool             `json:"ddns_active"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil || !status.DDNSActive {
		t.Fatalf("status: %v %s", err, recorder.Body.String())
	}
	holders := map[string]float64{}
	for _, item := range status.Data {
		for _, raw := range item["dnsNames"].([]any) {
			entry := raw.(map[string]any)
			holders[entry["name"].(string)] = entry["holders"].(float64)
		}
	}
	if holders["lb.example.com"] != 2 || holders["jp1.example.com"] != 1 {
		t.Fatalf("holders=%v", holders)
	}

	// A root domain in use cannot be removed.
	if err := srv.saveDNSConfig(map[string]any{"domains": []dns.Domain{}}); err == nil {
		t.Fatal("removed a root domain machines still use")
	}
	if body := setNamesFor(t, srv, first, ""); body["success"] != true {
		t.Fatalf("clear names: %v", body)
	}
	if got := st.DNSHostNames(accounts[0]); len(got) != 0 {
		t.Fatalf("names not cleared: %v", got)
	}
}
