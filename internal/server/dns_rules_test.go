package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kori1c/ecs-controller/internal/dns"
	"github.com/Kori1c/ecs-controller/internal/store"
)

func TestDNSRulesRoundTripAndRetirementAreAtomic(t *testing.T) {
	srv, st := newDNSRulesServer(t)
	rule := dns.Rule{ID: "aws", Enabled: true, Kind: "pool", Provider: "cloudflare", Domain: "other.net", Name: "loadbalance", Scope: dns.MachineScope{Mode: "aws"}}
	if err := srv.saveDNSConfig(map[string]any{"rules": []dns.Rule{rule}, "provider": "cloudflare", "credentials": map[string]any{"cloudflare": map[string]any{"token": "********"}}}); err != nil {
		t.Fatal(err)
	}
	config := srv.dnsConfig()
	rules := config["rules"].([]dns.Rule)
	if len(rules) != 1 || rules[0].Domain != "other.net" {
		t.Fatalf("round trip: %+v", rules)
	}
	jobs, err := st.ListJobs("dns_rule_cleanup", 10)
	if err != nil || len(jobs) != 1 || !strings.Contains(jobs[0].Payload, "jp-1.example.com") {
		t.Fatalf("retired records: %+v %v", jobs, err)
	}
	before := st.GetSetting("ddns_rules", "")
	rule.Scope = dns.MachineScope{Mode: "instances"}
	if err := srv.saveDNSConfig(map[string]any{"rules": []dns.Rule{rule}, "credentials": map[string]any{"cloudflare": map[string]any{"token": "new-token"}}}); err == nil {
		t.Fatal("empty selection accepted")
	}
	if st.GetSetting("ddns_rules", "") != before {
		t.Fatal("failed validation modified rules")
	}
	token, _ := st.OpenSecret(st.GetSetting("ddns_cf_token", ""))
	if token != "cf-token" {
		t.Fatal("failed validation modified credentials")
	}
}

func TestDNSRulesAcceptInstanceRulesAndRejectDuplicateNames(t *testing.T) {
	srv, st := newDNSRulesServer(t)
	instance := dns.Rule{ID: "one", Enabled: true, Kind: "instance", Provider: "cloudflare", Domain: "example.com", Scope: dns.MachineScope{Mode: "aws"}}
	if err := srv.saveDNSConfig(map[string]any{"rules": []dns.Rule{instance}}); err != nil {
		t.Fatalf("single-instance rule rejected: %v", err)
	}
	recorder := httptest.NewRecorder()
	srv.status(recorder)
	var body struct {
		Data       []map[string]any `json:"data"`
		DDNSActive bool             `json:"ddns_active"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || !body.DDNSActive || len(body.Data) != 2 {
		t.Fatalf("status: %+v, %v", body, err)
	}
	for _, item := range body.Data {
		if name, _ := item["dnsName"].(string); !strings.HasSuffix(name, ".example.com") {
			t.Fatalf("instance DNS name missing: %v", item)
		}
	}
	accounts, _ := st.LoadAccounts(false)
	taken := st.InstanceDNSName(accounts[0], accounts, "example.com")
	clash := dns.Rule{ID: "pool", Enabled: true, Kind: "pool", Provider: "cloudflare", Domain: "example.com", Name: strings.TrimSuffix(taken, ".example.com"), Scope: dns.MachineScope{Mode: "aws"}}
	if err := srv.saveDNSConfig(map[string]any{"rules": []dns.Rule{instance, clash}}); err == nil {
		t.Fatal("pool name equal to an instance name accepted")
	}
	pool := instance
	pool.ID, pool.Kind, pool.Name = "pool", "pool", "loadbalance"
	other := pool
	other.ID = "other"
	if err := srv.saveDNSConfig(map[string]any{"rules": []dns.Rule{pool, other}}); err == nil {
		t.Fatal("duplicate pool name accepted")
	}
}

func TestStatusOmitsInstanceDNSNamesWithoutInstanceRule(t *testing.T) {
	srv, st := newDNSRulesServer(t)
	accounts, _ := st.LoadAccounts(false)
	rule := dns.Rule{ID: "one", Enabled: true, Kind: "pool", Provider: "cloudflare", Domain: "example.com", Name: "loadbalance", Scope: dns.MachineScope{Mode: "instances", InstanceKeys: []string{dns.InstanceKey(accounts[0])}}}
	if err := srv.saveDNSConfig(map[string]any{"rules": []dns.Rule{rule}, "enabled": true}); err != nil {
		t.Fatal(err)
	}
	if st.GetSetting("ddns_enabled", "") != "0" {
		t.Fatal("legacy instance switch was accepted")
	}
	recorder := httptest.NewRecorder()
	srv.status(recorder)
	var body struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || len(body.Data) != 2 {
		t.Fatalf("status: %+v, %v", body, err)
	}
	for _, item := range body.Data {
		if item["dnsInstanceKey"] == "" || item["dnsName"] != nil {
			t.Fatalf("unexpected instance DNS metadata: %v", item)
		}
	}
	if err := srv.saveDNSConfig(map[string]any{"rules": []dns.Rule{}}); err != nil {
		t.Fatal(err)
	}
	if rules := srv.dnsConfig()["rules"].([]dns.Rule); len(rules) != 0 {
		t.Fatalf("empty rule list reactivated DNS: %+v", rules)
	}
}

func newDNSRulesServer(t *testing.T) (*Server, *store.Store) {
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
	return srv, st
}
